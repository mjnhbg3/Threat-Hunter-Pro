"""
FastAPI application for Threat Hunter.

This module defines the HTTP API served by the Threat Hunter backend.
It exposes endpoints for the dashboard UI, log retrieval, chat
interaction with the AI assistant, configuration management and
persistent state operations. Authentication is enforced via HTTP
Basic using credentials from environment variables.
"""

from __future__ import annotations

import json
import logging
from typing import List, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from . import state
from .config import BASIC_AUTH_USER, BASIC_AUTH_PASS, LITE_MODEL, PRO_MODEL
from .html_template import HTML_CONTENT
from .models import DashboardData, QueryRequest, Settings
from .persistence import (
    save_dashboard_data,
    save_settings,
)
from .vector_db import search_vector_db
from .ai_logic import (
    call_gemini_api,
    generate_retrieval_queries,
    summarize_logs,
    count_tokens_local,
    chat_analyze_with_ner,
    chat_execute_with_ner,
    analyze_context_with_ner_enhancement,
)
from .enhanced_retrieval import comprehensive_log_search, get_entity_focused_logs
from .ai_logic import get_model_family  # reused for metrics
from .ai_logic import rotate_api_key  # exported for potential use

from datetime import datetime


app = FastAPI(title="Wazuh Threat Hunter Pro (Gemini Edition)")
security = HTTPBasic()


def check_auth(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    """Verify HTTP Basic credentials."""
    is_user_ok = credentials.username == BASIC_AUTH_USER
    is_pass_ok = credentials.password == BASIC_AUTH_PASS
    if not (is_user_ok and is_pass_ok):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return credentials.username


@app.get("/", response_class=HTMLResponse)
async def get_dashboard_ui(user: str = Depends(check_auth)) -> Response:
    """Serve the dashboard HTML interface."""
    return HTMLResponse(content=HTML_CONTENT)


@app.get("/api/dashboard", response_model=DashboardData)
async def get_dashboard_data_api(user: str = Depends(check_auth)) -> Any:
    """Return the current dashboard data including minimal settings."""
    state.dashboard_data["settings"] = {"processing_interval": state.settings.get("processing_interval")}
    
    # Debug: Log dashboard data being returned
    logging.info(f"Dashboard API returning {len(state.dashboard_data.get('issues', []))} issues")
    if state.dashboard_data.get('issues'):
        for issue in state.dashboard_data['issues']:
            logging.info(f"Issue: {issue.get('title', 'No title')} - Category: {issue.get('category', 'No category')}")
    
    return state.dashboard_data


@app.get("/api/logs/{log_id}")
async def get_log_details(log_id: str, user: str = Depends(check_auth)) -> Any:
    """Fetch a single log by SHA256."""
    async with state.vector_lock:
        log = state.metadata_db.get(log_id)
        if not log:
            raise HTTPException(status_code=404, detail="Log not found")
        escaped_log = json.loads(json.dumps(log).replace('<', '&lt;').replace('>', '&gt;'))
        return JSONResponse(content=escaped_log)


@app.get("/metrics", response_class=PlainTextResponse)
async def get_metrics() -> Any:
    """Expose application metrics in Prometheus format (no auth)."""
    return await state.metrics.get_metrics_text()


@app.post("/api/chat/analyze")
async def chat_analyze(req: QueryRequest, user: str = Depends(check_auth)) -> Any:
    """Analyze the user's query with NER enhancement and plan an information gathering strategy."""
    logging.info(f"Analyzing chat query with NER: {req.query}")
    try:
        analysis = await chat_analyze_with_ner(req.query)
        return JSONResponse(content=analysis)
    except Exception as e:
        logging.error(f"NER-enhanced chat analysis failed: {e}")
        fallback = {
            "search_strategy": "General search approach due to analysis error",
            "search_queries": [req.query],
            "keywords": [],
            "need_issues": True,
            "focus_areas": ["general security"],
            "estimated_complexity": "simple",
            "entity_insights": "NER extraction failed"
        }
        return JSONResponse(content=fallback)


@app.post("/api/chat/execute")
async def chat_execute(request: Dict[str, Any], user: str = Depends(check_auth)) -> Any:
    """Execute a chat plan with NER-enhanced hybrid search and return the AI's answer."""
    query = request.get("query", "")
    analysis = request.get("analysis", {})
    history = request.get("history", [])
    logging.info(f"Executing NER-enhanced chat plan for query: {query}")
    try:
        answer = await chat_execute_with_ner(query, analysis, history)
        return JSONResponse(content={"answer": answer})
    except Exception as e:
        logging.error(f"NER-enhanced chat execution failed: {e}")
        return JSONResponse(content={"answer": f"I encountered an error while analyzing your request: {e}. Please try rephrasing your question."}, status_code=500)


@app.post("/api/analyze")
async def manual_analyze(user: str = Depends(check_auth)) -> Any:
    """Trigger manual NER-enhanced analysis of new logs."""
    logging.info("Manual NER-enhanced analysis triggered")
    from .log_processing import process_logs, update_dashboard_metrics
    try:
        new_logs = await process_logs()
        update_dashboard_metrics(new_logs)
        if new_logs:
            await analyze_context_with_ner_enhancement(new_logs)
        state.dashboard_data["last_run"] = datetime.now().isoformat()  # type: ignore[name-defined]
        await save_dashboard_data()
        logging.info("Manual NER-enhanced analysis completed")
        return {"status": "NER-enhanced analysis triggered"}
    except Exception as e:
        logging.error(f"Manual NER-enhanced analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"NER-enhanced analysis failed: {e}")


@app.post("/api/issues/{issue_id}/ignore")
async def ignore_issue(issue_id: str, user: str = Depends(check_auth)) -> Any:
    """Ignore a detected issue and remove it from the dashboard."""
    state.dashboard_data["issues"] = [i for i in state.dashboard_data["issues"] if i["id"] != issue_id]
    state.ignored_issue_ids.add(issue_id)
    state.dashboard_data["stats"]["anomalies"] = len(state.dashboard_data["issues"])
    await save_dashboard_data()
    from .persistence import save_ignored_issues
    save_ignored_issues()
    logging.info(f"Issue {issue_id} ignored and added to persistent ignore list")
    return {"status": "Issue ignored"}


@app.post("/api/issues/{issue_id}/query")
async def query_issue(issue_id: str, req: QueryRequest, user: str = Depends(check_auth)) -> Any:
    """Answer a question related to a specific issue using comprehensive log retrieval."""
    issue = next((i for i in state.dashboard_data["issues"] if i["id"] == issue_id), None)
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    
    try:
        logging.info(f"Answering question about issue: {issue['title']} - Question: {req.query}")
        
        # Get basic related logs
        async with state.vector_lock:
            basic_related_logs = [state.metadata_db.get(log_id) for log_id in issue.get("related_logs", [])[:10] if state.metadata_db.get(log_id)]
        
        # Use comprehensive search to find additional relevant logs for the question
        combined_query = f"{req.query} {issue['title']} {issue['summary']}"
        
        all_relevant_logs = []
        seen_shas = set()
        
        # Add basic related logs first
        for log in basic_related_logs:
            if log and log.get('sha256'):
                all_relevant_logs.append(log)
                seen_shas.add(log['sha256'])
        
        # Comprehensive search for the user's specific question
        try:
            comprehensive_results = await comprehensive_log_search(combined_query, max_results=100)
            for result in comprehensive_results['results'][:30]:  # Top 30 results
                log_data = result.get('metadata', {})
                sha = log_data.get('sha256', '')
                if sha and sha not in seen_shas:
                    all_relevant_logs.append(log_data)
                    seen_shas.add(sha)
                    
        except Exception as e:
            logging.warning(f"Comprehensive search failed for issue query: {e}")
        
        # Also search for the issue title and summary to get more context
        try:
            issue_context_results = await comprehensive_log_search(issue['title'], max_results=50)
            for result in issue_context_results['results'][:20]:
                log_data = result.get('metadata', {})
                sha = log_data.get('sha256', '')
                if sha and sha not in seen_shas:
                    all_relevant_logs.append(log_data)
                    seen_shas.add(sha)
                    
        except Exception as e:
            logging.warning(f"Issue context search failed: {e}")
        
        # Limit to most relevant logs
        final_logs = all_relevant_logs[:40]  # More comprehensive than before
        
        log_context_str = json.dumps(final_logs, indent=1)
        history_str = "\n".join([f"User: {h['user']}\nAI: {h['ai']}" for h in req.history[-2:]]) if req.history else ""
        
        logging.info(f"Using {len(final_logs)} logs for issue query (vs {len(basic_related_logs)} basic related logs)")
        
        prompt = f"""You are a helpful security analyst assistant with comprehensive log analysis capabilities. A user is asking a question about a specific security issue. Use the extensive log context and conversation history to provide a thorough answer.

**Issue Details:**
Title: {issue["title"]}
Summary: {issue["summary"]}
Recommendation: {issue["recommendation"]}

**Conversation History:**
{history_str}

**User Question:**
{req.query}

**Comprehensive Log Context ({len(final_logs)} relevant logs found):**

```json
{log_context_str}
```

**Critical Instructions:**

You have access to comprehensive log data gathered through advanced search techniques, including:
- Original issue-related logs
- Logs found through comprehensive search of the user's question combined with issue details
- Additional context logs related to the issue title and summary

**Response Requirements:**

1. Answer the user's question directly and thoroughly based on ALL available log data
2. Cite specific Log SHA256 hashes that support your answer
3. Look for patterns and correlations across the comprehensive log set
4. If you find relevant information in the logs, explain what it reveals about the user's question
5. If the comprehensive search still doesn't provide enough information, state that clearly
6. Present the answer in a clear, readable format
7. Take advantage of the comprehensive log context to provide detailed insights

**Response Guidelines:**

- Be thorough but focused on the user's specific question
- Reference multiple logs when they support your analysis
- Explain any patterns or trends you identify in the comprehensive data
- Provide actionable insights when possible
- Maximum response length: 600 words (increased due to comprehensive context)
"""

        answer = await call_gemini_api(prompt, model_name=PRO_MODEL)
        
        return JSONResponse(content={
            "answer": answer,
            "metadata": {
                "total_logs_analyzed": len(final_logs),
                "basic_related_logs": len(basic_related_logs),
                "comprehensive_search_used": True
            }
        })
        
    except Exception as e:
        logging.error(f"Comprehensive issue query failed: {e}")
        return JSONResponse(content={"answer": f"Error communicating with AI: {e}"}, status_code=500)


@app.post("/api/issues/{issue_id}/generate-script")
async def generate_script(issue_id: str, user: str = Depends(check_auth)) -> Any:
    """Generate a comprehensive diagnosis and repair script using comprehensive log retrieval."""
    issue = next((i for i in state.dashboard_data["issues"] if i["id"] == issue_id), None)
    if not issue:
        raise HTTPException(status_code=404, detail="Issue not found")
    
    try:
        logging.info(f"Generating script for issue: {issue['title']}")
        
        # Get basic related logs
        async with state.vector_lock:
            basic_related_logs = [state.metadata_db.get(log_id) for log_id in issue.get("related_logs", [])[:10] if state.metadata_db.get(log_id)]
        
        # Use comprehensive search to find ALL relevant logs for this issue
        search_queries = [
            issue["title"],
            issue["summary"],
            f"{issue['title']} error failure",
            f"{issue['title']} authentication certificate cryptographic",
        ]
        
        all_relevant_logs = []
        seen_shas = set()
        
        # Add basic related logs first
        for log in basic_related_logs:
            if log and log.get('sha256'):
                all_relevant_logs.append(log)
                seen_shas.add(log['sha256'])
        
        # Comprehensive search for additional context
        for search_query in search_queries:
            try:
                comprehensive_results = await comprehensive_log_search(search_query, max_results=100)
                for result in comprehensive_results['results'][:30]:  # Top 30 per query
                    log_data = result.get('metadata', {})
                    sha = log_data.get('sha256', '')
                    if sha and sha not in seen_shas:
                        all_relevant_logs.append(log_data)
                        seen_shas.add(sha)
                        
            except Exception as e:
                logging.warning(f"Comprehensive search failed for query '{search_query}': {e}")
        
        # Extract entities from issue and search for entity-specific logs
        try:
            from .ner_utils import extract_entities
            issue_text = f"{issue['title']} {issue['summary']}"
            entities = extract_entities(issue_text)
            
            for entity in entities[:5]:  # Top 5 entities
                try:
                    entity_logs = await get_entity_focused_logs(entity, 'COMPUTER', max_results=20)
                    for result in entity_logs:
                        log_data = result.get('metadata', {})
                        sha = log_data.get('sha256', '')
                        if sha and sha not in seen_shas:
                            all_relevant_logs.append(log_data)
                            seen_shas.add(sha)
                except Exception as e:
                    logging.debug(f"Entity search failed for {entity}: {e}")
                    
        except Exception as e:
            logging.warning(f"Entity extraction for script generation failed: {e}")
        
        # Limit to most relevant logs (sorted by relevance if available)
        final_logs = all_relevant_logs[:50]  # Much more comprehensive than before
        
        log_context_str = json.dumps(final_logs, indent=2)
        
        logging.info(f"Using {len(final_logs)} logs for script generation (vs {len(basic_related_logs)} basic related logs)")
        
        prompt = f"""You are an expert security engineer with access to comprehensive log analysis. Generate a detailed diagnosis and automatic repair script for the following security issue using the extensive log context provided.

**Issue Details:**
Title: {issue["title"]}
Severity: {issue["severity"]}  
Summary: {issue["summary"]}
Current Recommendation: {issue["recommendation"]}

**Comprehensive Log Context ({len(final_logs)} relevant logs found):**

```json
{log_context_str}
```

**Critical Instructions:**

You have access to comprehensive log data that was gathered using advanced search techniques. This includes:
- Original issue-related logs
- Logs found through semantic search of the issue title and summary
- Entity-specific logs for systems, users, and processes mentioned
- Related security events and failures

**Script Requirements:**

1. Create a bash script that performs the following:
   - Initial comprehensive diagnosis commands to verify the issue
   - Backup any configurations that will be modified
   - Step-by-step remediation actions based on ALL log evidence
   - Verification commands to confirm the issue is resolved
   - Rollback procedure if something goes wrong

2. The script should:
   - Be safe and include error handling
   - Log all actions to /var/log/wazuh_repair_$(date +%Y%m%d_%H%M%S).log
   - Request confirmation before making critical changes
   - Be compatible with common Linux distributions (Ubuntu, CentOS, RHEL)
   - Include detailed comments explaining each step
   - Be limited to 250 lines maximum (increased due to comprehensive context)

3. Focus on:
   - The specific issue identified and patterns found in the comprehensive log data
   - ALL systems/IPs/users/processes mentioned across the logs
   - Wazuh-specific configurations if relevant
   - System hardening based on the complete attack vector analysis
   - Address root causes identified through the comprehensive log analysis

4. Use the comprehensive log context to:
   - Identify all affected systems and components
   - Understand the full scope and timeline of the issue
   - Address related security concerns found in the logs
   - Implement preventive measures based on log patterns

Output ONLY the complete bash script, starting with #!/bin/bash."""

        script = await call_gemini_api(prompt, model_name=PRO_MODEL)
        
        # Clean up script formatting
        if "```bash" in script:
            script = script.split("```bash", 1)[-1].rsplit("```", 1)[0].strip()
        elif "```" in script:
            script = script.split("```", 1)[-1].rsplit("```", 1)[0].strip()
            
        if not script.startswith("#!/bin/bash"):
            script = "#!/bin/bash\n" + script
            
        # Increase line limit due to comprehensive context
        lines = script.split('\n')
        if len(lines) > 250:
            script = '\n'.join(lines[:250]) + '\n# Script truncated to 250 lines for safety'
        
        # Add enhanced safety disclaimer
        safety_disclaimer = f"""#!/bin/bash

# COMPREHENSIVE SCRIPT DISCLAIMER: This script was auto-generated by AI using comprehensive log analysis.
# Generated from {len(final_logs)} relevant logs vs {len(basic_related_logs)} basic related logs.
# Please review carefully before execution. Test in a safe environment first.
# The script may need adjustments for your specific environment.
# This script addresses patterns found across comprehensive log data.
"""
        if "COMPREHENSIVE SCRIPT DISCLAIMER" not in script:
            script = script.replace("#!/bin/bash", safety_disclaimer, 1)
            
        return JSONResponse(content={
            "script": script,
            "metadata": {
                "total_logs_analyzed": len(final_logs),
                "basic_related_logs": len(basic_related_logs),
                "comprehensive_search_used": True,
                "entities_extracted": len(entities) if 'entities' in locals() else 0
            }
        })
        
    except Exception as e:
        logging.error(f"Comprehensive script generation failed: {e}")
        return JSONResponse(content={"script": f"# Error generating comprehensive script: {e}"}, status_code=500)


@app.get("/api/settings")
async def get_settings(user: str = Depends(check_auth)) -> Any:
    """Return the current configuration settings."""
    return state.settings


@app.post("/api/settings")
async def update_settings(new_settings: Settings, user: str = Depends(check_auth)) -> Any:
    """Update configuration settings."""
    state.settings.update({k: v for k, v in new_settings.dict().items() if v is not None})
    save_settings()
    return {"status": "Settings updated"}


@app.post("/api/clear_db")
async def api_clear_database(user: str = Depends(check_auth)) -> Any:
    """Clear the vector database and dashboard state."""
    from .vector_db import clear_database
    await clear_database()
    return {"status": "Database cleared"}


# Hierarchical Summarization API Endpoints

@app.get("/api/hierarchical_summary/status")
async def get_hierarchical_summary_status(user: str = Depends(check_auth)) -> Any:
    """Get the status of the hierarchical summarization system."""
    try:
        from .rag_interface import RAGInterface
        rag = RAGInterface()
        status = await rag.get_hierarchical_summary_status()
        return status
    except Exception as e:
        logging.error(f"Failed to get hierarchical summary status: {e}")
        return {"available": False, "error": str(e)}


@app.post("/api/hierarchical_summary/run_nightly")
async def run_nightly_summarization(user: str = Depends(check_auth), target_date: str = None) -> Any:
    """Run the nightly summarization process."""
    try:
        from .rag_interface import RAGInterface
        rag = RAGInterface()
        result = await rag.run_nightly_summarization(target_date)
        return result
    except Exception as e:
        logging.error(f"Failed to run nightly summarization: {e}")
        return {"success": False, "error": str(e)}


@app.get("/api/hierarchical_summary/query")
async def query_hierarchical_summaries(
    query: str,
    level: str = None,
    start_date: str = None,
    end_date: str = None,
    limit: int = 50,
    user: str = Depends(check_auth)
) -> Any:
    """Query hierarchical summaries with filters."""
    try:
        from .rag_interface import RAGInterface
        rag = RAGInterface()
        result = await rag.query_hierarchical_summaries(
            query=query,
            level=level,
            start_date=start_date,
            end_date=end_date,
            limit=limit
        )
        return result
    except Exception as e:
        logging.error(f"Failed to query hierarchical summaries: {e}")
        return {"summaries": [], "error": str(e)}


@app.get("/api/hierarchical_summary/levels")
async def get_summary_levels(user: str = Depends(check_auth)) -> Any:
    """Get available summary levels."""
    try:
        from .hierarchical_summary.models import SummaryLevel
        return {
            "levels": [level.value for level in SummaryLevel],
            "descriptions": {
                "cluster": "Groups of related logs (5-50 logs)",
                "daily": "Daily security summary aggregating cluster summaries",
                "weekly": "Weekly trends and major incidents analysis",
                "monthly": "Monthly security posture assessment", 
                "quarterly": "Quarterly executive reporting and strategic analysis"
            }
        }
    except Exception as e:
        logging.error(f"Failed to get summary levels: {e}")
        return {"levels": [], "error": str(e)}


@app.post("/api/hierarchical_summary/generate")
async def generate_summary(
    content: List[Dict[str, Any]],
    scope: str = "cluster",
    user: str = Depends(check_auth)
) -> Any:
    """Generate a summary for provided content."""
    try:
        from .rag_interface import RAGInterface
        rag = RAGInterface()
        
        # Use the RAG interface to generate summary
        result = await rag.summarize(content, scope)
        
        return {
            "summary": result.summary,
            "scope": result.scope,
            "item_count": result.item_count,
            "confidence_score": result.confidence_score,
            "key_insights": result.key_insights,
            "generation_time_ms": result.generation_time_ms,
            "metadata": result.metadata
        }
    except Exception as e:
        logging.error(f"Failed to generate summary: {e}")
        return {"error": str(e)}


@app.get("/api/hierarchical_summary/performance")
async def get_summary_performance_metrics(user: str = Depends(check_auth)) -> Any:
    """Get performance metrics for the hierarchical summarization system."""
    try:
        from .rag_interface import RAGInterface
        rag = RAGInterface()
        
        if not rag._hierarchical_summary:
            return {"error": "Hierarchical summarizer not available"}
            
        if await rag._is_hierarchical_summarizer_ready():
            status = await rag._hierarchical_summary.get_system_status()
            return {
                "performance_metrics": status.get("performance_metrics", {}),
                "storage_stats": status.get("storage_stats", {}),
                "last_updated": datetime.utcnow().isoformat()
            }
        else:
            return {"error": "Hierarchical summarizer not ready"}
            
    except Exception as e:
        logging.error(f"Failed to get performance metrics: {e}")
        return {"error": str(e)}


@app.post("/api/hierarchical_summary/optimize")
async def optimize_summarization_performance(user: str = Depends(check_auth)) -> Any:
    """Run performance optimization on the hierarchical summarization system."""
    try:
        from .rag_interface import RAGInterface
        rag = RAGInterface()
        
        if not rag._hierarchical_summary:
            return {"error": "Hierarchical summarizer not available"}
            
        if await rag._is_hierarchical_summarizer_ready():
            result = await rag._hierarchical_summary.optimize_performance()
            return result
        else:
            return {"error": "Hierarchical summarizer not ready"}
            
    except Exception as e:
        logging.error(f"Failed to optimize performance: {e}")
        return {"error": str(e)}