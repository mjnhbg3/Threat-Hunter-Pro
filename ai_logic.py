"""
AI interaction and analysis logic for Threat Hunter.

This module contains helper functions for counting tokens, rate
limiting Gemini API usage, sending prompts to the Gemini service,
summarising logs, generating retrieval queries, identifying new
security issues and answering chat queries. The functions in this
module are used by the background worker and the FastAPI endpoints.

Although the implementations mirror those in the monolithic script,
some error handling and logging has been streamlined for clarity.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import hashlib
import time
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional

import httpx
import google.generativeai as genai  # type: ignore

from . import state
from .config import (
    GEMINI_API_KEYS,
    LITE_MODEL,
    FULL_MODEL,
    PRO_MODEL,
    MODEL_QUOTA,
)
from .token_bucket import TokenBucket
from .metrics import MetricsCollector
from .vector_db import search_vector_db
from .persistence import save_dashboard_data
from .ner_utils import extract_entities, extract_entities_with_labels
from .enhanced_retrieval import comprehensive_log_search, get_entity_focused_logs


# -----------------------------------------------------------------------------
# Token counting
# -----------------------------------------------------------------------------

def count_tokens_local(text: str, model_name: str) -> int:
    """Approximate token counting based on text characteristics."""
    try:
        model = genai.GenerativeModel(model_name)
        result = model.count_tokens(text)
        return result.total_tokens
    except Exception as e:
        logging.warning(f"Token counting failed for {model_name}: {e}. Using character-based estimate.")
        char_count = len(text.encode('utf-8'))
        if text.strip().startswith('{') or '"' in text[:100]:
            estimated_tokens = char_count // 3
        else:
            estimated_tokens = char_count // 4
        return max(1, estimated_tokens)


# -----------------------------------------------------------------------------
# Rate limiting helpers
# -----------------------------------------------------------------------------

def get_model_family(model_name: str) -> str:
    name_lower = model_name.lower()
    if "pro" in name_lower:
        return "pro"
    if "lite" in name_lower:
        return "flash-lite"
    return "flash"


def get_or_create_bucket(api_key: str, bucket_type: str, model_name: str = None) -> TokenBucket:
    """Get or create a rate limiting bucket for the specified API key and model."""
    # Determine model family and get appropriate limits
    if model_name:
        model_family = get_model_family(model_name)
        rpm_limit, tpm_limit, _ = MODEL_QUOTA.get(model_family, (10, 250_000, 250))
    else:
        # Default to flash limits if no model specified
        rpm_limit, tpm_limit = 10, 250_000
    
    # Use safety margins: 95% of actual limits
    safe_rpm = int(rpm_limit * 0.95)
    safe_tpm = int(tpm_limit * 0.95)
    
    bucket_key = f"{api_key}_{model_family if model_name else 'default'}"
    buckets_dict = state.rpm_buckets if bucket_type == "rpm" else state.tpm_buckets
    
    if bucket_key not in buckets_dict:
        if bucket_type == "rpm":
            buckets_dict[bucket_key] = TokenBucket(safe_rpm, safe_rpm / 60.0)
        else:
            buckets_dict[bucket_key] = TokenBucket(safe_tpm, safe_tpm / 60.0)
    
    return buckets_dict[bucket_key]


async def find_best_api_key(required_tokens: int, model_name: str = FULL_MODEL) -> Tuple[str, int]:
    """Find the API key with the most available capacity for the required tokens."""
    if not GEMINI_API_KEYS:
        raise RuntimeError("No GEMINI_API_KEY configured.")
    
    best_key_index = state.current_api_key_index
    best_capacity = 0.0
    current_key_capacity = 0.0
    
    for i, key in enumerate(GEMINI_API_KEYS):
        rpm_bucket = get_or_create_bucket(key, "rpm", model_name)
        tpm_bucket = get_or_create_bucket(key, "tpm", model_name)
        
        # Calculate available capacity as minimum of RPM and TPM ratios
        rpm_capacity = rpm_bucket.tokens / rpm_bucket.capacity
        tpm_capacity = tpm_bucket.tokens / tpm_bucket.capacity
        combined_capacity = min(rpm_capacity, tpm_capacity)
        
        # Track current key's capacity for pre-emptive switching
        if i == state.current_api_key_index:
            current_key_capacity = combined_capacity
        
        # Check if this key can handle the required tokens
        can_handle = (rpm_bucket.tokens >= 1 and tpm_bucket.tokens >= required_tokens)
        
        if can_handle and combined_capacity > best_capacity:
            best_capacity = combined_capacity
            best_key_index = i
    
    # Pre-emptive switching: if current key is below 20% capacity and better key available
    should_switch = (
        best_key_index != state.current_api_key_index and
        (current_key_capacity < 0.2 or best_capacity > current_key_capacity + 0.3)
    )
    
    if should_switch:
        logging.info(f"Pre-emptively switching to API key {best_key_index + 1} (capacity: {best_capacity:.2f} vs current: {current_key_capacity:.2f})")
        state.current_api_key_index = best_key_index
        state.dashboard_data["active_api_key_index"] = state.current_api_key_index
        genai.configure(api_key=GEMINI_API_KEYS[best_key_index])
    
    return GEMINI_API_KEYS[best_key_index], best_key_index


async def rotate_api_key() -> Tuple[str, int]:
    """Rotate the active Gemini API key and reconfigure the genai client."""
    if not GEMINI_API_KEYS:
        raise RuntimeError("No GEMINI_API_KEY configured.")
    async with state.api_key_lock:
        old_index = state.current_api_key_index
        state.current_api_key_index = (state.current_api_key_index + 1) % len(GEMINI_API_KEYS)
        state.dashboard_data["active_api_key_index"] = state.current_api_key_index
        new_key = GEMINI_API_KEYS[state.current_api_key_index]
        genai.configure(api_key=new_key)
        state.consecutive_failures[GEMINI_API_KEYS[old_index]] = 0
        logging.info(f"Rotated from API key {old_index + 1} to {state.current_api_key_index + 1}")
    return new_key, state.current_api_key_index


async def call_gemini_api(prompt: str, is_json_output: bool = False, model_name: str = FULL_MODEL) -> str:
    """
    Send a prompt to the Gemini generative language model and return
    the raw response text. Implements rate limiting, token counting
    and automatic retry/rotation of API keys.
    """
    if not GEMINI_API_KEYS:
        raise RuntimeError("No GEMINI_API_KEY configured.")
    if state.http_client is None:
        state.http_client = httpx.AsyncClient(timeout=180.0)
    model_family = get_model_family(model_name)
    input_tokens = count_tokens_local(prompt, model_name)
    # Adjust output token limits based on model
    if model_name == PRO_MODEL:
        max_output = min(state.settings.get("max_output_tokens", 8192), 8192)
    elif model_name == LITE_MODEL:
        max_output = min(state.settings.get("max_output_tokens", 8192), 8192)
    else:  # FULL_MODEL (Flash)
        max_output = min(state.settings.get("max_output_tokens", 8192), 8192)
    
    expected_output = max_output
    total_expected = input_tokens + expected_output
    
    # Use consistent context limit for all models
    if total_expected > 200_000:
        raise ValueError(f"Prompt too large: {total_expected} tokens exceeds safe limit")
    max_retries = 15
    retry_count = 0
    while retry_count < max_retries:
        # Use intelligent key selection to find best available key
        current_key, key_index = await find_best_api_key(total_expected, model_name)
        rpm_bucket = get_or_create_bucket(current_key, "rpm", model_name)
        tpm_bucket = get_or_create_bucket(current_key, "tpm", model_name)
        await rpm_bucket.wait_for_tokens(1)
        await tpm_bucket.wait_for_tokens(total_expected)
        api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={current_key}"
        # Build payload with model-specific configurations
        generation_config = {"maxOutputTokens": expected_output}
        
        # Fix JSON schema - must include properties for object type
        if is_json_output:
            generation_config["responseMimeType"] = "application/json"
            generation_config["responseSchema"] = {
                "type": "object",
                "properties": {
                    "response": {
                        "type": "string",
                        "description": "The JSON response content"
                    }
                },
                "required": ["response"]
            }
        
        payload: Dict[str, Any] = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": generation_config,
        }
        try:
            resp = await state.http_client.post(api_url, json=payload, headers={'Content-Type': 'application/json'})
            await state.metrics.increment_requests(model_family)
            if resp.status_code == 429:
                await state.metrics.increment_429s(model_family)
                state.consecutive_failures[current_key] += 1
                logging.warning(f"Rate limit hit on key {key_index + 1} (failure #{state.consecutive_failures[current_key]})")
                
                # Immediately try to find a different key instead of waiting
                if len(GEMINI_API_KEYS) > 1:
                    # Mark current key as temporarily exhausted by depleting its buckets
                    rpm_bucket.tokens = 0
                    tpm_bucket.tokens = 0
                    
                    # Try to find another key with capacity
                    try_key, try_index = await find_best_api_key(total_expected, model_name)
                    if try_index != key_index:
                        logging.info(f"Switching to key {try_index + 1} after 429 on key {key_index + 1}")
                        retry_count += 1
                        continue
                
                # If no other keys available or single key, use shorter wait time
                retry_after = resp.headers.get('Retry-After')
                wait_time = min(int(retry_after) if retry_after else 2, 5)  # Cap at 5 seconds
                logging.warning(f"No alternative keys available, waiting {wait_time}s")
                await asyncio.sleep(wait_time)
                retry_count += 1
                continue
            resp.raise_for_status()
            state.consecutive_failures[current_key] = 0
            result = resp.json()
            await state.metrics.add_tokens(model_family, "in", input_tokens)
            await state.metrics.add_tokens(model_family, "out", expected_output)
            if 'candidates' in result and result['candidates']:
                candidate = result['candidates'][0]
                if 'content' in candidate and 'parts' in candidate['content'] and candidate['content']['parts']:
                    part = candidate['content']['parts'][0]
                    if 'text' in part:
                        return part['text']
                finish_reason = candidate.get('finishReason', 'UNKNOWN')
                return f"Generation stopped: {finish_reason}"
            elif 'error' in result:
                error_msg = result['error'].get('message', 'Unknown error')
                raise RuntimeError(f"Gemini API Error: {error_msg}")
            else:
                raise RuntimeError("Invalid response structure from Gemini API.")
        except httpx.TimeoutException as e:
            logging.warning(f"Request timed out: {e}. Retrying...")
            await asyncio.sleep(min(2 ** retry_count, 30))
            retry_count += 1
            continue
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                continue
            elif e.response.status_code == 400:
                # Log detailed error information for 400 Bad Request
                error_msg = "Unknown error"
                try:
                    error_detail = e.response.json()
                    error_msg = str(error_detail)
                    logging.error(f"400 Bad Request with model {model_name}: {error_detail}")
                except:
                    error_msg = e.response.text
                    logging.error(f"400 Bad Request with model {model_name}: {e.response.text}")
                
                # If Pro model fails, try Flash model instead
                if model_name == PRO_MODEL and retry_count < 2:
                    logging.info(f"Pro model failed with 400, retrying with Flash model")
                    model_name = FULL_MODEL
                    retry_count += 1
                    continue
                # If Flash model fails, try Flash-Lite
                elif model_name == FULL_MODEL and retry_count < 2:
                    logging.info(f"Flash model failed with 400, retrying with Flash-Lite model")  
                    model_name = LITE_MODEL
                    retry_count += 1
                    continue
                    
                # If all models fail, raise the error with details
                raise RuntimeError(f"400 Bad Request for model {model_name}: {error_msg}")
            raise RuntimeError(f"HTTP error: {e}") from e
        except Exception as e:
            raise RuntimeError(f"Unexpected error during Gemini API call: {e}") from e
    raise RuntimeError("Max retries exceeded.")


# -----------------------------------------------------------------------------
# JSON extraction helper
# -----------------------------------------------------------------------------

def extract_json_from_string(text: str) -> Optional[str]:
    """Attempt to extract the first valid JSON object from arbitrary text."""
    if not text:
        logging.debug("Empty text provided to JSON extractor")
        return None
    
    original_text = text
    text = text.strip()
    
    # Log the first 200 chars for debugging
    logging.debug(f"Attempting JSON extraction from: {text[:200]}...")
    
    # Try different extraction methods
    extraction_methods = []
    
    # Method 1: Extract from ```json code blocks
    if "```json" in text:
        extracted = text.split("```json", 1)[-1].rsplit("```", 1)[0].strip()
        extraction_methods.append(("json_code_block", extracted))
    
    # Method 2: Extract from generic code blocks  
    elif "```" in text and text.count("```") >= 2:
        extracted = text.split("```", 1)[-1].rsplit("```", 1)[0].strip()
        extraction_methods.append(("generic_code_block", extracted))
    
    # Method 3: Use the raw text
    extraction_methods.append(("raw_text", text))
    
    # Method 4: Try to find JSON in the middle of text
    if '{' in text and '}' in text:
        # Find the largest JSON-like structure
        first_brace = text.find('{')
        last_brace = text.rfind('}')
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            extracted = text[first_brace:last_brace + 1]
            extraction_methods.append(("brace_extraction", extracted))
    
    # Try each extraction method
    for method_name, candidate_text in extraction_methods:
        if not candidate_text.strip():
            continue
            
        # Find JSON object boundaries
        start_pos = candidate_text.find('{')
        if start_pos == -1:
            # Try array format
            start_pos = candidate_text.find('[')
            if start_pos == -1:
                continue
                
        brace_count = 0
        end_pos = -1
        open_char = candidate_text[start_pos]
        close_char = '}' if open_char == '{' else ']'
        
        for i in range(start_pos, len(candidate_text)):
            if candidate_text[i] == open_char:
                brace_count += 1
            elif candidate_text[i] == close_char:
                brace_count -= 1
                if brace_count == 0:
                    end_pos = i + 1
                    break
        
        if end_pos == -1:
            # Fallback: find last closing brace
            end_pos = candidate_text.rfind(close_char) + 1
            if end_pos == 0:
                continue
                
        json_str = candidate_text[start_pos:end_pos]
        
        # Try to parse the extracted JSON
        parsing_attempts = [
            ("original", json_str),
            ("trailing_comma_fix", re.sub(r',(\s*[}\]])', r'\1', json_str)),
            ("quote_fix", json_str.replace("'", '"')),
            ("newline_fix", json_str.replace('\n', ' ').replace('\r', '')),
        ]
        
        for attempt_name, attempt_json in parsing_attempts:
            try:
                parsed = json.loads(attempt_json)
                logging.debug(f"JSON extraction successful using {method_name} + {attempt_name}")
                return attempt_json
            except json.JSONDecodeError as e:
                logging.debug(f"JSON parse failed ({method_name} + {attempt_name}): {e}")
                continue
    
    # If all methods fail, try advanced JSON repair techniques
    logging.warning(f"JSON extraction failed, attempting advanced JSON repair...")
    try:
        fixed_json = _advanced_json_repair(original_text)
        if fixed_json:
            logging.info("Advanced JSON repair successful")
            return fixed_json
    except Exception as e:
        logging.debug(f"Advanced JSON repair failed: {e}")
    
    # Final fallback: log the original text for debugging
    logging.warning(f"All JSON extraction methods failed. Original response: {original_text[:500]}...")
    return None


def _advanced_json_repair(text: str) -> Optional[str]:
    """Advanced JSON repair using heuristic fixes."""
    if not text:
        return None
    
    # Common JSON repair techniques
    repair_attempts = []
    
    # Find potential JSON content
    lines = text.split('\n')
    json_lines = []
    in_json = False
    brace_count = 0
    
    for line in lines:
        stripped = line.strip()
        
        # Start collecting when we see opening brace
        if '{' in stripped and not in_json:
            in_json = True
            brace_count = 0
        
        if in_json:
            json_lines.append(line)
            # Count braces to know when JSON ends
            brace_count += stripped.count('{') - stripped.count('}')
            if brace_count <= 0 and '}' in stripped:
                break
    
    if json_lines:
        potential_json = '\n'.join(json_lines)
        repair_attempts.append(("line_by_line", potential_json))
    
    # Try the original text with various fixes
    repair_attempts.extend([
        ("original", text),
        ("stripped", text.strip()),
        ("single_line", text.replace('\n', ' ').replace('\r', '')),
    ])
    
    # For each candidate, try multiple repair strategies
    for attempt_name, candidate in repair_attempts:
        if not candidate:
            continue
            
        # Find JSON boundaries
        start_pos = candidate.find('{')
        if start_pos == -1:
            start_pos = candidate.find('[')
            if start_pos == -1:
                continue
        
        # Extract to end of string first
        json_part = candidate[start_pos:]
        
        # Try to find proper end
        if candidate[start_pos] == '{':
            brace_count = 0
            end_pos = -1
            for i, char in enumerate(json_part):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i + 1
                        break
            if end_pos > 0:
                json_part = json_part[:end_pos]
        
        # Apply various fixes
        fixes = [
            ("original", json_part),
            ("trailing_comma", re.sub(r',(\s*[}\]])', r'\1', json_part)),
            ("unquoted_keys", re.sub(r'(\w+):', r'"\1":', json_part)),
            ("single_quotes", json_part.replace("'", '"')),
            ("escape_quotes", json_part.replace('\\"', '"').replace('"', '\\"')),
            ("combined", re.sub(r',(\s*[}\]])', r'\1', 
                               re.sub(r'(\w+):', r'"\1":', json_part.replace("'", '"')))),
        ]
        
        for fix_name, fixed_candidate in fixes:
            try:
                # Try to parse
                parsed = json.loads(fixed_candidate)
                logging.debug(f"JSON repair successful: {attempt_name} + {fix_name}")
                return fixed_candidate
            except json.JSONDecodeError:
                continue
    
    return None


async def _ai_assisted_json_repair(malformed_response: str) -> Optional[str]:
    """Ask the AI to repair its own malformed JSON response."""
    if not malformed_response:
        return None
    
    repair_prompt = f"""The following is a malformed JSON response that needs to be fixed. Please repair it and return ONLY the corrected JSON object.

Malformed JSON response:
{malformed_response}

Requirements:
1. Return ONLY valid JSON - no explanations, no markdown formatting, no code blocks
2. Fix any syntax errors (missing quotes, trailing commas, unescaped characters, etc.)
3. Preserve all the original data and structure
4. Ensure all strings are properly quoted with double quotes
5. Start your response with {{ and end with }}

Fixed JSON:"""

    try:
        # Use the LITE model for quick repair
        repaired_response = await call_gemini_api(repair_prompt, is_json_output=True, model_name=LITE_MODEL)
        
        # Use the same extraction logic to get clean JSON
        extracted_json = extract_json_from_string(repaired_response)
        
        if extracted_json:
            # Verify it's actually valid JSON
            json.loads(extracted_json)
            return extracted_json
            
    except Exception as e:
        logging.debug(f"AI-assisted JSON repair failed: {e}")
    
    return None


# -----------------------------------------------------------------------------
# Issue signature helper
# -----------------------------------------------------------------------------

def generate_issue_signature(issue_data: Dict[str, Any]) -> str:
    """Create a short hash signature based on severity, title and summary."""
    severity = issue_data.get('severity', '').lower()
    title_words = issue_data.get('title', '').lower().split()[:5]
    summary_words = issue_data.get('summary', '').lower().split()[:10]
    signature_text = f"{severity}|{' '.join(title_words)}|{' '.join(summary_words)}"
    return hashlib.sha256(signature_text.encode()).hexdigest()[:16]


# -----------------------------------------------------------------------------
# Log summarisation and retrieval query generation
# -----------------------------------------------------------------------------

def prepare_full_log_context(logs: List[Dict[str, Any]]) -> str:
    """Prepare a JSON representation of log metadata for embedding."""
    context_list = [log.get('metadata', log) for log in logs if log.get('metadata', log)]
    return json.dumps(context_list[:300], indent=2)


async def generate_retrieval_queries(recent_logs_summary: str) -> List[str]:
    """Use Gemini to produce search queries based on recent logs summary."""
    prompt = f"""Analyze the following summary of recent logs and generate 2 search queries to retrieve relevant historical context from a vector database of past logs. The queries should capture potential patterns, anomalies, or related events.

Recent Logs Summary:
{recent_logs_summary}

Output ONLY a JSON array of strings, e.g., [\"query1\", \"query2\"].
"""
    try:
        raw_response = await call_gemini_api(prompt, is_json_output=True, model_name=LITE_MODEL)
        queries = json.loads(raw_response)
        return queries if isinstance(queries, list) else []
    except Exception as e:
        logging.error(f"Failed to generate retrieval queries: {e}")
        return []


async def summarize_logs(logs: List[Dict[str, Any]], log_type: str = "historical") -> str:
    """Summarise a list of logs using the Gemini API, chunking if necessary."""
    if not logs:
        return f"No {log_type} logs available."
    chunk_size = 100
    logs_to_process = logs[:500]
    summaries: List[str] = []
    num_chunks = (len(logs_to_process) // chunk_size) + 1
    for i in range(0, len(logs_to_process), chunk_size):
        chunk = logs_to_process[i:i+chunk_size]
        logs_str = prepare_full_log_context(chunk)
        prompt = f"""Summarize the following {log_type} logs, highlighting key patterns, security events, anomalies, and correlations. Include relevant details like timestamps, IPs, users, systems, and rule descriptions.

{log_type.capitalize()} Logs:
{logs_str}

Output ONLY the summary text.
"""
        try:
            summary = await call_gemini_api(prompt, model_name=LITE_MODEL)
            summaries.append(summary)
        except Exception as e:
            logging.error(f"Failed to summarise {log_type} chunk: {e}")
    if len(summaries) > 1:
        combined_prompt = f"""Combine these {log_type} chunk summaries into a single comprehensive summary. Highlight overall patterns, security trends, anomalies, and key correlations across all timeframes and systems.

Chunk Summaries:
{chr(10).join(summaries)}

Output ONLY the combined comprehensive summary text.
"""
        try:
            return await call_gemini_api(combined_prompt, model_name=LITE_MODEL)
        except Exception as e:
            logging.error(f"Failed to combine summaries: {e}")
            return '\n'.join(summaries)
    return summaries[0]


# -----------------------------------------------------------------------------
# Issue analysis
# -----------------------------------------------------------------------------

async def _process_and_add_comprehensive_issues(detected_issues: List[Dict[str, Any]], recent_logs: List[Dict[str, Any]]) -> None:
    """Process comprehensive issues and add them to the dashboard."""
    try:
        logging.info(f"Processing {len(detected_issues)} comprehensive issues")
        
        new_issues: List[Dict[str, Any]] = []
        for issue_data in detected_issues:
            try:
                # Check if essential fields exist (title and severity are minimum)
                if not issue_data.get('title') or not issue_data.get('severity'):
                    logging.warning(f"Issue missing essential fields (title/severity): {issue_data}")
                    continue
                
                # Generate unique ID if missing
                issue_id = issue_data.get('id')
                if not issue_id:
                    # Create ID from title hash and timestamp
                    title_hash = hashlib.md5(issue_data['title'].encode()).hexdigest()[:8]
                    issue_id = f"comp_{title_hash}_{int(time.time())}"
                
                # Add default fields if missing
                issue = {
                    "id": issue_id,
                    "title": issue_data.get('title', 'Unknown Issue'),
                    "severity": issue_data.get('severity', 'medium').lower(),
                    "summary": issue_data.get('summary', 'No summary available'),
                    "category": issue_data.get('category', 'operational'),
                    "timestamp": datetime.now().isoformat(),
                    "related_logs": issue_data.get('related_logs', []),
                    "recommendation": issue_data.get('recommendation', ''),
                    "source": "comprehensive_analysis"
                }
                
                new_issues.append(issue)
                logging.info(f"Processed comprehensive issue: {issue['title']} ({issue['category']})")
                
            except Exception as e:
                logging.error(f"Error processing comprehensive issue: {e}, issue_data: {issue_data}")
                continue
        
        # Add to dashboard
        existing_issue_ids = {i['id'] for i in state.dashboard_data["issues"]}
        for issue in new_issues:
            if issue['id'] not in existing_issue_ids:
                state.dashboard_data["issues"].insert(0, issue)
                logging.info(f"Added comprehensive issue to dashboard: {issue['title']}")
        
        # Update stats
        state.dashboard_data["issues"] = state.dashboard_data["issues"][:state.settings.get("max_issues", 1000)]
        state.dashboard_data["stats"]["anomalies"] = len(state.dashboard_data["issues"])
        
        # Save changes
        await save_dashboard_data()
        logging.info(f"Added {len(new_issues)} comprehensive issues to dashboard")
        
    except Exception as e:
        logging.error(f"Error processing comprehensive issues: {e}")


async def analyze_comprehensive_issues(logs: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Use AI to comprehensively analyze logs for both security and operational issues.
    Returns categorized issues: {"security_issues": [...], "operational_issues": [...]}
    """
    logging.info(f"analyze_comprehensive_issues called with {len(logs)} logs")
    if not logs:
        logging.info("No logs provided to analyze_comprehensive_issues")
        return {"security_issues": [], "operational_issues": []}
    
    # Prepare log context for comprehensive analysis
    log_context = prepare_full_log_context(logs[:100])  # Analyze up to 100 recent logs
    
    prompt = f"""You are a security and system analyst. Analyze these logs and AGGRESSIVELY identify ANY issues that warrant attention.

FIND ISSUES IN THESE CATEGORIES:
- SECURITY: Failed logins, privilege changes, suspicious network activity, authentication issues, access violations
- OPERATIONAL: Error messages, service failures, high resource usage, configuration problems, repeated warnings

You MUST look for patterns like:
- Multiple failures from same source
- Error codes and exception messages  
- Authentication or authorization failures
- System service problems
- Network connectivity issues
- Resource exhaustion signs
- Configuration mismatches

Return this JSON format:

{{
"security_issues": [
{{
"severity": "High",
"title": "Specific issue found",
"summary": "What happened and why it's concerning", 
"recommendation": "How to investigate or fix it",
"related_logs": ["actual_sha256_hash_from_logs"]
}}
],
"operational_issues": [
{{
"severity": "Medium", 
"title": "Specific operational problem",
"summary": "What's wrong and the impact",
"recommendation": "Steps to resolve",
"related_logs": ["actual_sha256_hash_from_logs"]
}}
]
}}

CRITICAL: Do NOT return empty arrays unless you've thoroughly analyzed every log entry and found absolutely nothing suspicious, concerning, or problematic. Look harder for patterns, errors, failures, or anomalies.

LOG DATA TO ANALYZE:
{log_context[:15000]}

Return ONLY the JSON object."""

    try:
        logging.info(f"Sending comprehensive analysis prompt to AI with {len(logs)} logs")
        raw_response = await call_gemini_api(prompt, is_json_output=True, model_name=FULL_MODEL)
        logging.info(f"AI raw response (first 500 chars): {raw_response[:500]}")
        json_str = extract_json_from_string(raw_response)
        
        if not json_str:
            logging.warning(f"Failed to extract JSON from comprehensive analysis. Raw response length: {len(raw_response)}")
            logging.warning(f"Raw response content: {raw_response}")
            return {"security_issues": [], "operational_issues": []}
        
        result = json.loads(json_str)
        
        # Handle wrapped response from Gemini API
        if "response" in result and isinstance(result["response"], str):
            try:
                result = json.loads(result["response"])
                logging.info("Unwrapped nested JSON response from AI")
            except json.JSONDecodeError:
                logging.warning("Failed to parse nested response JSON")
                return {"security_issues": [], "operational_issues": []}
        
        # Validate structure
        if not isinstance(result, dict):
            return {"security_issues": [], "operational_issues": []}
        
        security_issues = result.get("security_issues", [])
        operational_issues = result.get("operational_issues", [])
        
        if not isinstance(security_issues, list):
            security_issues = []
        if not isinstance(operational_issues, list):
            operational_issues = []
        
        logging.info(f"Comprehensive analysis found {len(security_issues)} security issues and {len(operational_issues)} operational issues")
        return {"security_issues": security_issues, "operational_issues": operational_issues}
        
    except Exception as e:
        logging.error(f"Error in comprehensive issue analysis: {e}")
        return {"security_issues": [], "operational_issues": []}


async def analyze_context_and_identify_issues(recent_logs: List[Dict[str, Any]]) -> None:
    """
    Perform AI analysis on recent logs and identify new security issues.
    Updates state.dashboard_data with the analysis summary and issues.
    """
    if not recent_logs:
        state.dashboard_data["summary"] = "No new activity detected."
        await state.metrics.set_cycle_time(0.0)  # no analysis time
        await state.metrics.set_cycle_time(0.0)
        await state.metrics.set_cycle_time(0.0)
        return
    try:
        logging.info(f"Starting AI analysis with {len(recent_logs)} new logs")
        
        # First, run comprehensive AI analysis to detect both security and operational issues
        state.set_app_status("Running comprehensive issue analysis...")
        comprehensive_results = await analyze_comprehensive_issues(recent_logs)
        all_detected_issues = comprehensive_results["security_issues"] + comprehensive_results["operational_issues"]
        logging.info(f"Comprehensive analysis found {len(comprehensive_results['security_issues'])} security issues and {len(comprehensive_results['operational_issues'])} operational issues")
        
        # Debug: Log the actual results for troubleshooting
        if comprehensive_results['security_issues']:
            logging.info(f"Security issues found: {[issue.get('title', 'No title') for issue in comprehensive_results['security_issues']]}")
        if comprehensive_results['operational_issues']:
            logging.info(f"Operational issues found: {[issue.get('title', 'No title') for issue in comprehensive_results['operational_issues']]}")
        
        # Process and add comprehensive issues to dashboard immediately
        if all_detected_issues:
            logging.info(f"Processing {len(all_detected_issues)} comprehensive issues for dashboard")
            # Tag issues with proper categories before processing
            categorized_issues = []
            for issue in comprehensive_results["security_issues"]:
                issue["category"] = "security"
                categorized_issues.append(issue)
            for issue in comprehensive_results["operational_issues"]:
                issue["category"] = "operational" 
                categorized_issues.append(issue)
            await _process_and_add_comprehensive_issues(categorized_issues, recent_logs)
        
        state.set_app_status("Summarizing recent logs...")
        recent_logs_subset = recent_logs[:200]
        recent_summary = await summarize_logs(recent_logs_subset, "recent")
        state.set_app_status("Generating search queries...")
        retrieval_queries = await generate_retrieval_queries(recent_summary)
        state.set_app_status("Searching historical logs...")
        combined_historical_logs: List[Dict[str, Any]] = []
        seen_shas = {log.get('sha256', '') for log in recent_logs}
        for query in retrieval_queries[:3]:
            try:
                related = await search_vector_db(query, k=100)
                for item in related:
                    md = item['metadata']
                    if md.get('sha256') not in seen_shas:
                        combined_historical_logs.append(md)
                        seen_shas.add(md.get('sha256', ''))
                        if len(combined_historical_logs) >= 300:
                            break
                if len(combined_historical_logs) >= 300:
                    break
            except Exception as e:
                logging.error(f"Error in retrieval query '{query}': {e}")
        logging.info(f"Retrieved {len(combined_historical_logs)} historical logs")
        state.set_app_status("Summarizing historical context...")
        historical_summary = await summarize_logs(combined_historical_logs, "historical")
        # Prepare context for main analysis
        recent_logs_str = prepare_full_log_context(recent_logs_subset)
        existing_issues_context: List[Dict[str, Any]] = []
        for issue in state.dashboard_data["issues"][:20]:
            issue_summary = {
                "id": issue["id"],
                "severity": issue["severity"],
                "title": issue["title"],
                "summary": issue["summary"][:200],
                "timestamp": issue["timestamp"]
            }
            existing_issues_context.append(issue_summary)
        existing_issues_str = json.dumps(existing_issues_context, indent=1)
        prompt = f"""You are a senior security analyst named 'Threat Hunter Pro'. Analyze security logs and return findings in JSON format.

CRITICAL INSTRUCTIONS:

1. Your response must be EXACTLY this JSON structure with NO additional text, explanations, or formatting
2. Check existing issues to avoid exact duplicates, but create new issues for different security events
3. Focus on identifying ALL security threats that warrant investigation - be thorough, not conservative
4. ENSURE related_logs contains actual SHA256 hashes from the provided log data

{{
\"overall_summary\": \"Brief summary of current security situation and new findings\",
\"identified_issues\": [
{{
\"severity\": \"Low|Medium|High|Critical\",
\"title\": \"Unique, descriptive title not matching existing issues\",
\"summary\": \"Detailed explanation of this specific new threat\",
\"recommendation\": \"Specific action steps for this issue\",
\"related_logs\": [\"sha256_hash1\", \"sha256_hash2\"]
}}
]
}}

**EXISTING ISSUES TO AVOID DUPLICATING:**
{existing_issues_str}

**CONTEXT FOR ANALYSIS:**
Historical Context: {historical_summary[:2000]}

Recent Activity Summary: {recent_summary[:3000]}

Sample Recent Logs: {recent_logs_str[:10000]}

**ANALYSIS REQUIREMENTS:**

1. Create overall_summary describing the CURRENT security situation and any developments
2. PROACTIVELY identify security issues that require attention - err on the side of detection rather than missing threats
3. Create issues for patterns like:
   - Multiple failures (cryptographic, authentication, audit) from same source
   - Concentrated suspicious activity within short time windows  
   - Privilege escalations or special logons during anomalous periods
   - Repeated error patterns that could indicate attacks or system compromise
   - Any Windows Event IDs 5061 (crypto failures), 4625 (failed logons), 4672 (special privileges)
4. Use severity: Low, Medium, High, or Critical based on actual threat level
5. Include specific SHA256 hashes in related_logs from the log data provided above
6. Focus on ACTIONABLE threats and suspicious patterns that warrant investigation
7. Better to create an issue for investigation than miss a potential security incident
8. Ensure related_logs contains valid SHA256 hashes from the actual log data

IMPORTANT: Return ONLY the JSON object above with your analysis data filled in. Do not include any explanatory text, markdown formatting, or code blocks. Start your response with {{ and end with }}."""
        token_count = count_tokens_local(prompt, FULL_MODEL)
        if token_count > 150_000:
            # Reduce sample logs if too big
            prompt = prompt.replace(f"Sample Recent Logs: {recent_logs_str[:10000]}", "Sample Recent Logs: Content reduced due to size constraints.")
        try:
            state.set_app_status("Sending to Gemini AI...")
            raw_response = await call_gemini_api(prompt, is_json_output=True, model_name=FULL_MODEL)
            json_str = extract_json_from_string(raw_response)
            if not json_str:
                logging.error("No valid JSON object found in AI response")
                # Try AI-assisted JSON repair as a last resort
                try:
                    logging.info("Attempting AI-assisted JSON repair...")
                    repaired_json = await _ai_assisted_json_repair(raw_response)
                    if repaired_json:
                        analysis_result = json.loads(repaired_json)
                        logging.info("AI-assisted JSON repair successful!")
                    else:
                        raise ValueError("AI repair failed")
                except Exception as repair_error:
                    logging.warning(f"AI-assisted JSON repair failed: {repair_error}")
                    # Fallback to extracting meaningful summary
                    fallback_summary = "AI analysis completed but JSON parsing failed."
                    if raw_response:
                        # Try to extract meaningful text from the response
                        lines = raw_response.strip().split('\n')
                        meaningful_lines = [line.strip() for line in lines if line.strip() and not line.strip().startswith('{') and not line.strip().startswith('}')]
                        if meaningful_lines:
                            fallback_summary = meaningful_lines[0][:200] + "..." if len(meaningful_lines[0]) > 200 else meaningful_lines[0]
                    
                    analysis_result = {
                        "overall_summary": fallback_summary,
                        "identified_issues": []
                    }
            else:
                analysis_result = json.loads(json_str)
        except Exception as e:
            logging.error(f"Error during AI analysis: {e}")
            state.dashboard_data["summary"] = f"AI analysis failed: {e}"
            await save_dashboard_data()
            return
        # Validate result
        if not isinstance(analysis_result, dict):
            logging.error("Analysis result is not a dictionary")
            state.dashboard_data["summary"] = "Analysis result format error: expected dictionary"
            await save_dashboard_data()
            return
        if "overall_summary" not in analysis_result:
            state.dashboard_data["summary"] = "Analysis completed but missing summary field"
            await save_dashboard_data()
            return
        state.set_app_status("Processing results...")
        state.dashboard_data["summary"] = analysis_result.get("overall_summary", "Analysis complete.")
        new_issues: List[Dict[str, Any]] = []
        
        # Combine pattern-based issues with AI-detected issues
        identified_issues = analysis_result.get("identified_issues", [])
        if not isinstance(identified_issues, list):
            identified_issues = []
        
        # Add comprehensive analysis issues with proper categorization
        for issue in comprehensive_results["security_issues"]:
            issue["category"] = "security"
            identified_issues.append(issue)
        for issue in comprehensive_results["operational_issues"]:
            issue["category"] = "operational"
            identified_issues.append(issue)
        
        existing_signatures: set[str] = set()
        for existing_issue in state.dashboard_data["issues"]:
            existing_signatures.add(generate_issue_signature(existing_issue))
        for issue_data in identified_issues:
            try:
                required_fields = ["severity", "title", "summary", "recommendation"]
                if not all(field in issue_data for field in required_fields):
                    continue
                
                # Ensure category field exists, default to security for backward compatibility
                if "category" not in issue_data:
                    issue_data["category"] = "security"
                issue_signature = generate_issue_signature(issue_data)
                if issue_signature in existing_signatures:
                    continue
                issue_id = hashlib.sha256(issue_data['title'].encode()).hexdigest()[:10]
                if issue_id in state.ignored_issue_ids:
                    continue
                related_logs = issue_data.get('related_logs', [])
                cleaned_logs: List[str] = []
                for log_ref in related_logs:
                    if isinstance(log_ref, str) and len(log_ref) >= 8:
                        cleaned_logs.append(log_ref)
                    elif isinstance(log_ref, dict) and 'sha256' in log_ref:
                        cleaned_logs.append(log_ref['sha256'])
                issue_data['related_logs'] = cleaned_logs
                issue = {
                    "id": issue_id,
                    "timestamp": datetime.now().isoformat(),
                    **issue_data
                }
                new_issues.append(issue)
                existing_signatures.add(issue_signature)
            except Exception as e:
                logging.error(f"Error processing issue: {e}, issue_data: {issue_data}")
                continue
        existing_issue_ids = {i['id'] for i in state.dashboard_data["issues"]}
        truly_new_issues: List[Dict[str, Any]] = []
        for issue in new_issues:
            if issue['id'] not in existing_issue_ids:
                state.dashboard_data["issues"].insert(0, issue)
                truly_new_issues.append(issue)
        state.dashboard_data["issues"] = state.dashboard_data["issues"][:state.settings.get("max_issues", 1000)]
        state.dashboard_data["stats"]["anomalies"] = len(state.dashboard_data["issues"])
        await save_dashboard_data()
        logging.info(f"AI analysis complete. Found {len(truly_new_issues)} new unique issues.")
    except Exception as e:
        logging.error(f"Error during AI analysis: {e}")
        state.dashboard_data["summary"] = f"AI analysis failed: {e}"
        await save_dashboard_data()


# -----------------------------------------------------------------------------
# Enhanced chat functions with NER integration
# -----------------------------------------------------------------------------

async def chat_analyze_with_ner(query: str) -> Dict[str, Any]:
    """Analyze user query with NER to extract entities and plan search strategy."""
    logging.info(f"Analyzing chat query with NER: {query}")
    
    # Extract entities from user query for enhanced search
    try:
        extracted_entities = extract_entities(query)
        entity_labels = extract_entities_with_labels(query)
        logging.debug(f"Query entities: {len(extracted_entities)} found")
    except Exception as e:
        logging.warning(f"NER extraction failed for query: {e}")
        extracted_entities = []
        entity_labels = []
    
    # Build context-aware prompt
    total_logs = state.dashboard_data["stats"]["total_logs"]
    recent_issues = len(state.dashboard_data["issues"])
    
    entity_context = ""
    if extracted_entities:
        entity_context = f"\n**Extracted Entities:** {', '.join(extracted_entities[:10])}"
        if entity_labels:
            entity_types = [f"{text} ({label})" for text, label in entity_labels[:5]]
            entity_context += f"\n**Entity Types:** {', '.join(entity_types)}"
    
    analysis_prompt = f"""You are a security analyst AI assistant with entity recognition capabilities. A user has asked a question about their security logs and issues. Your job is to analyze their query and determine what information you need to gather to provide a comprehensive answer.

**User Query:** {query}{entity_context}

**Available Data Context:**
- Total indexed logs: {total_logs:,}
- Current security issues: {recent_issues}
- Vector database with full log history available
- Real-time security issue tracking
- NER-enhanced search capabilities

**Your Task:**
Analyze the user's query and extracted entities to determine:
1. What specific information you need to search for
2. What search queries would be most effective (incorporate entities when relevant)
3. Whether you need current issues, historical logs, or both
4. What keywords to use for hybrid search (BM25 + semantic)

Respond with a JSON object containing your analysis plan:
{{
"search_strategy": "brief description of your approach",
"search_queries": ["query1", "query2", "query3"],
"keywords": ["keyword1", "keyword2", "keyword3"],
"need_issues": true/false,
"focus_areas": ["area1", "area2"],
"estimated_complexity": "simple|moderate|complex",
"entity_insights": "how entities inform the search strategy"
}}

Examples of good search queries incorporating entities:
- "failed login attempts [IP_ADDRESS]"
- "suspicious connections from [HOSTNAME]"
- "malware detection [USER_ACCOUNT]"
- "privilege escalation [PROCESS_NAME]"

For keywords, use specific terms that would benefit from BM25 keyword matching:
- IP addresses, hostnames, usernames
- Process names, file paths
- Error codes, rule names

Respond ONLY with the JSON object."""

    try:
        response_text = await call_gemini_api(analysis_prompt, is_json_output=True, model_name=LITE_MODEL)
        
        # Use enhanced JSON extraction
        json_str = extract_json_from_string(response_text)
        if not json_str:
            logging.error("No valid JSON object found in chat analysis response")
            raise ValueError("Failed to extract JSON from AI response")
        
        analysis = json.loads(json_str)
        
        # Validate and enhance with extracted entities
        if not isinstance(analysis, dict):
            raise ValueError("Invalid analysis response structure")
        
        # Add extracted entities to keywords if not already present
        if "keywords" not in analysis:
            analysis["keywords"] = []
        
        # Merge extracted entities with AI-suggested keywords
        entity_keywords = [entity.lower() for entity in extracted_entities if len(entity) > 2]
        existing_keywords = [kw.lower() for kw in analysis.get("keywords", [])]
        
        for entity in entity_keywords:
            if entity not in existing_keywords:
                analysis["keywords"].append(entity)
        
        # Ensure we have search queries
        if "search_queries" not in analysis or not analysis["search_queries"]:
            analysis["search_queries"] = [query]
        
        return analysis
        
    except Exception as e:
        logging.error(f"Chat analysis with NER failed: {e}")
        fallback = {
            "search_strategy": "General search approach due to analysis error",
            "search_queries": [query],
            "keywords": extracted_entities[:5],  # Use extracted entities as keywords
            "need_issues": True,
            "focus_areas": ["general security"],
            "estimated_complexity": "simple",
            "entity_insights": f"Extracted {len(extracted_entities)} entities from query"
        }
        return fallback


async def chat_execute_with_ner(query: str, analysis: Dict[str, Any], history: List[Dict[str, Any]] = None) -> str:
    """Execute chat plan with comprehensive retrieval system."""
    if history is None:
        history = []
    
    logging.info(f"Executing comprehensive chat search for query: {query}")
    
    try:
        # Gather issue context
        issue_context: List[Dict[str, Any]] = []
        if analysis.get("need_issues") and state.dashboard_data["issues"]:
            recent_issues = state.dashboard_data["issues"][:10]
            for issue in recent_issues:
                if any(word.lower() in issue["title"].lower() or word.lower() in issue["summary"].lower()
                       for word in query.lower().split()):
                    issue_context.append({
                        "title": issue["title"],
                        "severity": issue["severity"],
                        "summary": issue["summary"][:300],
                        "timestamp": issue["timestamp"]
                    })
            issue_context = issue_context[:5]
        
        # Use comprehensive search instead of limited search
        logging.info("Starting comprehensive log search...")
        search_results = await comprehensive_log_search(query, max_results=150)
        
        # Process comprehensive search results
        all_search_results = []
        for result in search_results['results'][:50]:  # Take top 50 for context
            log_data = result.get('metadata', {})
            compact_log = {
                "timestamp": log_data.get("timestamp", ""),
                "rule": log_data.get("rule", {}).get("description", "")[:100],
                "level": log_data.get("rule", {}).get("level", ""),
                "agent": log_data.get("agent", {}).get("name", ""),
                "sha256": log_data.get("sha256", "")[:8],
                "search_score": result.get("relevance_score", 0),
                "search_strategy": result.get("search_strategy", "unknown"),
                "matched_entity": result.get("matched_entity", "")
            }
            
            if "data" in log_data and log_data["data"]:
                compact_log["data"] = str(log_data["data"])[:200]  # More data for comprehensive view
            
            # Add comprehensive search metadata
            compact_log["match_type"] = "comprehensive"
            if result.get("bm25_score", 0) > 0:
                compact_log["match_type"] = "hybrid"
            
            all_search_results.append(compact_log)
        
        # Prepare enhanced context strings
        issue_context_str = json.dumps(issue_context, indent=1) if issue_context else "[]"
        logs_context_str = json.dumps(all_search_results, indent=1) if all_search_results else "[]"
        
        # Format conversation history
        history_str = ""
        if history:
            history_str = "\n".join([
                f"User: {h.get('user', '')[:100]}\nAI: {h.get('ai', '')[:200]}" for h in history[-2:]
            ])
        
        # Enhanced search metadata
        search_metadata = search_results.get('search_metadata', {})
        entity_stats = search_results.get('entity_stats', {})
        strategy_stats = search_results.get('strategy_stats', {})
        
        search_summary = f"""
**Comprehensive Search Results:**
- Total logs found: {search_results['total_results']}
- Entities detected: {search_metadata.get('entities_found', 0)}
- Search completeness: {search_metadata.get('search_completeness', 0):.1f}%
- Strategy breakdown: {', '.join(f"{k}: {v}" for k, v in strategy_stats.items())}
- Entity matches: {', '.join(f"{k}: {v}" for k, v in entity_stats.items() if k != 'no_entity')}
"""
        
        final_prompt = f"""You are an expert security analyst AI assistant with comprehensive log analysis capabilities. Based on the extensive multi-stage search results, provide a thorough and helpful response to the user's question.

**User Question:** {query}

**Recent Conversation:**
{history_str}

{search_summary}

**Relevant Security Issues Found:**
{issue_context_str}

**Comprehensive Log Data Found ({len(all_search_results)} of {search_results['total_results']} total entries):**
{logs_context_str}

**Critical Instructions:**
1. You have access to a comprehensive search that used multiple strategies (entity-exact, semantic, AI-generated, related-term searches)
2. The search found {search_results['total_results']} total relevant logs - this is much more comprehensive than typical searches
3. Pay special attention to logs with high relevance_scores and specific matched_entity fields
4. Look for patterns across different search strategies and entity matches
5. If you see logs related to the user's question, analyze them thoroughly even if they seem indirectly related

**Response Requirements:**
1. Provide a comprehensive answer to the user's question based on ALL available log data
2. Reference specific findings from the issues and logs with SHA256 hashes
3. Include relevant timestamps, severity levels, and entity relationships
4. Identify patterns, trends, and correlations across the log data
5. Provide actionable insights or recommendations
6. If you found relevant logs, explain what they reveal about the user's question
7. Mention the comprehensive nature of the search and what it uncovered
8. Keep the response well-structured and easy to read

**Response Guidelines:**
- Be conversational but professional
- Focus on security implications and actual findings
- Highlight the most important discoveries first
- Use bullet points or numbered lists for clarity when appropriate
- Maximum response length: 800 words (increased for comprehensive results)
- Always explain what the comprehensive search found, even if results seem indirect
"""

        # Token management with higher limits for comprehensive results
        token_count = count_tokens_local(final_prompt, PRO_MODEL)
        if token_count > 120_000:  # Higher limit for comprehensive search
            # Reduce context to fit within limits but keep more data than before
            logs_context_str = json.dumps(all_search_results[:25], indent=1)
            issue_context_str = json.dumps(issue_context[:5], indent=1)
            final_prompt = f"""You are a security analyst AI assistant with comprehensive search capabilities. Answer the user's question based on extensive log analysis.

**User Question:** {query}

**Search Summary:** Found {search_results['total_results']} total logs using comprehensive multi-stage search

**Security Issues:** {issue_context_str}

**Top Log Data (25 of {search_results['total_results']} total):** {logs_context_str}

Provide a thorough response focusing on the comprehensive findings. Include specific log references and explain what the extensive search revealed about the user's question."""

        answer = await call_gemini_api(final_prompt, model_name=PRO_MODEL)
        return answer
        
    except Exception as e:
        logging.error(f"Comprehensive chat execution failed: {e}")
        return f"I encountered an error while analyzing your request: {e}. Please try rephrasing your question."


async def analyze_context_with_ner_enhancement(recent_logs: List[Dict[str, Any]]) -> None:
    """Enhanced analysis function that incorporates NER for better entity detection in issues."""
    if not recent_logs:
        state.dashboard_data["summary"] = "No new activity detected."
        return
    
    try:
        logging.info(f"Starting NER-enhanced AI analysis with {len(recent_logs)} new logs")
        state.set_app_status("Extracting entities from recent logs...")
        
        # Extract entities from recent logs for enhanced context
        all_entities = set()
        entity_log_map = {}
        
        for log in recent_logs[:50]:  # Process subset for entity extraction
            try:
                log_text = json.dumps({
                    "rule": log.get("rule", {}),
                    "data": log.get("data", {}),
                    "full_log": log.get("full_log", "")
                })
                
                entities = extract_entities(log_text)
                log_sha = log.get('sha256', '')
                
                for entity in entities:
                    all_entities.add(entity)
                    if entity not in entity_log_map:
                        entity_log_map[entity] = []
                    entity_log_map[entity].append(log_sha)
                    
            except Exception as e:
                logging.debug(f"Entity extraction failed for log: {e}")
                continue
        
        logging.info(f"Entity extraction: {len(all_entities)} unique entities found")
        
        # Continue with enhanced analysis using entities
        state.set_app_status("Summarizing recent logs...")
        recent_logs_subset = recent_logs[:200]
        
        # Only summarize if we have a substantial number of logs to reduce API calls
        if len(recent_logs_subset) > 20:
            recent_summary = await summarize_logs(recent_logs_subset, "recent")
        else:
            # For small log sets, create a simple summary without AI
            recent_summary = f"Analysis of {len(recent_logs_subset)} recent security events with entities: {', '.join(list(all_entities)[:10])}"
        
        # Generate enhanced retrieval queries using entities (rule-based, no API calls)
        state.set_app_status("Generating entity-enhanced search queries...")
        retrieval_queries = await generate_enhanced_retrieval_queries(recent_summary, list(all_entities)[:20])
        
        # Enhanced search with comprehensive retrieval
        state.set_app_status("Searching historical logs with comprehensive retrieval...")
        combined_historical_logs: List[Dict[str, Any]] = []
        seen_shas = {log.get('sha256', '') for log in recent_logs}
        
        # Use comprehensive search for each retrieval query
        for query in retrieval_queries[:2]:  # Reduced to 2 queries but more comprehensive each
            try:
                comprehensive_results = await comprehensive_log_search(query, max_results=200)
                for item in comprehensive_results['results']:
                    md = item.get('metadata', {})
                    if md.get('sha256') not in seen_shas:
                        combined_historical_logs.append(md)
                        seen_shas.add(md.get('sha256', ''))
                        if len(combined_historical_logs) >= 400:  # Increased limit
                            break
                if len(combined_historical_logs) >= 400:
                    break
            except Exception as e:
                logging.error(f"Comprehensive retrieval query '{query}' failed: {e}")
        
        # Also search for entity-specific logs
        top_entities = sorted(entity_log_map.items(), key=lambda x: len(x[1]), reverse=True)[:5]
        for entity, _ in top_entities:
            try:
                entity_logs = await get_entity_focused_logs(entity, 'COMPUTER', max_results=50)
                for item in entity_logs:
                    md = item.get('metadata', {})
                    if md.get('sha256') not in seen_shas:
                        combined_historical_logs.append(md)
                        seen_shas.add(md.get('sha256', ''))
            except Exception as e:
                logging.debug(f"Entity-focused search failed for {entity}: {e}")
        
        logging.info(f"Retrieved {len(combined_historical_logs)} historical logs using comprehensive retrieval")
        
        # Continue with standard analysis process
        state.set_app_status("Summarizing historical context...")
        historical_summary = await summarize_logs(combined_historical_logs, "historical")
        
        # Enhanced analysis prompt with entity context
        await _perform_enhanced_analysis_with_entities(
            recent_logs_subset, recent_summary, historical_summary, all_entities, entity_log_map
        )
        
    except Exception as e:
        logging.error(f"Error during NER-enhanced analysis: {e}")
        state.dashboard_data["summary"] = f"Enhanced AI analysis failed: {e}"
        await save_dashboard_data()


async def generate_enhanced_retrieval_queries(recent_logs_summary: str, entities: List[str]) -> List[str]:
    """Generate retrieval queries enhanced with extracted entities using rule-based approach."""
    queries = []
    
    # Base queries from summary keywords
    try:
        # Extract key terms from summary
        summary_words = recent_logs_summary.lower().split()
        security_keywords = [
            word for word in summary_words 
            if any(term in word for term in ['error', 'fail', 'alert', 'warn', 'critical', 'auth', 'crypto', 'cert', 'suspicious', 'attack'])
        ]
        
        if security_keywords:
            queries.append(' '.join(security_keywords[:3]))
        
    except Exception:
        pass
    
    # Entity-based queries
    if entities:
        # General entity search
        queries.append(' '.join(entities[:5]))
        
        # Security-focused entity queries
        for entity in entities[:3]:
            queries.extend([
                f"{entity} authentication failure",
                f"{entity} security event",
                f"{entity} error alert"
            ])
    
    # Fallback generic security queries
    fallback_queries = [
        "security events authentication",
        "system failures errors",
        "suspicious activity alerts"
    ]
    
    # Combine and deduplicate
    all_queries = queries + fallback_queries
    unique_queries = []
    seen = set()
    
    for query in all_queries:
        if query and query not in seen:
            unique_queries.append(query)
            seen.add(query)
    
    # Return top 3 queries
    result_queries = unique_queries[:3] if unique_queries else ["security events", "authentication failures", "system errors"]
    
    logging.info(f"Generated {len(result_queries)} rule-based retrieval queries")
    return result_queries


async def _perform_enhanced_analysis_with_entities(
    recent_logs: List[Dict[str, Any]], 
    recent_summary: str, 
    historical_summary: str, 
    entities: set, 
    entity_log_map: Dict[str, List[str]]
) -> None:
    """Perform the main analysis with entity context."""
    
    # First run comprehensive analysis for both security and operational issues
    comprehensive_results = await analyze_comprehensive_issues(recent_logs)
    all_detected_issues = comprehensive_results["security_issues"] + comprehensive_results["operational_issues"]
    logging.info(f"Enhanced analysis found {len(comprehensive_results['security_issues'])} security issues and {len(comprehensive_results['operational_issues'])} operational issues")
    
    # Process and add comprehensive issues to dashboard immediately
    if all_detected_issues:
        logging.info(f"Processing {len(all_detected_issues)} comprehensive issues for enhanced analysis")
        # Tag issues with proper categories before processing
        categorized_issues = []
        for issue in comprehensive_results["security_issues"]:
            issue["category"] = "security"
            categorized_issues.append(issue)
        for issue in comprehensive_results["operational_issues"]:
            issue["category"] = "operational"
            categorized_issues.append(issue)
        await _process_and_add_comprehensive_issues(categorized_issues, recent_logs)
    
    # Prepare enhanced context
    recent_logs_str = prepare_full_log_context(recent_logs)
    existing_issues_context: List[Dict[str, Any]] = []
    
    for issue in state.dashboard_data["issues"][:20]:
        issue_summary = {
            "id": issue["id"],
            "severity": issue["severity"],
            "title": issue["title"],
            "summary": issue["summary"][:200],
            "timestamp": issue["timestamp"]
        }
        existing_issues_context.append(issue_summary)
    
    existing_issues_str = json.dumps(existing_issues_context, indent=1)
    
    # Entity insights for better issue correlation
    entity_insights = ""
    if entities:
        high_frequency_entities = sorted(entity_log_map.items(), key=lambda x: len(x[1]), reverse=True)[:10]
        entity_insights = f"\n**Key Entities Analysis:**\n"
        for entity, log_shas in high_frequency_entities:
            entity_insights += f"- {entity}: appears in {len(log_shas)} logs\n"
    
    prompt = f"""You are a senior security analyst named 'Threat Hunter Pro' with advanced entity recognition capabilities. Analyze security logs and return findings in JSON format, leveraging extracted entities for better correlation and detection.

CRITICAL INSTRUCTIONS:
1. Your response must be EXACTLY this JSON structure with NO additional text, explanations, or formatting
2. DO NOT create duplicate issues - check against existing issues first
3. Focus on NEW, UNIQUE security threats not already identified
4. ENSURE related_logs contains actual SHA256 hashes from the provided log data
5. Use entity analysis to identify patterns and correlations

{{
"overall_summary": "Brief summary of current security situation and new findings",
"identified_issues": [
{{
"severity": "Low|Medium|High|Critical",
"title": "Unique, descriptive title not matching existing issues",
"summary": "Detailed explanation of this specific new threat",
"recommendation": "Specific action steps for this issue",
"related_logs": ["sha256_hash1", "sha256_hash2"]
}}
]
}}

**EXISTING ISSUES TO AVOID DUPLICATING:**
{existing_issues_str}

**CONTEXT FOR ANALYSIS:**
Historical Context: {historical_summary[:2000]}

Recent Activity Summary: {recent_summary[:3000]}{entity_insights}

Sample Recent Logs: {recent_logs_str[:10000]}

**ANALYSIS REQUIREMENTS:**
1. Create overall_summary describing the CURRENT security situation and any NEW developments
2. Only add to identified_issues array if you find NEW, UNIQUE security incidents not covered by existing issues
3. Use severity: Low, Medium, High, or Critical based on actual threat level
4. Include specific SHA256 hashes in related_logs from the log data provided above
5. If no NEW issues found (only existing ones), use empty identified_issues array: []
6. Focus on ACTIONABLE threats that require immediate attention
7. Leverage entity patterns to identify related incidents and coordinated attacks
8. Consider entity frequency and correlation across logs for threat assessment

IMPORTANT: Return ONLY the JSON object above with your analysis data filled in. Do not include any explanatory text, markdown formatting, or code blocks. Start your response with {{ and end with }}."""

    token_count = count_tokens_local(prompt, FULL_MODEL)
    if token_count > 150_000:
        # Reduce context if too large
        prompt = prompt.replace(f"Sample Recent Logs: {recent_logs_str[:10000]}", 
                               "Sample Recent Logs: Content reduced due to size constraints.")
    
    try:
        state.set_app_status("Sending enhanced analysis to Gemini AI...")
        raw_response = await call_gemini_api(prompt, is_json_output=True, model_name=FULL_MODEL)
        json_str = extract_json_from_string(raw_response)
        
        if not json_str:
            logging.error("No valid JSON object found in enhanced AI response")
            # Try AI-assisted JSON repair as a last resort
            try:
                logging.info("Attempting AI-assisted JSON repair for enhanced analysis...")
                repaired_json = await _ai_assisted_json_repair(raw_response)
                if repaired_json:
                    analysis_result = json.loads(repaired_json)
                    logging.info("AI-assisted JSON repair successful for enhanced analysis!")
                else:
                    raise ValueError("Enhanced AI repair failed")
            except Exception as repair_error:
                logging.warning(f"Enhanced AI-assisted JSON repair failed: {repair_error}")
                # Fallback to extracting meaningful summary
                fallback_summary = "Enhanced AI analysis completed but JSON parsing failed."
                if raw_response:
                    # Try to extract meaningful text from the response
                    lines = raw_response.strip().split('\n')
                    meaningful_lines = [line.strip() for line in lines if line.strip() and not line.strip().startswith('{') and not line.strip().startswith('}')]
                    if meaningful_lines:
                        fallback_summary = meaningful_lines[0][:200] + "..." if len(meaningful_lines[0]) > 200 else meaningful_lines[0]
                
                analysis_result = {
                    "overall_summary": fallback_summary,
                    "identified_issues": []
                }
        else:
            analysis_result = json.loads(json_str)
            
    except Exception as e:
        logging.error(f"Error during enhanced AI analysis: {e}")
        state.dashboard_data["summary"] = f"Enhanced AI analysis failed: {e}"
        await save_dashboard_data()
        return
    
    # Process results (same as original function)
    if not isinstance(analysis_result, dict):
        logging.error("Analysis result is not a dictionary")
        state.dashboard_data["summary"] = "Analysis result format error: expected dictionary"
        await save_dashboard_data()
        return
    
    if "overall_summary" not in analysis_result:
        state.dashboard_data["summary"] = "Analysis completed but missing summary field"
        await save_dashboard_data()
        return
    
    state.set_app_status("Processing enhanced analysis results...")
    state.dashboard_data["summary"] = analysis_result.get("overall_summary", "Enhanced analysis complete.")
    
    # Process new issues with entity context
    new_issues: List[Dict[str, Any]] = []
    identified_issues = analysis_result.get("identified_issues", [])
    if not isinstance(identified_issues, list):
        identified_issues = []
    
    # Add comprehensive analysis issues with proper categorization
    for issue in comprehensive_results["security_issues"]:
        issue["category"] = "security"
        identified_issues.append(issue)
    for issue in comprehensive_results["operational_issues"]:
        issue["category"] = "operational"
        identified_issues.append(issue)
    
    existing_signatures: set[str] = set()
    for existing_issue in state.dashboard_data["issues"]:
        existing_signatures.add(generate_issue_signature(existing_issue))
    
    for issue_data in identified_issues:
        try:
            required_fields = ["severity", "title", "summary", "recommendation"]
            if not all(field in issue_data for field in required_fields):
                continue
            
            # Ensure category field exists, default to security for backward compatibility
            if "category" not in issue_data:
                issue_data["category"] = "security"
            
            issue_signature = generate_issue_signature(issue_data)
            if issue_signature in existing_signatures:
                continue
            
            issue_id = hashlib.sha256(issue_data['title'].encode()).hexdigest()[:10]
            if issue_id in state.ignored_issue_ids:
                continue
            
            related_logs = issue_data.get('related_logs', [])
            cleaned_logs: List[str] = []
            for log_ref in related_logs:
                if isinstance(log_ref, str) and len(log_ref) >= 8:
                    cleaned_logs.append(log_ref)
                elif isinstance(log_ref, dict) and 'sha256' in log_ref:
                    cleaned_logs.append(log_ref['sha256'])
            
            issue_data['related_logs'] = cleaned_logs
            
            issue = {
                "id": issue_id,
                "timestamp": datetime.now().isoformat(),
                **issue_data
            }
            new_issues.append(issue)
            existing_signatures.add(issue_signature)
            
        except Exception as e:
            logging.error(f"Error processing enhanced issue: {e}, issue_data: {issue_data}")
            continue
    
    # Update dashboard with new issues
    existing_issue_ids = {i['id'] for i in state.dashboard_data["issues"]}
    truly_new_issues: List[Dict[str, Any]] = []
    
    for issue in new_issues:
        if issue['id'] not in existing_issue_ids:
            state.dashboard_data["issues"].insert(0, issue)
            truly_new_issues.append(issue)
    
    state.dashboard_data["issues"] = state.dashboard_data["issues"][:state.settings.get("max_issues", 1000)]
    state.dashboard_data["stats"]["anomalies"] = len(state.dashboard_data["issues"])
    
    await save_dashboard_data()
    logging.info(f"Enhanced AI analysis complete. Found {len(truly_new_issues)} new unique issues using NER.")