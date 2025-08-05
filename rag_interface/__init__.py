"""
RAG Interface Layer for Threat Hunter Pro.

This module provides the main interface between the web application and the 
underlying RAG capabilities, including search, summarization, relationship analysis,
trend detection, and explanation generation.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from ..config import DEFAULT_SETTINGS
from . import contracts
from .base import BaseRAGInterface
from .exceptions import RAGException, SearchException, SummarizationException

# Import existing modules to maintain compatibility
from .. import state
from ..vector_db import search_vector_db
from ..enhanced_retrieval import comprehensive_log_search
from ..ai_logic import call_gemini_api, PRO_MODEL, LITE_MODEL


class RAGInterface(BaseRAGInterface):
    """
    Main RAG Interface implementation that coordinates between different
    search strategies, summarization techniques, and analysis capabilities.
    
    This class serves as the primary integration point between the web layer
    and the underlying RAG capabilities while maintaining backward compatibility
    with existing functionality.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the RAG Interface with configuration.
        
        Args:
            config: Optional configuration dictionary. Uses DEFAULT_SETTINGS if not provided.
        """
        self.config = config or DEFAULT_SETTINGS.copy()
        self.logger = logging.getLogger(__name__)
        
        # Initialize components (will be enhanced as we implement them)
        self._agent_router = None
        self._agentic_search = None  
        self._hierarchical_summary = None
        self._security_pipeline = None
        
        # Initialize hierarchical summarizer if available
        self._init_hierarchical_summarizer()
        
        self.logger.info("RAG Interface initialized with configuration")
    
    async def retrieve(self, 
                      query: str, 
                      context: Dict[str, Any], 
                      filters: Optional[Dict[str, Any]] = None) -> contracts.RetrievalResult:
        """
        Execute intelligent hybrid search across all available data sources.
        
        This method coordinates different search strategies including vector search,
        keyword search, and potentially agentic search based on query characteristics.
        
        Args:
            query: The search query string
            context: Contextual information for the search (user, history, etc.)
            filters: Optional metadata filters (time range, severity, etc.)
            
        Returns:
            RetrievalResult containing ranked results with confidence scores
            
        Raises:
            SearchException: If search execution fails
        """
        try:
            self.logger.info(f"Executing retrieve for query: {query[:100]}...")
            
            # TODO: Implement agent router for strategy selection
            # For now, use existing comprehensive search
            max_results = self.config.get('search_k', 500)
            
            # Use existing comprehensive log search as baseline
            search_results = await comprehensive_log_search(query, max_results)
            
            # Convert to our contract format
            results = []
            for result in search_results.get('results', []):
                results.append(contracts.SearchResult(
                    id=result.get('metadata', {}).get('sha256', ''),
                    content=result.get('metadata', {}),
                    score=result.get('hybrid_score', result.get('semantic_score', 0.0)),
                    metadata={
                        'search_strategy': search_results.get('strategy', 'comprehensive'),
                        'source': 'vector_db'
                    }
                ))
            
            return contracts.RetrievalResult(
                results=results,
                total_count=len(results),
                query_analysis=contracts.QueryAnalysis(
                    original_query=query,
                    complexity=contracts.QueryComplexity.MODERATE,
                    entities=search_results.get('entities', []),
                    intent='search'
                ),
                execution_time_ms=search_results.get('execution_time_ms', 0),
                confidence_score=search_results.get('confidence', 0.8)
            )
            
        except Exception as e:
            self.logger.error(f"Retrieve operation failed: {e}")
            raise SearchException(f"Search failed: {e}")
    
    async def summarize(self, 
                       content: List[Dict[str, Any]], 
                       scope: str = "cluster") -> contracts.SummaryResult:
        """
        Generate hierarchical summaries at various granularities.
        
        Args:
            content: List of log entries or other content to summarize
            scope: Summary scope ("cluster", "daily", "weekly", "monthly", "quarterly")
            
        Returns:
            SummaryResult with generated summary and metadata
            
        Raises:
            SummarizationException: If summarization fails
        """
        try:
            self.logger.info(f"Generating {scope} summary for {len(content)} items")
            
            if not content:
                return contracts.SummaryResult(
                    summary="No content provided for summarization",
                    scope=scope,
                    item_count=0,
                    confidence_score=0.0,
                    metadata={}
                )
            
            # Use hierarchical summarizer if available and initialized
            if self._hierarchical_summary and await self._is_hierarchical_summarizer_ready():
                try:
                    result = await self._hierarchical_summary.generate_summary(content, scope)
                    return result
                except Exception as e:
                    self.logger.warning(f"Hierarchical summarizer failed, falling back to basic: {e}")
            
            # Fallback to existing AI logic for basic summarization
            content_text = self._prepare_content_for_summary(content, scope)
            
            # Generate summary using existing AI logic
            prompt = f"""Analyze and summarize the following security log data for a {scope} summary.
            
Content ({len(content)} items):
{content_text}

Provide a concise summary that highlights:
1. Key security events and patterns
2. Notable anomalies or threats detected  
3. System/user activity trends
4. Recommendations for investigation

Maximum 300 words."""

            summary_text = await call_gemini_api(prompt, model_name=LITE_MODEL)
            
            return contracts.SummaryResult(
                summary=summary_text,
                scope=scope,
                item_count=len(content),
                confidence_score=0.8,
                metadata={
                    'generation_method': 'ai_basic',
                    'model_used': LITE_MODEL,
                    'scope': scope
                }
            )
            
        except Exception as e:
            self.logger.error(f"Summarization failed: {e}")
            raise SummarizationException(f"Summary generation failed: {e}")
    
    async def relate(self, 
                    entities: List[str], 
                    timeframe: str = "24h") -> contracts.RelationshipResult:
        """
        Analyze relationships between security entities over time.
        
        Args:
            entities: List of entities to analyze (IPs, hosts, users, etc.)
            timeframe: Time window for analysis ("1h", "24h", "7d", etc.)
            
        Returns:
            RelationshipResult with relationship graph and analysis
        """
        try:
            self.logger.info(f"Analyzing relationships for {len(entities)} entities over {timeframe}")
            
            # TODO: Implement proper relationship analysis
            # For now, return basic structure
            
            relationships = []
            for i, entity1 in enumerate(entities):
                for j, entity2 in enumerate(entities[i+1:], i+1):
                    relationships.append(contracts.EntityRelationship(
                        source_entity=entity1,
                        target_entity=entity2,
                        relationship_type="co_occurrence",
                        strength=0.5,  # Placeholder
                        evidence_count=1,
                        temporal_pattern="concurrent"
                    ))
            
            return contracts.RelationshipResult(
                relationships=relationships,
                entity_count=len(entities),
                timeframe=timeframe,
                analysis_confidence=0.6,
                metadata={
                    'analysis_method': 'basic_cooccurrence',
                    'timeframe': timeframe
                }
            )
            
        except Exception as e:
            self.logger.error(f"Relationship analysis failed: {e}")
            raise RAGException(f"Relationship analysis failed: {e}")
    
    async def trend(self, 
                   patterns: List[str], 
                   period: str = "7d") -> contracts.TrendResult:
        """
        Identify trends and anomalies in security patterns.
        
        Args:
            patterns: List of patterns to analyze (alert types, behaviors, etc.)
            period: Analysis period ("1d", "7d", "30d", etc.)
            
        Returns:
            TrendResult with trend analysis and forecasting
        """
        try:
            self.logger.info(f"Analyzing trends for {len(patterns)} patterns over {period}")
            
            # TODO: Implement proper trend analysis
            # For now, return basic structure
            
            trends = []
            for pattern in patterns:
                trends.append(contracts.TrendAnalysis(
                    pattern=pattern,
                    direction="stable",  # "increasing", "decreasing", "stable"
                    confidence=0.7,
                    data_points=[],  # Placeholder
                    statistical_significance=0.05,
                    forecast=None
                ))
            
            return contracts.TrendResult(
                trends=trends,
                period=period,
                analysis_confidence=0.7,
                anomalies_detected=0,
                metadata={
                    'analysis_method': 'basic_trend',
                    'period': period
                }
            )
            
        except Exception as e:
            self.logger.error(f"Trend analysis failed: {e}")
            raise RAGException(f"Trend analysis failed: {e}")
    
    async def explain(self, 
                     findings: Dict[str, Any], 
                     evidence: List[Dict[str, Any]]) -> contracts.ExplanationResult:
        """
        Generate detailed explanations of security findings.
        
        Args:
            findings: Dictionary describing the findings to explain
            evidence: List of supporting evidence (logs, alerts, etc.)
            
        Returns:
            ExplanationResult with human-readable explanation and citations
        """
        try:
            self.logger.info(f"Generating explanation for findings with {len(evidence)} evidence items")
            
            # Prepare evidence for AI analysis
            evidence_text = self._prepare_evidence_for_explanation(evidence)
            findings_text = str(findings)
            
            # Generate explanation using existing AI logic
            prompt = f"""As a cybersecurity expert, provide a detailed explanation of the following security findings based on the available evidence.

Findings:
{findings_text}

Supporting Evidence ({len(evidence)} items):
{evidence_text}

Please provide:
1. A clear explanation of what these findings indicate
2. The security implications and potential risks
3. How the evidence supports these conclusions
4. Recommended next steps for investigation or remediation

Be thorough but accessible, citing specific evidence where relevant."""

            explanation_text = await call_gemini_api(prompt, model_name=PRO_MODEL)
            
            # Extract citations (basic implementation)
            citations = []
            for i, item in enumerate(evidence):
                if item.get('sha256'):
                    citations.append(contracts.EvidenceCitation(
                        evidence_id=item['sha256'],
                        relevance_score=0.8,  # Placeholder
                        excerpt=str(item)[:200] + "..." if len(str(item)) > 200 else str(item)
                    ))
            
            return contracts.ExplanationResult(
                explanation=explanation_text,
                citations=citations,
                confidence_score=0.8,
                reasoning_steps=[
                    "Analyzed security findings",
                    "Correlated with available evidence", 
                    "Generated comprehensive explanation"
                ],
                metadata={
                    'model_used': PRO_MODEL,
                    'evidence_count': len(evidence)
                }
            )
            
        except Exception as e:
            self.logger.error(f"Explanation generation failed: {e}")
            raise RAGException(f"Explanation generation failed: {e}")
    
    def _prepare_content_for_summary(self, content: List[Dict[str, Any]], scope: str) -> str:
        """Prepare content for summarization by extracting key fields."""
        content_items = []
        for item in content[:50]:  # Limit to avoid token limits
            # Extract key fields for summarization
            summary_item = {
                'timestamp': item.get('timestamp'),
                'rule_id': item.get('rule', {}).get('id'),
                'rule_description': item.get('rule', {}).get('description'),
                'agent': item.get('agent', {}).get('name'),
                'location': item.get('location'),
                'level': item.get('rule', {}).get('level')
            }
            content_items.append(str(summary_item))
        
        return '\n'.join(content_items)
    
    def _prepare_evidence_for_explanation(self, evidence: List[Dict[str, Any]]) -> str:
        """Prepare evidence for explanation generation."""
        evidence_items = []
        for item in evidence[:20]:  # Limit to avoid token limits
            # Extract key fields for explanation
            evidence_item = {
                'timestamp': item.get('timestamp'),
                'rule': item.get('rule', {}),
                'agent': item.get('agent', {}),
                'data': item.get('data', {}),
                'full_log': item.get('full_log', '')[:500]  # Truncate long logs
            }
            evidence_items.append(str(evidence_item))
        
        return '\n---\n'.join(evidence_items)
    
    def _init_hierarchical_summarizer(self):
        """Initialize hierarchical summarizer if available."""
        try:
            from ..hierarchical_summary import HierarchicalSummarizer, SummaryConfig
            
            # Initialize with default configuration
            config = SummaryConfig()
            self._hierarchical_summary = HierarchicalSummarizer(config)
            self.logger.info("Hierarchical summarizer initialized")
            
        except ImportError as e:
            self.logger.info("Hierarchical summarizer not available - using basic summarization")
            self._hierarchical_summary = None
        except Exception as e:
            self.logger.warning(f"Failed to initialize hierarchical summarizer: {e}")
            self._hierarchical_summary = None
    
    async def _is_hierarchical_summarizer_ready(self) -> bool:
        """Check if hierarchical summarizer is ready for use."""
        if not self._hierarchical_summary:
            return False
            
        try:
            # Check if it's initialized
            if not self._hierarchical_summary._initialized:
                await self._hierarchical_summary.initialize()
            return self._hierarchical_summary._initialized
        except Exception as e:
            self.logger.warning(f"Hierarchical summarizer not ready: {e}")
            return False
    
    async def get_hierarchical_summary_status(self) -> Dict[str, Any]:
        """Get status of hierarchical summarization system."""
        if not self._hierarchical_summary:
            return {"available": False, "reason": "Not initialized"}
            
        try:
            if await self._is_hierarchical_summarizer_ready():
                return await self._hierarchical_summary.get_system_status()
            else:
                return {"available": False, "reason": "Not ready"}
        except Exception as e:
            return {"available": False, "reason": str(e)}
    
    async def run_nightly_summarization(self, target_date: Optional[str] = None) -> Dict[str, Any]:
        """Run nightly summarization process."""
        if not self._hierarchical_summary:
            return {"success": False, "error": "Hierarchical summarizer not available"}
            
        try:
            if not await self._is_hierarchical_summarizer_ready():
                return {"success": False, "error": "Hierarchical summarizer not ready"}
                
            from datetime import date, datetime
            
            # Parse target date if provided
            if target_date:
                try:
                    parsed_date = datetime.fromisoformat(target_date).date()
                except ValueError:
                    return {"success": False, "error": f"Invalid date format: {target_date}"}
            else:
                parsed_date = None
                
            return await self._hierarchical_summary.run_nightly_summarization(parsed_date)
            
        except Exception as e:
            self.logger.error(f"Nightly summarization failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def query_hierarchical_summaries(self, query: str, level: Optional[str] = None,
                                         start_date: Optional[str] = None,
                                         end_date: Optional[str] = None,
                                         limit: int = 50) -> Dict[str, Any]:
        """Query hierarchical summaries."""
        if not self._hierarchical_summary:
            return {"summaries": [], "error": "Hierarchical summarizer not available"}
            
        try:
            if not await self._is_hierarchical_summarizer_ready():
                return {"summaries": [], "error": "Hierarchical summarizer not ready"}
                
            from ..hierarchical_summary.models import SummaryLevel
            from datetime import datetime
            
            # Parse parameters
            summary_level = None
            if level:
                try:
                    summary_level = SummaryLevel(level.lower())
                except ValueError:
                    return {"summaries": [], "error": f"Invalid summary level: {level}"}
            
            parsed_start_date = None
            if start_date:
                try:
                    parsed_start_date = datetime.fromisoformat(start_date)
                except ValueError:
                    return {"summaries": [], "error": f"Invalid start date format: {start_date}"}
            
            parsed_end_date = None
            if end_date:
                try:
                    parsed_end_date = datetime.fromisoformat(end_date)
                except ValueError:
                    return {"summaries": [], "error": f"Invalid end date format: {end_date}"}
            
            # Execute query
            response = await self._hierarchical_summary.query_summaries(
                query, summary_level, parsed_start_date, parsed_end_date, limit
            )
            
            # Convert response to dict format
            return {
                "summaries": [self._summary_to_dict(s) for s in response.summaries],
                "total_count": response.total_count,
                "query_time_ms": response.query_time_ms,
                "cache_hit": response.cache_hit
            }
            
        except Exception as e:
            self.logger.error(f"Hierarchical summary query failed: {e}")
            return {"summaries": [], "error": str(e)}
    
    def _summary_to_dict(self, summary) -> Dict[str, Any]:
        """Convert summary object to dictionary for API response."""
        try:
            summary_dict = summary.dict()
            # Ensure datetime objects are serializable
            if 'metadata' in summary_dict:
                metadata = summary_dict['metadata']
                for key, value in metadata.items():
                    if hasattr(value, 'isoformat'):
                        metadata[key] = value.isoformat()
            return summary_dict
        except Exception as e:
            self.logger.warning(f"Failed to convert summary to dict: {e}")
            return {"error": str(e)}


# Export the main interface
__all__ = ['RAGInterface', 'contracts']