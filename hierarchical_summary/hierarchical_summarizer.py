"""
Main hierarchical summarizer implementation.

This module provides the primary interface for the hierarchical summarization system,
integrating all components and providing seamless integration with the existing
RAG interface. It serves as the main orchestrator for summary generation,
querying, and management operations.
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional, Union
from datetime import datetime, date, timedelta
import json

from ..rag_interface.contracts import SummaryResult, RetrievalResult
from ..rag_interface.base import BaseSummarizer
from ..state import embedding_model
from .models import (
    AnySummary, ClusterSummary, DailySummary, WeeklySummary, MonthlySummary, QuarterlySummary,
    SummaryLevel, SummaryConfig, SummaryQuery, SummaryResponse, SummaryMetadata
)
from .cluster_summarizer import ClusterSummarizer
from .temporal_aggregator import TemporalAggregator
from .summary_storage import SummaryStorage
from .nightly_jobs import NightlyJobScheduler

logger = logging.getLogger(__name__)


class HierarchicalSummarizer(BaseSummarizer):
    """
    Main hierarchical summarization system.
    
    This class provides the primary interface for:
    - On-demand summarization of log clusters
    - Querying existing summaries at different levels
    - Integration with RAG interface
    - Background job management
    - Performance optimization through caching
    """
    
    def __init__(self, config: Optional[SummaryConfig] = None):
        self.config = config or SummaryConfig()
        
        # Core components
        self.cluster_summarizer: Optional[ClusterSummarizer] = None
        self.temporal_aggregator: Optional[TemporalAggregator] = None
        self.storage: Optional[SummaryStorage] = None
        self.job_scheduler: Optional[NightlyJobScheduler] = None
        
        # State tracking
        self._initialized = False
        self._summary_cache: Dict[str, AnySummary] = {}
        self._query_cache: Dict[str, SummaryResponse] = {}
        
        # Performance metrics
        self.performance_metrics = {
            'summaries_generated': 0,
            'queries_executed': 0,
            'cache_hits': 0,
            'avg_generation_time_ms': 0.0,
            'avg_query_time_ms': 0.0,
            'token_reduction_ratio': 0.0
        }
        
    async def initialize(self):
        """Initialize the hierarchical summarization system."""
        if self._initialized:
            return
            
        logger.info("Initializing HierarchicalSummarizer...")
        
        try:
            # Initialize core components
            self.cluster_summarizer = ClusterSummarizer(self.config)
            await self.cluster_summarizer.initialize(embedding_model)
            
            self.temporal_aggregator = TemporalAggregator(self.config)
            await self.temporal_aggregator.initialize()
            
            self.storage = SummaryStorage(self.config)
            await self.storage.initialize()
            
            # Initialize job scheduler
            self.job_scheduler = NightlyJobScheduler(self.config)
            await self.job_scheduler.initialize(embedding_model)
            
            self._initialized = True
            logger.info("HierarchicalSummarizer initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize HierarchicalSummarizer: {e}")
            raise
            
    async def generate_cluster_summary(self, content: List[Dict[str, Any]]) -> SummaryResult:
        """
        Generate a summary for a cluster of related logs.
        
        Args:
            content: List of log entries to cluster and summarize
            
        Returns:
            SummaryResult with generated cluster summary
        """
        if not self._initialized:
            await self.initialize()
            
        start_time = datetime.utcnow()
        
        try:
            # Cluster the logs
            clusters = await self.cluster_summarizer.cluster_logs(content)
            
            if not clusters:
                return SummaryResult(
                    summary="No clusters could be formed from the provided content.",
                    scope="cluster",
                    item_count=len(content),
                    confidence_score=0.0,
                    key_insights=["Insufficient data for clustering"],
                    generation_time_ms=0
                )
                
            # For simplicity, summarize the largest cluster
            largest_cluster = max(clusters, key=lambda c: len(c.logs))
            cluster_summary = await self.cluster_summarizer.summarize_cluster(largest_cluster)
            
            # Store the summary
            await self.storage.store_summary(cluster_summary)
            
            # Update performance metrics
            generation_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            self._update_generation_metrics(generation_time)
            
            return SummaryResult(
                summary=cluster_summary.summary_text,
                scope="cluster",
                item_count=len(content),
                confidence_score=cluster_summary.cluster_coherence,
                key_insights=cluster_summary.key_insights,
                generation_time_ms=generation_time,
                metadata={
                    "cluster_id": cluster_summary.cluster_id,
                    "risk_assessment": cluster_summary.risk_assessment,
                    "security_patterns": len(cluster_summary.security_patterns),
                    "entity_activities": len(cluster_summary.entity_activities)
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to generate cluster summary: {e}")
            return SummaryResult(
                summary=f"Failed to generate cluster summary: {str(e)}",
                scope="cluster",
                item_count=len(content),
                confidence_score=0.0,
                generation_time_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000)
            )
            
    async def aggregate_summaries(self, summaries: List[SummaryResult], 
                                target_scope: str) -> SummaryResult:
        """
        Aggregate multiple summaries into a higher-level summary.
        
        Args:
            summaries: List of summaries to aggregate
            target_scope: Target scope for aggregation (daily, weekly, monthly, quarterly)
            
        Returns:
            Aggregated SummaryResult
        """
        if not self._initialized:
            await self.initialize()
            
        start_time = datetime.utcnow()
        
        try:
            # Convert SummaryResults to actual summary objects if needed
            # This is a simplified implementation - in practice you'd need more sophisticated conversion
            
            if target_scope == "daily":
                # For daily aggregation, we need cluster summaries
                # This is a placeholder implementation
                daily_summary = await self.temporal_aggregator.aggregate_to_daily([], date.today())
                
                return SummaryResult(
                    summary=daily_summary.executive_summary,
                    scope="daily",
                    item_count=len(summaries),
                    confidence_score=daily_summary.metadata.quality_score,
                    key_insights=daily_summary.key_findings,
                    generation_time_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000),
                    metadata={
                        "incident_count": daily_summary.incident_count,
                        "alert_volume": daily_summary.alert_volume,
                        "top_entities": len(daily_summary.top_entities)
                    }
                )
                
            else:
                # Generic aggregation fallback
                combined_summary = await self._combine_summaries(summaries)
                
                return SummaryResult(
                    summary=combined_summary,
                    scope=target_scope,
                    item_count=len(summaries),
                    confidence_score=0.8,  # Default confidence
                    key_insights=[f"Aggregated {len(summaries)} summaries"],
                    generation_time_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000)
                )
                
        except Exception as e:
            logger.error(f"Failed to aggregate summaries: {e}")
            return SummaryResult(
                summary=f"Failed to aggregate summaries: {str(e)}",
                scope=target_scope,
                item_count=len(summaries),
                confidence_score=0.0,
                generation_time_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000)
            )
            
    async def query_summaries(self, query: str, level: Optional[SummaryLevel] = None,
                            start_date: Optional[datetime] = None,
                            end_date: Optional[datetime] = None,
                            limit: int = 50) -> SummaryResponse:
        """
        Query summaries with natural language and filters.
        
        Args:
            query: Natural language query
            level: Optional summary level filter
            start_date: Optional start date filter
            end_date: Optional end date filter
            limit: Maximum number of results
            
        Returns:
            SummaryResponse with matching summaries
        """
        if not self._initialized:
            await self.initialize()
            
        start_time = datetime.utcnow()
        
        try:
            # Create query object
            summary_query = SummaryQuery(
                level=level,
                start_date=start_date,
                end_date=end_date,
                limit=limit
            )
            
            # Check cache first
            cache_key = self._generate_query_cache_key(summary_query, query)
            if cache_key in self._query_cache:
                self.performance_metrics['cache_hits'] += 1
                cached_response = self._query_cache[cache_key]
                cached_response.cache_hit = True
                return cached_response
                
            # Execute query
            response = await self.storage.query_summaries(summary_query)
            
            # Apply natural language filtering if query provided
            if query and response.summaries:
                filtered_summaries = await self._filter_summaries_by_query(
                    response.summaries, query
                )
                response.summaries = filtered_summaries
                response.total_count = len(filtered_summaries)
                
            # Update performance metrics
            query_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            response.query_time_ms = query_time
            self._update_query_metrics(query_time)
            
            # Cache the response
            if self.config.redis_caching:
                self._query_cache[cache_key] = response
                
            return response
            
        except Exception as e:
            logger.error(f"Failed to query summaries: {e}")
            return SummaryResponse(
                summaries=[],
                total_count=0,
                query_time_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000)
            )
            
    async def get_summary_by_id(self, summary_id: str) -> Optional[AnySummary]:
        """
        Get a specific summary by ID.
        
        Args:
            summary_id: The summary ID to retrieve
            
        Returns:
            The summary object or None if not found
        """
        if not self._initialized:
            await self.initialize()
            
        # Check cache first
        if summary_id in self._summary_cache:
            return self._summary_cache[summary_id]
            
        # Retrieve from storage
        summary = await self.storage.retrieve_summary(summary_id)
        
        # Cache the result
        if summary:
            self._summary_cache[summary_id] = summary
            
        return summary
        
    async def get_time_range_summaries(self, level: SummaryLevel,
                                     start_date: datetime,
                                     end_date: datetime) -> List[AnySummary]:
        """
        Get all summaries of a specific level within a time range.
        
        Args:
            level: Summary level to filter by
            start_date: Start of time range
            end_date: End of time range
            
        Returns:
            List of summaries in the time range
        """
        if not self._initialized:
            await self.initialize()
            
        return await self.storage.get_summaries_by_time_range(level, start_date, end_date)
        
    async def run_nightly_summarization(self, target_date: Optional[date] = None) -> Dict[str, Any]:
        """
        Run the complete nightly summarization pipeline.
        
        Args:
            target_date: Optional target date (defaults to yesterday)
            
        Returns:
            Dict with execution results and statistics
        """
        if not self._initialized:
            await self.initialize()
            
        return await self.job_scheduler.run_nightly_summarization(target_date)
        
    async def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status and metrics."""
        if not self._initialized:
            return {"status": "not_initialized"}
            
        try:
            # Get storage stats
            storage_stats = await self.storage.get_storage_stats()
            
            # Get job status
            job_status = await self.job_scheduler.get_job_status()
            
            # Calculate token reduction estimate
            total_summaries = storage_stats.total_summaries
            estimated_original_tokens = total_summaries * 1000  # Rough estimate
            actual_summary_tokens = sum(self.performance_metrics.values()) if total_summaries > 0 else 1
            token_reduction = 1.0 - (actual_summary_tokens / max(estimated_original_tokens, 1))
            
            return {
                "status": "initialized",
                "initialized": self._initialized,
                "storage_stats": {
                    "total_summaries": storage_stats.total_summaries,
                    "storage_size_mb": storage_stats.storage_size_bytes / (1024 * 1024),
                    "compression_ratio": storage_stats.compression_ratio,
                    "cache_hit_rate": storage_stats.cache_hit_rate,
                    "by_level": storage_stats.by_level
                },
                "performance_metrics": {
                    **self.performance_metrics,
                    "estimated_token_reduction": token_reduction
                },
                "job_scheduler": job_status,
                "config": {
                    "clustering_algorithm": self.config.clustering_algorithm,
                    "summary_model": self.config.summary_model,
                    "compression_enabled": self.config.compression_enabled,
                    "redis_caching": self.config.redis_caching,
                    "parallel_processing": self.config.parallel_processing
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get system status: {e}")
            return {
                "status": "error",
                "error": str(e),
                "initialized": self._initialized
            }
            
    async def optimize_performance(self) -> Dict[str, Any]:
        """Run performance optimization tasks."""
        if not self._initialized:
            await self.initialize()
            
        optimization_results = {}
        
        try:
            # Clear expired cache entries
            cache_cleared = await self._clear_expired_cache()
            optimization_results["cache_cleared"] = cache_cleared
            
            # Run storage cleanup
            cleanup_count = await self.storage.cleanup_expired_summaries()
            optimization_results["summaries_cleaned"] = cleanup_count
            
            # Optimize database (placeholder)
            optimization_results["database_optimized"] = True
            
            logger.info(f"Performance optimization completed: {optimization_results}")
            return optimization_results
            
        except Exception as e:
            logger.error(f"Performance optimization failed: {e}")
            return {"error": str(e)}
            
    # RAG Interface Implementation
    
    async def generate_summary(self, content: List[Dict[str, Any]], 
                             scope: str = "cluster") -> SummaryResult:
        """
        Implementation of BaseSummarizer.generate_summary.
        
        This method provides the interface for the RAG system to generate
        summaries at different scopes.
        """
        if scope == "cluster":
            return await self.generate_cluster_summary(content)
        else:
            # For other scopes, we'd need existing summaries to aggregate
            # This is a simplified implementation
            return SummaryResult(
                summary=f"Summary scope '{scope}' requires aggregation of existing summaries.",
                scope=scope,
                item_count=len(content),
                confidence_score=0.5,
                key_insights=["Aggregation required"],
                generation_time_ms=0
            )
            
    async def aggregate_summaries_interface(self, summaries: List[SummaryResult], 
                                          target_scope: str) -> SummaryResult:
        """Implementation of BaseSummarizer.aggregate_summaries."""
        return await self.aggregate_summaries(summaries, target_scope)
        
    # Private helper methods
    
    async def _combine_summaries(self, summaries: List[SummaryResult]) -> str:
        """Combine multiple summary results into a single summary."""
        if not summaries:
            return "No summaries to combine."
            
        # Extract key information from summaries
        combined_insights = []
        total_items = 0
        
        for summary in summaries:
            combined_insights.extend(summary.key_insights)
            total_items += summary.item_count
            
        # Create combined summary
        unique_insights = list(set(combined_insights))
        
        summary_text = f"Combined analysis of {len(summaries)} summaries covering {total_items} items. "
        summary_text += f"Key insights: {'; '.join(unique_insights[:5])}."
        
        return summary_text
        
    async def _filter_summaries_by_query(self, summaries: List[AnySummary], 
                                       query: str) -> List[AnySummary]:
        """Filter summaries based on natural language query."""
        # This is a simplified implementation
        # In practice, you'd use more sophisticated NLP/embedding matching
        
        query_lower = query.lower()
        filtered_summaries = []
        
        for summary in summaries:
            # Check if query terms appear in summary text
            if hasattr(summary, 'summary_text'):
                summary_text = summary.summary_text.lower()
            elif hasattr(summary, 'executive_summary'):
                summary_text = summary.executive_summary.lower()
            else:
                continue
                
            # Simple keyword matching
            if any(term in summary_text for term in query_lower.split()):
                filtered_summaries.append(summary)
                
        return filtered_summaries
        
    def _generate_query_cache_key(self, query: SummaryQuery, text_query: str) -> str:
        """Generate a cache key for query results."""
        key_components = [
            str(query.level) if query.level else "all",
            query.start_date.isoformat() if query.start_date else "no_start",
            query.end_date.isoformat() if query.end_date else "no_end",
            str(query.limit),
            text_query or "no_query"
        ]
        return "|".join(key_components)
        
    def _update_generation_metrics(self, generation_time_ms: int):
        """Update summary generation performance metrics."""
        self.performance_metrics['summaries_generated'] += 1
        
        # Update average generation time
        count = self.performance_metrics['summaries_generated']
        current_avg = self.performance_metrics['avg_generation_time_ms']
        self.performance_metrics['avg_generation_time_ms'] = (
            (current_avg * (count - 1) + generation_time_ms) / count
        )
        
    def _update_query_metrics(self, query_time_ms: int):
        """Update query performance metrics."""
        self.performance_metrics['queries_executed'] += 1
        
        # Update average query time
        count = self.performance_metrics['queries_executed']
        current_avg = self.performance_metrics['avg_query_time_ms']
        self.performance_metrics['avg_query_time_ms'] = (
            (current_avg * (count - 1) + query_time_ms) / count
        )
        
    async def _clear_expired_cache(self) -> int:
        """Clear expired cache entries."""
        # Simple cache clearing - in practice you'd implement TTL-based expiration
        cache_size_before = len(self._summary_cache) + len(self._query_cache)
        
        # Clear if cache is getting too large
        if len(self._summary_cache) > 1000:
            # Keep only recent entries
            self._summary_cache.clear()
            
        if len(self._query_cache) > 100:
            self._query_cache.clear()
            
        cache_size_after = len(self._summary_cache) + len(self._query_cache)
        return cache_size_before - cache_size_after
        
    async def shutdown(self):
        """Gracefully shutdown the hierarchical summarizer."""
        logger.info("Shutting down HierarchicalSummarizer...")
        
        if self.job_scheduler:
            await self.job_scheduler.shutdown()
            
        # Clear caches
        self._summary_cache.clear()
        self._query_cache.clear()
        
        self._initialized = False
        logger.info("HierarchicalSummarizer shutdown complete")