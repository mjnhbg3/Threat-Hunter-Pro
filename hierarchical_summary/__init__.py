"""
Hierarchical Summarization System for Threat Hunter Pro.

This module provides comprehensive multi-level summarization capabilities that support
efficient querying at different time granularities while dramatically reducing token
usage through intelligent clustering and progressive summarization.

Key Features:
- Multi-level summary hierarchy (cluster -> daily -> weekly -> monthly -> quarterly)
- Intelligent log clustering based on semantic similarity and temporal proximity
- Progressive summarization that builds insights at each level
- Efficient storage with time-partitioned indexing
- Seamless integration with existing RAG interface
- Automated nightly processing with dependency management
- Performance optimization through caching and parallel processing

Architecture:
- HierarchicalSummarizer: Main orchestrator class
- ClusterSummarizer: Handles log clustering and cluster-level summaries
- TemporalAggregator: Manages time-based summary aggregation
- SummaryStorage: Provides efficient storage and retrieval
- NightlyJobs: Background job management and scheduling

Usage:
    from hierarchical_summary import HierarchicalSummarizer
    
    summarizer = HierarchicalSummarizer()
    await summarizer.initialize()
    
    # Generate cluster summary
    cluster_summary = await summarizer.summarize_cluster(logs)
    
    # Generate daily summary 
    daily_summary = await summarizer.summarize_daily(date_range)
    
    # Query summaries
    results = await summarizer.query_summaries("Show me this week's security trends")
"""

from .models import (
    ClusterSummary,
    DailySummary, 
    WeeklySummary,
    MonthlySummary,
    QuarterlySummary,
    SummaryMetadata,
    SummaryLevel,
    EntityActivity,
    SecurityTrend,
    SummaryConfig
)

from .hierarchical_summarizer import HierarchicalSummarizer
from .cluster_summarizer import ClusterSummarizer
from .temporal_aggregator import TemporalAggregator
from .summary_storage import SummaryStorage
from .nightly_jobs import NightlyJobScheduler

__version__ = "1.0.0"
__all__ = [
    "HierarchicalSummarizer",
    "ClusterSummarizer", 
    "TemporalAggregator",
    "SummaryStorage",
    "NightlyJobScheduler",
    "ClusterSummary",
    "DailySummary",
    "WeeklySummary", 
    "MonthlySummary",
    "QuarterlySummary",
    "SummaryMetadata",
    "SummaryLevel",
    "EntityActivity",
    "SecurityTrend",
    "SummaryConfig"
]