"""
Abstract base classes for RAG components.

This module provides the foundational abstract classes that define the
interface contracts for all RAG components.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional

from .contracts import (
    RetrievalResult, SummaryResult, RelationshipResult, 
    TrendResult, ExplanationResult
)


class BaseRAGInterface(ABC):
    """
    Abstract base class for RAG Interface implementations.
    
    This class defines the contract that all RAG interfaces must implement,
    ensuring consistent behavior across different implementations.
    """
    
    @abstractmethod
    async def retrieve(self, 
                      query: str, 
                      context: Dict[str, Any], 
                      filters: Optional[Dict[str, Any]] = None) -> RetrievalResult:
        """
        Execute intelligent hybrid search across all available data sources.
        
        Args:
            query: The search query string
            context: Contextual information for the search
            filters: Optional metadata filters
            
        Returns:
            RetrievalResult containing ranked results with confidence scores
        """
        pass
    
    @abstractmethod
    async def summarize(self, 
                       content: List[Dict[str, Any]], 
                       scope: str = "cluster") -> SummaryResult:
        """
        Generate hierarchical summaries at various granularities.
        
        Args:
            content: List of log entries or other content to summarize
            scope: Summary scope (cluster, daily, weekly, monthly, quarterly)
            
        Returns:
            SummaryResult with generated summary and metadata
        """
        pass
    
    @abstractmethod
    async def relate(self, 
                    entities: List[str], 
                    timeframe: str = "24h") -> RelationshipResult:
        """
        Analyze relationships between security entities over time.
        
        Args:
            entities: List of entities to analyze
            timeframe: Time window for analysis
            
        Returns:
            RelationshipResult with relationship graph and analysis
        """
        pass
    
    @abstractmethod
    async def trend(self, 
                   patterns: List[str], 
                   period: str = "7d") -> TrendResult:
        """
        Identify trends and anomalies in security patterns.
        
        Args:
            patterns: List of patterns to analyze
            period: Analysis period
            
        Returns:
            TrendResult with trend analysis and forecasting
        """
        pass
    
    @abstractmethod
    async def explain(self, 
                     findings: Dict[str, Any], 
                     evidence: List[Dict[str, Any]]) -> ExplanationResult:
        """
        Generate detailed explanations of security findings.
        
        Args:
            findings: Dictionary describing the findings to explain
            evidence: List of supporting evidence
            
        Returns:
            ExplanationResult with human-readable explanation and citations
        """
        pass


class BaseAgentRouter(ABC):
    """
    Abstract base class for Agent Router implementations.
    
    The agent router is responsible for analyzing queries and selecting
    the optimal search strategy based on query characteristics.
    """
    
    @abstractmethod
    async def analyze_query(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a query to determine its characteristics and complexity.
        
        Args:
            query: The query string to analyze
            context: Additional context information
            
        Returns:
            Dictionary containing query analysis results
        """
        pass
    
    @abstractmethod
    async def select_strategy(self, query_analysis: Dict[str, Any]) -> str:
        """
        Select the optimal search strategy based on query analysis.
        
        Args:
            query_analysis: Results from query analysis
            
        Returns:
            String identifier for the selected strategy
        """
        pass
    
    @abstractmethod
    async def route_request(self, query: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Complete routing decision including analysis and strategy selection.
        
        Args:
            query: The query string to route
            context: Additional context information
            
        Returns:
            Dictionary containing routing decision and metadata
        """
        pass


class BaseSearchEngine(ABC):
    """
    Abstract base class for search engine implementations.
    
    Search engines handle the actual execution of search operations
    using various strategies and data sources.
    """
    
    @abstractmethod
    async def execute_search(self, 
                           query: str, 
                           strategy: str, 
                           context: Dict[str, Any]) -> RetrievalResult:
        """
        Execute a search using the specified strategy.
        
        Args:
            query: The search query
            strategy: The search strategy to use
            context: Additional context information
            
        Returns:
            RetrievalResult with search results and metadata
        """
        pass
    
    @abstractmethod
    async def refine_search(self, 
                          original_query: str, 
                          previous_results: List[Dict[str, Any]], 
                          context: Dict[str, Any]) -> str:
        """
        Refine a search query based on previous results.
        
        Args:
            original_query: The original search query
            previous_results: Results from previous search iterations
            context: Additional context information
            
        Returns:
            Refined query string
        """
        pass


class BaseSummarizer(ABC):
    """
    Abstract base class for summarization implementations.
    
    Summarizers handle the generation of hierarchical summaries
    at different granularities and time scales.
    """
    
    @abstractmethod
    async def generate_cluster_summary(self, logs: List[Dict[str, Any]]) -> SummaryResult:
        """
        Generate a summary for a cluster of related logs.
        
        Args:
            logs: List of log entries to summarize
            
        Returns:
            SummaryResult with cluster summary
        """
        pass
    
    @abstractmethod
    async def aggregate_summaries(self, 
                                summaries: List[SummaryResult], 
                                target_scope: str) -> SummaryResult:
        """
        Aggregate multiple summaries into a higher-level summary.
        
        Args:
            summaries: List of summaries to aggregate
            target_scope: Target scope for aggregation
            
        Returns:
            Aggregated SummaryResult
        """
        pass


class BaseSecurityPipeline(ABC):
    """
    Abstract base class for security pipeline implementations.
    
    Security pipelines handle PII detection, redaction, and
    security-aware processing of log data.
    """
    
    @abstractmethod
    async def detect_pii(self, content: str) -> Dict[str, Any]:
        """
        Detect personally identifiable information in content.
        
        Args:
            content: Content to analyze for PII
            
        Returns:
            Dictionary containing PII detection results
        """
        pass
    
    @abstractmethod
    async def redact_content(self, content: str, pii_results: Dict[str, Any]) -> str:
        """
        Redact PII from content based on detection results.
        
        Args:
            content: Original content
            pii_results: Results from PII detection
            
        Returns:
            Redacted content string
        """
        pass
    
    @abstractmethod
    async def preserve_security_entities(self, content: str) -> Dict[str, Any]:
        """
        Identify and preserve security-relevant entities during redaction.
        
        Args:
            content: Content to analyze
            
        Returns:
            Dictionary containing security entities to preserve
        """
        pass


class BaseObservabilityCollector(ABC):
    """
    Abstract base class for observability and metrics collection.
    
    Observability collectors handle metrics, tracing, and performance
    monitoring across RAG operations.
    """
    
    @abstractmethod
    async def start_trace(self, operation: str, context: Dict[str, Any]) -> str:
        """
        Start a new trace for an operation.
        
        Args:
            operation: Name of the operation being traced
            context: Additional context information
            
        Returns:
            Trace ID for the started trace
        """
        pass
    
    @abstractmethod
    async def end_trace(self, trace_id: str, results: Dict[str, Any]) -> None:
        """
        End a trace and record results.
        
        Args:
            trace_id: ID of the trace to end
            results: Results and metadata from the operation
        """
        pass
    
    @abstractmethod
    async def record_metric(self, metric_name: str, value: float, tags: Dict[str, str] = None) -> None:
        """
        Record a metric value with optional tags.
        
        Args:
            metric_name: Name of the metric
            value: Metric value to record
            tags: Optional tags for the metric
        """
        pass
    
    @abstractmethod
    async def get_metrics_summary(self) -> Dict[str, Any]:
        """
        Get a summary of collected metrics.
        
        Returns:
            Dictionary containing metrics summary
        """
        pass