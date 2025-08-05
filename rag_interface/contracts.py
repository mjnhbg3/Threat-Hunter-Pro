"""
Type definitions and contracts for the RAG system.

This module provides comprehensive type hints, protocols, and data structures 
that define the expected behavior and interfaces across the RAG pipeline.
"""
from typing import Protocol, List, Dict, Any, Optional, Union
from enum import Enum, auto
from dataclasses import dataclass
from datetime import datetime
from pydantic import BaseModel, Field


class QueryComplexity(Enum):
    """Enumeration of query complexity levels for routing decisions."""
    SIMPLE = auto()
    MODERATE = auto()
    COMPLEX = auto()
    EXPERT = auto()


class SearchStrategy(Enum):
    """Available search strategies for different query types."""
    VECTOR_SEARCH = "vector_search"
    HYBRID_SEARCH = "hybrid_search"
    ENTITY_FOCUSED = "entity_focused"
    AGENTIC_SEARCH = "agentic_search"
    HOT_STORE = "hot_store"
    COMPREHENSIVE = "comprehensive"


# Data Models using Pydantic for validation
class QueryAnalysis(BaseModel):
    """Analysis of a user query including complexity and extracted entities."""
    original_query: str
    complexity: QueryComplexity
    entities: List[str] = Field(default_factory=list)
    intent: str = "search"
    keywords: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)


class SearchResult(BaseModel):
    """Individual search result with content and metadata."""
    id: str
    content: Dict[str, Any]
    score: float = Field(ge=0.0, le=1.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class RetrievalResult(BaseModel):
    """Complete result of a retrieval operation."""
    results: List[SearchResult]
    total_count: int
    query_analysis: QueryAnalysis
    execution_time_ms: int = 0
    confidence_score: float = Field(ge=0.0, le=1.0, default=0.8)
    strategy_used: SearchStrategy = SearchStrategy.COMPREHENSIVE
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SummaryResult(BaseModel):
    """Result of a summarization operation."""
    summary: str
    scope: str = "cluster"  # cluster, daily, weekly, monthly, quarterly
    item_count: int
    confidence_score: float = Field(ge=0.0, le=1.0)
    key_insights: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    generation_time_ms: int = 0


class EntityRelationship(BaseModel):
    """Relationship between two security entities."""
    source_entity: str
    target_entity: str
    relationship_type: str  # co_occurrence, communication, shared_events, etc.
    strength: float = Field(ge=0.0, le=1.0)
    evidence_count: int = 0
    temporal_pattern: str = "concurrent"  # concurrent, sequential, periodic
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RelationshipResult(BaseModel):
    """Result of entity relationship analysis."""
    relationships: List[EntityRelationship]
    entity_count: int
    timeframe: str
    analysis_confidence: float = Field(ge=0.0, le=1.0)
    graph_metrics: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TrendAnalysis(BaseModel):
    """Analysis of a specific trend pattern."""
    pattern: str
    direction: str  # increasing, decreasing, stable, volatile
    confidence: float = Field(ge=0.0, le=1.0)
    data_points: List[Dict[str, Any]] = Field(default_factory=list)
    statistical_significance: float = Field(ge=0.0, le=1.0, default=0.05)
    forecast: Optional[Dict[str, Any]] = None


class TrendResult(BaseModel):
    """Result of trend analysis."""
    trends: List[TrendAnalysis]
    period: str
    analysis_confidence: float = Field(ge=0.0, le=1.0)
    anomalies_detected: int = 0
    seasonal_patterns: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EvidenceCitation(BaseModel):
    """Citation of evidence supporting an explanation."""
    evidence_id: str
    relevance_score: float = Field(ge=0.0, le=1.0)
    excerpt: str
    source_type: str = "log"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ExplanationResult(BaseModel):
    """Result of explanation generation."""
    explanation: str
    citations: List[EvidenceCitation] = Field(default_factory=list)
    confidence_score: float = Field(ge=0.0, le=1.0)
    reasoning_steps: List[str] = Field(default_factory=list)
    alternative_explanations: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# Search trace and performance tracking
@dataclass
class SearchTrace:
    """Detailed trace of a search operation for observability."""
    query_id: str
    original_query: str
    refined_queries: List[str]
    search_steps: List[Dict[str, Any]]
    total_tokens_used: int
    total_time_ms: float
    complexity: QueryComplexity
    strategy_used: SearchStrategy
    confidence_score: float


@dataclass
class SecurityContext:
    """Security and privacy context for RAG operations."""
    pii_detected: bool = False
    pii_entities: List[str] = None
    redaction_applied: bool = False
    security_score: float = 1.0  # 1.0 is fully secure
    audit_trail: List[str] = None

    def __post_init__(self):
        if self.pii_entities is None:
            self.pii_entities = []
        if self.audit_trail is None:
            self.audit_trail = []


# Protocols for component interfaces
class SearchEngineProtocol(Protocol):
    """Protocol defining the core search engine interface."""
    
    async def execute_search(self, query: str, context: Dict[str, Any]) -> RetrievalResult:
        """Execute a search operation based on the given query."""
        ...
    
    async def refine_query(self, query: str, previous_results: List[SearchResult]) -> str:
        """Refine and improve the original search query based on previous results."""
        ...


class SummarizerProtocol(Protocol):
    """Protocol for summarization engines."""
    
    async def generate_summary(self, content: List[Dict[str, Any]], scope: str) -> SummaryResult:
        """Generate a summary for the given content at the specified scope."""
        ...
    
    async def aggregate_summaries(self, summaries: List[SummaryResult], target_scope: str) -> SummaryResult:
        """Aggregate multiple summaries into a higher-level summary."""
        ...


class RelationshipAnalyzerProtocol(Protocol):
    """Protocol for relationship analysis engines."""
    
    async def analyze_relationships(self, entities: List[str], timeframe: str) -> RelationshipResult:
        """Analyze relationships between entities within the given timeframe."""  
        ...
    
    async def find_related_entities(self, entity: str, relationship_type: str) -> List[str]:
        """Find entities related to the given entity by relationship type."""
        ...


class TrendAnalyzerProtocol(Protocol):
    """Protocol for trend analysis engines."""
    
    async def analyze_trends(self, patterns: List[str], period: str) -> TrendResult:
        """Analyze trends for the given patterns over the specified period."""
        ...
    
    async def detect_anomalies(self, data: List[Dict[str, Any]], threshold: float) -> List[Dict[str, Any]]:
        """Detect anomalies in the given data using the specified threshold."""
        ...


class ExplanationEngineProtocol(Protocol):
    """Protocol for explanation generation engines."""
    
    async def generate_explanation(self, findings: Dict[str, Any], evidence: List[Dict[str, Any]]) -> ExplanationResult:
        """Generate an explanation for findings based on evidence."""
        ...
    
    async def validate_explanation(self, explanation: str, evidence: List[Dict[str, Any]]) -> float:
        """Validate an explanation against evidence and return confidence score."""
        ...


# Budget and resource management
@dataclass
class SearchBudget:
    """Budget constraints for search operations."""
    max_tokens: int = 10000
    max_time_ms: int = 30000
    max_iterations: int = 5
    current_tokens: int = 0
    current_time_ms: int = 0
    current_iterations: int = 0
    
    def consume_tokens(self, tokens: int) -> bool:
        """Consume tokens from budget. Returns True if successful."""
        if self.current_tokens + tokens <= self.max_tokens:
            self.current_tokens += tokens
            return True
        return False
    
    def consume_time(self, time_ms: int) -> bool:
        """Consume time from budget. Returns True if successful."""
        if self.current_time_ms + time_ms <= self.max_time_ms:
            self.current_time_ms += time_ms
            return True
        return False
    
    def consume_iteration(self) -> bool:
        """Consume an iteration from budget. Returns True if successful."""
        if self.current_iterations < self.max_iterations:
            self.current_iterations += 1
            return True
        return False
    
    @property
    def is_exhausted(self) -> bool:
        """Check if any budget constraint is exhausted."""
        return (self.current_tokens >= self.max_tokens or 
                self.current_time_ms >= self.max_time_ms or
                self.current_iterations >= self.max_iterations)


# Configuration models
class RAGConfig(BaseModel):
    """Configuration for RAG operations."""
    search_strategy: SearchStrategy = SearchStrategy.COMPREHENSIVE
    max_results: int = 500
    enable_agentic_search: bool = True
    enable_pii_redaction: bool = True
    enable_caching: bool = True
    cache_ttl_seconds: int = 3600
    budget_constraints: Optional[SearchBudget] = None
    
    class Config:
        use_enum_values = True


# Error and exception types
class RAGError(Exception):
    """Base exception for RAG operations."""
    pass


class SearchError(RAGError):
    """Exception raised during search operations."""
    pass


class SummarizationError(RAGError):
    """Exception raised during summarization operations."""
    pass


class RelationshipError(RAGError):
    """Exception raised during relationship analysis."""
    pass


class TrendError(RAGError):
    """Exception raised during trend analysis."""
    pass


class ExplanationError(RAGError):
    """Exception raised during explanation generation."""
    pass


class BudgetExhaustedError(RAGError):
    """Exception raised when budget constraints are exceeded."""
    pass


class SecurityError(RAGError):
    """Exception raised for security-related issues."""
    pass