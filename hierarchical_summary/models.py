"""
Pydantic models for hierarchical summarization system.

This module defines comprehensive data models for the multi-level summarization
hierarchy, from cluster-level summaries to quarterly executive reports.
All models include full validation, metadata tracking, and integration points
with the existing Threat Hunter Pro system.
"""

from typing import List, Dict, Any, Optional, Union, Set
from datetime import datetime, date
from enum import Enum
from pydantic import BaseModel, Field, validator, root_validator
import json


class SummaryLevel(str, Enum):
    """Enumeration of summary hierarchy levels."""
    CLUSTER = "cluster"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"


class SecurityPattern(BaseModel):
    """Represents a detected security pattern or anomaly."""
    pattern_type: str = Field(..., description="Type of pattern (e.g., 'bruteforce', 'lateral_movement')")
    description: str = Field(..., description="Human-readable description of the pattern")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score for pattern detection")
    severity: str = Field(..., description="Severity level (low, medium, high, critical)")
    entity_count: int = Field(default=0, description="Number of entities involved in this pattern")
    occurrence_count: int = Field(default=1, description="Number of times this pattern occurred")
    first_seen: datetime = Field(..., description="First occurrence timestamp")
    last_seen: datetime = Field(..., description="Last occurrence timestamp")
    affected_systems: List[str] = Field(default_factory=list, description="Systems affected by this pattern")
    related_rules: List[str] = Field(default_factory=list, description="Wazuh rules that detected this pattern")


class EntityActivity(BaseModel):
    """Tracks activity and behavior patterns for security entities."""
    entity: str = Field(..., description="Entity identifier (IP, user, hostname, etc.)")
    entity_type: str = Field(..., description="Type of entity (ip, user, host, process, etc.)")
    activity_score: float = Field(..., ge=0.0, description="Normalized activity score")
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Calculated risk score")
    event_count: int = Field(default=0, description="Total number of events for this entity")
    unique_rules: int = Field(default=0, description="Number of unique rules triggered")
    first_seen: datetime = Field(..., description="First appearance in time period")
    last_seen: datetime = Field(..., description="Last appearance in time period")
    top_behaviors: List[str] = Field(default_factory=list, description="Most common behaviors observed")
    anomaly_indicators: List[str] = Field(default_factory=list, description="Detected anomalous behaviors")
    geographic_locations: Set[str] = Field(default_factory=set, description="Geographic locations if applicable")
    
    @validator('geographic_locations', pre=True)
    def convert_geographic_locations(cls, v):
        """Convert geographic_locations to set if it's a list."""
        if isinstance(v, list):
            return set(v)
        return v


class SecurityTrend(BaseModel):
    """Represents a security trend with directional analysis."""
    trend_name: str = Field(..., description="Name of the trend")
    category: str = Field(..., description="Category (attack_patterns, system_behavior, etc.)")
    direction: str = Field(..., description="Trend direction (increasing, decreasing, stable, volatile)")
    magnitude: float = Field(..., description="Magnitude of change (percentage or absolute)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Statistical confidence in trend")
    time_period: str = Field(..., description="Time period for trend analysis")
    data_points: List[Dict[str, Any]] = Field(default_factory=list, description="Supporting data points")
    significance: str = Field(default="medium", description="Business significance (low, medium, high)")
    forecast: Optional[Dict[str, Any]] = Field(default=None, description="Trend forecast if available")
    recommendations: List[str] = Field(default_factory=list, description="Recommended actions")


class SummaryMetadata(BaseModel):
    """Metadata for summary objects with versioning and lineage tracking."""
    summary_id: str = Field(..., description="Unique identifier for this summary")
    level: SummaryLevel = Field(..., description="Summary hierarchy level")
    version: int = Field(default=1, description="Version number for this summary")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    updated_at: Optional[datetime] = Field(default=None, description="Last update timestamp")
    time_range_start: datetime = Field(..., description="Start of time range covered")
    time_range_end: datetime = Field(..., description="End of time range covered")
    source_count: int = Field(..., description="Number of source items summarized")
    token_count: int = Field(default=0, description="Estimated token count for this summary")
    generation_time_ms: int = Field(default=0, description="Time taken to generate summary")
    parent_summaries: List[str] = Field(default_factory=list, description="Parent summary IDs")
    child_summaries: List[str] = Field(default_factory=list, description="Child summary IDs")
    quality_score: float = Field(default=0.8, ge=0.0, le=1.0, description="Quality assessment score")
    tags: Set[str] = Field(default_factory=set, description="Categorization tags")
    
    @validator('tags', pre=True)
    def convert_tags(cls, v):
        """Convert tags to set if it's a list."""
        if isinstance(v, list):
            return set(v)
        return v


class ClusterSummary(BaseModel):
    """Summary of a cluster of related security logs."""
    metadata: SummaryMetadata = Field(..., description="Summary metadata and lineage")
    cluster_id: str = Field(..., description="Unique identifier for this cluster")
    summary_text: str = Field(..., description="Human-readable summary of the cluster")
    key_insights: List[str] = Field(default_factory=list, description="Key insights extracted from logs")
    security_patterns: List[SecurityPattern] = Field(default_factory=list, description="Detected security patterns")
    entity_activities: List[EntityActivity] = Field(default_factory=list, description="Entity activity summaries")
    common_elements: Dict[str, Any] = Field(default_factory=dict, description="Common elements across cluster")
    anomalies: List[str] = Field(default_factory=list, description="Detected anomalies")
    risk_assessment: str = Field(default="medium", description="Overall risk assessment")
    log_references: List[str] = Field(default_factory=list, description="References to source log IDs")
    clustering_method: str = Field(default="semantic", description="Method used for clustering")
    cluster_coherence: float = Field(default=0.7, ge=0.0, le=1.0, description="Cluster coherence score")
    
    @validator('summary_text')
    def validate_summary_length(cls, v):
        """Ensure summary text is within expected length bounds."""
        if len(v) < 50:
            raise ValueError("Summary text too short (minimum 50 characters)")
        if len(v) > 2000:
            raise ValueError("Summary text too long (maximum 2000 characters)")
        return v


class DailySummary(BaseModel):
    """Daily security summary aggregating cluster summaries."""
    metadata: SummaryMetadata = Field(..., description="Summary metadata and lineage")
    date: date = Field(..., description="Date for this daily summary")
    executive_summary: str = Field(..., description="Executive summary of the day's security events")
    key_findings: List[str] = Field(default_factory=list, description="Key security findings")
    security_trends: List[SecurityTrend] = Field(default_factory=list, description="Daily security trends")
    top_entities: List[EntityActivity] = Field(default_factory=list, description="Most active entities")
    incident_count: int = Field(default=0, description="Number of security incidents")
    alert_volume: int = Field(default=0, description="Total alert volume")
    cluster_summaries: List[str] = Field(default_factory=list, description="IDs of constituent cluster summaries")
    system_health: Dict[str, Any] = Field(default_factory=dict, description="System health indicators")
    compliance_status: Dict[str, str] = Field(default_factory=dict, description="Compliance check results")
    recommendations: List[str] = Field(default_factory=list, description="Daily recommendations")
    metrics: Dict[str, float] = Field(default_factory=dict, description="Quantitative metrics")
    
    @validator('executive_summary')
    def validate_executive_summary_length(cls, v):
        """Ensure executive summary is within expected length bounds."""
        if len(v) < 100:
            raise ValueError("Executive summary too short (minimum 100 characters)")
        if len(v) > 5000:
            raise ValueError("Executive summary too long (maximum 5000 characters)")
        return v


class WeeklySummary(BaseModel):
    """Weekly security summary with trend analysis."""
    metadata: SummaryMetadata = Field(..., description="Summary metadata and lineage")
    week_start: date = Field(..., description="Start date of the week")
    week_end: date = Field(..., description="End date of the week")
    executive_summary: str = Field(..., description="Executive summary of weekly security posture")
    weekly_trends: List[SecurityTrend] = Field(default_factory=list, description="Week-over-week trends")
    major_incidents: List[Dict[str, Any]] = Field(default_factory=list, description="Major security incidents")
    entity_behavior_analysis: List[EntityActivity] = Field(default_factory=list, description="Entity behavior patterns")
    campaign_detection: List[Dict[str, Any]] = Field(default_factory=list, description="Detected attack campaigns")
    daily_summaries: List[str] = Field(default_factory=list, description="IDs of constituent daily summaries")
    week_over_week_comparison: Dict[str, Any] = Field(default_factory=dict, description="Comparison with previous week")
    infrastructure_insights: List[str] = Field(default_factory=list, description="Infrastructure-related insights")
    user_behavior_insights: List[str] = Field(default_factory=list, description="User behavior insights")
    threat_landscape: Dict[str, Any] = Field(default_factory=dict, description="Threat landscape analysis")
    strategic_recommendations: List[str] = Field(default_factory=list, description="Strategic recommendations")
    
    @validator('executive_summary')
    def validate_weekly_summary_length(cls, v):
        """Ensure weekly executive summary is within expected length bounds."""
        if len(v) < 200:
            raise ValueError("Weekly executive summary too short (minimum 200 characters)")
        if len(v) > 8000:
            raise ValueError("Weekly executive summary too long (maximum 8000 characters)")
        return v


class MonthlySummary(BaseModel):
    """Monthly security summary with strategic analysis."""
    metadata: SummaryMetadata = Field(..., description="Summary metadata and lineage")
    month: int = Field(..., ge=1, le=12, description="Month number")
    year: int = Field(..., description="Year")
    executive_summary: str = Field(..., description="Executive summary of monthly security posture")
    security_posture_assessment: Dict[str, Any] = Field(default_factory=dict, description="Overall security posture")
    monthly_trends: List[SecurityTrend] = Field(default_factory=list, description="Monthly trend analysis")
    threat_intelligence: Dict[str, Any] = Field(default_factory=dict, description="Threat intelligence insights")
    weekly_summaries: List[str] = Field(default_factory=list, description="IDs of constituent weekly summaries")
    month_over_month_analysis: Dict[str, Any] = Field(default_factory=dict, description="Month-over-month comparison")
    infrastructure_assessment: Dict[str, Any] = Field(default_factory=dict, description="Infrastructure security assessment")
    policy_effectiveness: Dict[str, Any] = Field(default_factory=dict, description="Security policy effectiveness")
    budget_impact_analysis: Dict[str, Any] = Field(default_factory=dict, description="Budget and resource impact")
    compliance_scorecard: Dict[str, Any] = Field(default_factory=dict, description="Compliance scorecard")
    strategic_initiatives: List[str] = Field(default_factory=list, description="Recommended strategic initiatives")
    executive_kpis: Dict[str, float] = Field(default_factory=dict, description="Key performance indicators")
    
    @validator('executive_summary')
    def validate_monthly_summary_length(cls, v):
        """Ensure monthly executive summary is within expected length bounds."""
        if len(v) < 500:
            raise ValueError("Monthly executive summary too short (minimum 500 characters)")
        if len(v) > 12000:
            raise ValueError("Monthly executive summary too long (maximum 12000 characters)")
        return v


class QuarterlySummary(BaseModel):
    """Quarterly security summary with executive reporting."""
    metadata: SummaryMetadata = Field(..., description="Summary metadata and lineage")
    quarter: int = Field(..., ge=1, le=4, description="Quarter number")
    year: int = Field(..., description="Year")
    executive_summary: str = Field(..., description="Executive summary for quarterly board report")
    security_program_assessment: Dict[str, Any] = Field(default_factory=dict, description="Security program assessment")
    quarterly_trends: List[SecurityTrend] = Field(default_factory=list, description="Quarterly trend analysis")
    threat_landscape_evolution: Dict[str, Any] = Field(default_factory=dict, description="Threat landscape evolution")
    monthly_summaries: List[str] = Field(default_factory=list, description="IDs of constituent monthly summaries")
    quarter_over_quarter_analysis: Dict[str, Any] = Field(default_factory=dict, description="Quarter-over-quarter analysis")
    strategic_security_metrics: Dict[str, float] = Field(default_factory=dict, description="Strategic security metrics")
    investment_recommendations: List[Dict[str, Any]] = Field(default_factory=list, description="Investment recommendations")
    regulatory_compliance_status: Dict[str, Any] = Field(default_factory=dict, description="Regulatory compliance status")
    business_risk_assessment: Dict[str, Any] = Field(default_factory=dict, description="Business risk assessment")
    board_presentation_highlights: List[str] = Field(default_factory=list, description="Key points for board presentation")
    annual_planning_inputs: Dict[str, Any] = Field(default_factory=dict, description="Inputs for annual security planning")
    
    @validator('executive_summary')
    def validate_quarterly_summary_length(cls, v):
        """Ensure quarterly executive summary is within expected length bounds."""
        if len(v) < 800:
            raise ValueError("Quarterly executive summary too short (minimum 800 characters)")
        if len(v) > 15000:
            raise ValueError("Quarterly executive summary too long (maximum 15000 characters)")
        return v


class SummaryConfig(BaseModel):
    """Configuration for hierarchical summarization system."""
    # Clustering configuration
    cluster_size_min: int = Field(default=5, description="Minimum logs per cluster")
    cluster_size_max: int = Field(default=50, description="Maximum logs per cluster") 
    clustering_algorithm: str = Field(default="semantic", description="Clustering algorithm to use")
    similarity_threshold: float = Field(default=0.7, ge=0.0, le=1.0, description="Similarity threshold for clustering")
    temporal_window_hours: int = Field(default=24, description="Temporal window for clustering")
    
    # Summarization configuration
    summary_model: str = Field(default="gemini-2.5-flash", description="AI model for summary generation")
    max_summary_tokens: int = Field(default=2000, description="Maximum tokens per summary")
    quality_threshold: float = Field(default=0.7, ge=0.0, le=1.0, description="Minimum quality threshold")
    entity_extraction_enabled: bool = Field(default=True, description="Whether to extract entities")
    
    # Storage configuration
    compression_enabled: bool = Field(default=True, description="Whether to compress stored summaries")
    retention_days_cluster: int = Field(default=90, description="Retention days for cluster summaries")
    retention_days_daily: int = Field(default=365, description="Retention days for daily summaries")
    retention_days_weekly: int = Field(default=730, description="Retention days for weekly summaries")
    retention_days_monthly: int = Field(default=1825, description="Retention days for monthly summaries")
    retention_days_quarterly: int = Field(default=3650, description="Retention days for quarterly summaries")
    
    # Processing configuration
    parallel_processing: bool = Field(default=True, description="Whether to use parallel processing")
    max_concurrent_jobs: int = Field(default=4, description="Maximum concurrent summarization jobs")
    batch_size: int = Field(default=100, description="Batch size for processing")
    timeout_seconds: int = Field(default=1800, description="Timeout for summarization jobs")
    
    # Integration configuration
    redis_caching: bool = Field(default=True, description="Whether to use Redis caching")
    cache_ttl_seconds: int = Field(default=3600, description="Cache TTL in seconds")
    metrics_enabled: bool = Field(default=True, description="Whether to collect metrics")
    
    @validator('cluster_size_max')
    def validate_cluster_sizes(cls, v, values):
        """Ensure cluster_size_max is greater than cluster_size_min."""
        if 'cluster_size_min' in values and v <= values['cluster_size_min']:
            raise ValueError("cluster_size_max must be greater than cluster_size_min")
        return v


# Union type for all summary types
AnySummary = Union[ClusterSummary, DailySummary, WeeklySummary, MonthlySummary, QuarterlySummary]


class SummaryQuery(BaseModel):
    """Query model for summary retrieval."""
    level: Optional[SummaryLevel] = Field(default=None, description="Summary level to query")
    start_date: Optional[datetime] = Field(default=None, description="Start date for time range")
    end_date: Optional[datetime] = Field(default=None, description="End date for time range")
    entity_filter: Optional[str] = Field(default=None, description="Filter by entity")
    pattern_filter: Optional[str] = Field(default=None, description="Filter by security pattern")
    tags: Optional[List[str]] = Field(default=None, description="Filter by tags")
    limit: int = Field(default=50, ge=1, le=1000, description="Maximum number of results")
    include_metadata: bool = Field(default=True, description="Whether to include metadata")


class SummaryResponse(BaseModel):
    """Response model for summary queries."""
    summaries: List[AnySummary] = Field(default_factory=list, description="Retrieved summaries")
    total_count: int = Field(default=0, description="Total number of matching summaries")
    query_time_ms: int = Field(default=0, description="Query execution time in milliseconds")
    cache_hit: bool = Field(default=False, description="Whether this was a cache hit")
    aggregation_level: Optional[SummaryLevel] = Field(default=None, description="Aggregation level used")