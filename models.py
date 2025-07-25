"""
Pydantic models used throughout the Threat Hunter application.

These models are used both for API request/response bodies as well
as for internal data structures. Defining them here centralises
validation and ensures consistent typing across the codebase.
"""

from typing import List, Optional, Dict, Union
from pydantic import BaseModel, Field


class Issue(BaseModel):
    """Representation of an issue detected by the analysis."""

    id: str
    timestamp: str
    severity: str
    title: str
    summary: str
    recommendation: str
    related_logs: List[str]
    category: str = "security"  # "security" or "operational"


class DashboardData(BaseModel):
    """Schema for the aggregated dashboard data returned by the API."""

    summary: str
    last_run: Optional[str]
    issues: List[Issue]
    stats: Dict[str, int]
    log_trend: List[Dict[str, Union[str, int]]]
    rule_distribution: Dict[str, int]
    active_api_key_index: Optional[int] = 0
    status: Optional[str] = "Initializing..."


class QueryRequest(BaseModel):
    """Request body schema for chat-related queries."""

    query: str
    history: Optional[List[dict]] = Field(default_factory=list)


class Settings(BaseModel):
    """Schema used to update application settings via the API."""

    processing_interval: Optional[int]
    initial_scan_count: Optional[int]
    log_batch_size: Optional[int]
    search_k: Optional[int]
    analysis_k: Optional[int]
    max_issues: Optional[int]
    max_output_tokens: Optional[int]