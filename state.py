"""
Global state for the Threat Hunter application.

This module defines a collection of variables and helper functions used
across multiple modules. By centralising shared state here we avoid
circular imports and ensure that there is a single source of truth
for things like the vector database, metadata store, dashboard data,
settings and rate limiting buckets.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Optional, Dict, Any, List

from .config import DEFAULT_SETTINGS, GEMINI_API_KEYS
from .metrics import MetricsCollector

__all__ = [
    'embedding_model', 'vector_db', 'metadata_db', 'dashboard_data',
    'settings', 'ignored_issue_ids', 'app_status', 'set_app_status',
    'vector_lock', 'api_key_lock', 'rpm_buckets', 'tpm_buckets',
    'current_api_key_index', 'consecutive_failures', 'http_client', 'metrics'
]

# Embedding model (sentence_transformers.SentenceTransformer)
embedding_model = None  # type: ignore

# FAISS vector database instance
vector_db = None  # type: ignore

# Mapping of SHA256 hashes to log metadata. Keys are SHA256 strings.
metadata_db: Dict[str, Dict[str, Any]] = {}

# Dashboard data structure exposed via the API. See models.DashboardData for
# details of the shape. This dictionary will be mutated by worker
# threads and API handlers.
dashboard_data: Dict[str, Any] = {
    "summary": "Initializing…",
    "last_run": None,
    "issues": [],
    "stats": {"total_logs": 0, "new_logs": 0, "anomalies": 0},
    "log_trend": [],
    "rule_distribution": {},
    "active_api_key_index": 0,
    "status": "Initializing…"
}

# Application configuration settings. This dictionary is seeded with
# DEFAULT_SETTINGS and may be overridden by values loaded from disk.
settings: Dict[str, Any] = DEFAULT_SETTINGS.copy()

# Set of issue IDs which have been ignored by the user. These IDs
# correspond to ``Issue.id`` values. Persisted via persistence.py.
ignored_issue_ids: set[str] = set()

# Human‑readable application status string. Updated via set_app_status().
app_status: str = "Initializing…"


def set_app_status(status: str) -> None:
    """Update the global application status and dashboard data status."""
    global app_status
    app_status = status
    dashboard_data["status"] = status
    logging.info(f"Status: {status}")


# Locks used to guard concurrent modifications to shared state
vector_lock = asyncio.Lock()
api_key_lock = asyncio.Lock()

# Rate limiting buckets: per API key for requests per minute and tokens per minute
rpm_buckets: Dict[str, Any] = {}
tpm_buckets: Dict[str, Any] = {}

# Current index into GEMINI_API_KEYS for rotating keys
current_api_key_index: int = 0

# Track consecutive failures per API key when contacting Gemini API
consecutive_failures: Dict[str, int] = defaultdict(int)

# HTTP client used to contact Gemini API. Lazy initialised in ai_logic.py
http_client: Optional[Any] = None

# Metrics collector instance
metrics = MetricsCollector()