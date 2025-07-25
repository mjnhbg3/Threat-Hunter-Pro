"""
Prometheus-style metrics collector for the Threat Hunter application.

This module defines a ``MetricsCollector`` class which accumulates
counts for Gemini API requests, rate limit errors (HTTP 429) and
token usage. It also tracks the execution duration of worker cycles.
The metrics can be rendered in Prometheus exposition format via
``get_metrics_text``.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Dict


class MetricsCollector:
    """Thread-safe collector of application metrics."""

    def __init__(self) -> None:
        self.gemini_requests_total: Dict[str, int] = defaultdict(int)
        self.gemini_429_total: Dict[str, int] = defaultdict(int)
        self.gemini_tokens_total: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.worker_cycle_seconds: float = 0.0
        self.lock = asyncio.Lock()

    async def increment_requests(self, model: str) -> None:
        async with self.lock:
            self.gemini_requests_total[model] += 1

    async def increment_429s(self, model: str) -> None:
        async with self.lock:
            self.gemini_429_total[model] += 1

    async def add_tokens(self, model: str, direction: str, tokens: int) -> None:
        async with self.lock:
            self.gemini_tokens_total[model][direction] += tokens

    async def set_cycle_time(self, seconds: float) -> None:
        async with self.lock:
            self.worker_cycle_seconds = seconds

    async def get_metrics_text(self) -> str:
        """Render all metrics in Prometheus exposition format."""
        async with self.lock:
            lines: list[str] = []
            # Requests per model
            for model, count in self.gemini_requests_total.items():
                lines.append(f'gemini_requests_total{{model="{model}"}} {count}')
            # 429 errors per model
            for model, count in self.gemini_429_total.items():
                lines.append(f'gemini_429_total{{model="{model}"}} {count}')
            # Token counts per model/direction
            for model, directions in self.gemini_tokens_total.items():
                for direction, count in directions.items():
                    lines.append(f'gemini_tokens_total{{model="{model}",direction="{direction}"}} {count}')
            # Worker cycle duration
            lines.append(f'worker_cycle_seconds {self.worker_cycle_seconds}')
            return '\n'.join(lines) + '\n'