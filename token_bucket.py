"""
Implementation of a simple asynchronous token bucket for rate limiting.

The token bucket algorithm controls how frequently an action may be
performed. Tokens are added to the bucket at a steady rate and
consumed when an action is executed. If the bucket does not contain
enough tokens, callers must wait until enough tokens have been
refilled.

This implementation uses asyncio locks to ensure thread safety when
used concurrently in an async environment.
"""

import asyncio
import time
from dataclasses import dataclass


@dataclass
class TokenBucket:
    """Simple token bucket for rate limiting."""

    capacity: int
    refill_rate: float
    tokens: float = None
    last_refill: float = None
    lock: asyncio.Lock = None

    def __post_init__(self) -> None:
        # Initialise tokens and last_refill on first use
        if self.tokens is None:
            self.tokens = float(self.capacity)
        if self.last_refill is None:
            self.last_refill = time.time()
        if self.lock is None:
            self.lock = asyncio.Lock()

    async def consume(self, tokens: int) -> bool:
        """Try to consume tokens from the bucket. Returns True if successful."""
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            # Refill tokens based on time passed
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    async def wait_for_tokens(self, tokens: int) -> None:
        """Block until enough tokens are available for consumption."""
        while not await self.consume(tokens):
            needed = tokens - self.tokens
            # Add a small buffer to the wait time to ensure tokens accrue
            wait_time = needed / self.refill_rate
            await asyncio.sleep(max(wait_time + 0.1, 0))