"""
Gemini Embedding Client for Threat Hunter Pro.

This module provides a client for Google's Gemini embedding API,
specifically optimized for the gemini-embedding-001 model.
It handles authentication, rate limiting, batch processing,
and error handling for embedding generation.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import List, Dict, Any, Optional, Tuple
import httpx
import numpy as np

import state
from config import (
    GEMINI_API_KEYS, 
    GEMINI_EMBEDDING_MODEL, 
    GEMINI_EMBEDDING_DIMENSION,
    GEMINI_EMBEDDING_TASK,
    MODEL_QUOTA
)
from token_bucket import TokenBucket


class GeminiEmbeddingClient:
    """Client for Google Gemini Embedding API."""
    
    def __init__(self):
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"
        self.model_name = GEMINI_EMBEDDING_MODEL
        self.dimension = GEMINI_EMBEDDING_DIMENSION
        self.task_type = GEMINI_EMBEDDING_TASK
        self.current_key_index = 0
        self.http_client: Optional[httpx.AsyncClient] = None
        
        # Rate limiting buckets for embedding API
        self.rpm_buckets: Dict[str, TokenBucket] = {}
        self.tpm_buckets: Dict[str, TokenBucket] = {}
        
        # Get rate limits for embedding model
        self.rpm_limit, self.tpm_limit, self.rpd_limit = MODEL_QUOTA.get("embedding", (1500, 1_000_000, 50_000))
        
        logging.info(f"Initialized Gemini Embedding Client with model: {self.model_name}")
        logging.info(f"Rate limits: {self.rpm_limit} RPM, {self.tpm_limit} TPM, {self.rpd_limit} RPD")
    
    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self.http_client is None:
            self.http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0),
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=100)
            )
        return self.http_client
    
    def _get_rate_bucket(self, api_key: str, bucket_type: str) -> TokenBucket:
        """Get or create rate limiting bucket for API key."""
        bucket_dict = self.rpm_buckets if bucket_type == "rpm" else self.tpm_buckets
        
        if api_key not in bucket_dict:
            if bucket_type == "rpm":
                bucket_dict[api_key] = TokenBucket(capacity=self.rpm_limit, refill_rate=self.rpm_limit/60.0)
            else:  # tpm
                bucket_dict[api_key] = TokenBucket(capacity=self.tpm_limit, refill_rate=self.tpm_limit/60.0)
        
        return bucket_dict[api_key]
    
    def _check_daily_limit(self, api_key: str) -> bool:
        """Check if API key has exceeded daily limit."""
        now = datetime.now()
        
        # Reset daily counter if it's a new day
        if api_key in self.daily_reset_times:
            if now >= self.daily_reset_times[api_key]:
                self.daily_request_counts[api_key] = 0
                self.daily_reset_times[api_key] = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
                logging.info(f"Reset daily request count for API key {GEMINI_API_KEYS.index(api_key)+1}")
        else:
            # Initialize tracking for new key
            self.daily_request_counts[api_key] = 0
            self.daily_reset_times[api_key] = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        
        current_count = self.daily_request_counts.get(api_key, 0)
        return current_count < self.rpd_limit
    
    def _increment_daily_count(self, api_key: str) -> None:
        """Increment daily request count for API key."""
        self.daily_request_counts[api_key] = self.daily_request_counts.get(api_key, 0) + 1
        
    async def _find_available_key(self, estimated_tokens: int = 1000) -> Optional[str]:
        """Find an API key with available rate limit capacity."""
        if not GEMINI_API_KEYS:
            raise ValueError("No Gemini API keys configured")
        
        # Try current key first
        current_key = GEMINI_API_KEYS[self.current_key_index]
        rpm_bucket = self._get_rate_bucket(current_key, "rpm")
        tpm_bucket = self._get_rate_bucket(current_key, "tpm")
        
        if rpm_bucket.consume(1) and tpm_bucket.consume(estimated_tokens):
            return current_key
        
        # Try other keys
        for i, key in enumerate(GEMINI_API_KEYS):
            if i == self.current_key_index:
                continue
                
            rpm_bucket = self._get_rate_bucket(key, "rpm")
            tpm_bucket = self._get_rate_bucket(key, "tpm")
            
            if rpm_bucket.consume(1) and tpm_bucket.consume(estimated_tokens):
                self.current_key_index = i
                logging.info(f"Switched to API key {i+1} for embedding request")
                return key
        
        return None
    
    async def _make_embedding_request(self, texts: List[str], api_key: str) -> List[List[float]]:
        """Make a single embedding request to Gemini API."""
        client = await self._get_http_client()
        url = f"{self.base_url}/models/{self.model_name}:embedContent"
        
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": api_key
        }
        
        # Prepare request payload
        requests = []
        for text in texts:
            requests.append({
                "model": f"models/{self.model_name}",
                "content": {
                    "parts": [{"text": text}]
                },
                "taskType": self.task_type,
                "outputDimensionality": self.dimension
            })
        
        payload = {"requests": requests}
        
        try:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            
            result = response.json()
            embeddings = []
            
            if "embeddings" in result:
                for embedding_data in result["embeddings"]:
                    if "values" in embedding_data:
                        embeddings.append(embedding_data["values"])
                    else:
                        logging.warning("No values found in embedding response")
                        embeddings.append([0.0] * self.dimension)
            else:
                logging.error(f"No embeddings in response: {result}")
                return [[0.0] * self.dimension] * len(texts)
            
            return embeddings
            
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                logging.warning(f"Rate limit hit for embedding API: {e}")
                raise
            else:
                logging.error(f"HTTP error in embedding request: {e}")
                raise
        except Exception as e:
            logging.error(f"Error in embedding request: {e}")
            raise
    
    async def embed_texts(self, texts: List[str], batch_size: int = 10) -> np.ndarray:
        """
        Generate embeddings for a list of texts.
        
        Args:
            texts: List of text strings to embed
            batch_size: Number of texts to process in each API call
            
        Returns:
            numpy array of embeddings with shape (len(texts), dimension)
        """
        if not texts:
            return np.array([])
        
        all_embeddings = []
        
        # Process texts in batches
        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i:i + batch_size]
            
            # Estimate token usage (rough approximation)
            estimated_tokens = sum(len(text.split()) * 1.3 for text in batch_texts)
            
            # Find available API key
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    api_key = await self._find_available_key(int(estimated_tokens))
                    if not api_key:
                        logging.warning("No API keys available, waiting 60 seconds...")
                        await asyncio.sleep(60)
                        continue
                    
                    # Make the embedding request
                    batch_embeddings = await self._make_embedding_request(batch_texts, api_key)
                    all_embeddings.extend(batch_embeddings)
                    
                    logging.debug(f"Generated embeddings for batch {i//batch_size + 1}/{(len(texts)-1)//batch_size + 1}")
                    break
                    
                except Exception as e:
                    if attempt == max_retries - 1:
                        logging.error(f"Failed to generate embeddings after {max_retries} attempts: {e}")
                        # Return zero embeddings as fallback
                        fallback_embeddings = [[0.0] * self.dimension] * len(batch_texts)
                        all_embeddings.extend(fallback_embeddings)
                    else:
                        logging.warning(f"Embedding attempt {attempt + 1} failed, retrying: {e}")
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
            
            # Small delay between batches to be respectful
            if i + batch_size < len(texts):
                await asyncio.sleep(0.1)
        
        # Convert to numpy array
        embeddings_array = np.array(all_embeddings, dtype=np.float32)
        logging.info(f"Generated {len(embeddings_array)} embeddings with dimension {embeddings_array.shape[1] if len(embeddings_array) > 0 else 'N/A'}")
        
        return embeddings_array
    
    async def embed_single_text(self, text: str) -> np.ndarray:
        """Generate embedding for a single text."""
        embeddings = await self.embed_texts([text])
        return embeddings[0] if len(embeddings) > 0 else np.zeros(self.dimension, dtype=np.float32)
    
    async def close(self):
        """Close the HTTP client."""
        if self.http_client:
            await self.http_client.aclose()
            self.http_client = None


# Global instance
_gemini_embedding_client: Optional[GeminiEmbeddingClient] = None


async def get_gemini_embedding_client() -> GeminiEmbeddingClient:
    """Get or create the global Gemini embedding client."""
    global _gemini_embedding_client
    
    if _gemini_embedding_client is None:
        _gemini_embedding_client = GeminiEmbeddingClient()
    
    return _gemini_embedding_client


async def close_gemini_embedding_client():
    """Close the global Gemini embedding client."""
    global _gemini_embedding_client
    
    if _gemini_embedding_client:
        await _gemini_embedding_client.close()
        _gemini_embedding_client = None