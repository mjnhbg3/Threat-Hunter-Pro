"""
Gemini Embedding Client for Threat Hunter Pro using Google's official client library.

This module provides a client for Google's Gemini embedding API,
specifically optimized for the gemini-embedding-001 model with
intelligent fallback to local models when daily limits are exhausted.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Union
import numpy as np

try:
    import google.generativeai as genai
    from google.generativeai import types
    GOOGLE_AI_AVAILABLE = True
except ImportError:
    GOOGLE_AI_AVAILABLE = False
    logging.error("google-generativeai library not available. Install with: pip install google-generativeai")

from .config import GEMINI_API_KEYS
from .token_bucket import TokenBucket


class GeminiEmbeddingClient:
    """
    Client for Google Gemini Embedding API using the official Python client.
    Features:
    - Correct rate limiting: 100 RPM, 30K TPM, 1,000 RPD per API key
    - Daily request tracking with automatic reset at midnight
    - Intelligent fallback when ALL API keys exhaust daily limits
    - Multi-key rotation for redundancy
    """
    
    def __init__(self):
        if not GOOGLE_AI_AVAILABLE:
            raise ImportError("google-generativeai library is required. Install with: pip install google-generativeai")
        
        self.model_name = "gemini-embedding-001"
        self.dimension = 768  # Recommended dimension for gemini-embedding-001
        self.task_type = "RETRIEVAL_DOCUMENT"  # Optimized for document retrieval
        self.current_key_index = 0
        
        # Rate limiting: 100 RPM, 30K TPM, 1,000 RPD per key
        self.rpm_limit = 100
        self.tpm_limit = 30_000
        self.rpd_limit = 1_000
        
        # Rate limiting buckets per API key
        self.rpm_buckets: Dict[str, TokenBucket] = {}
        self.tpm_buckets: Dict[str, TokenBucket] = {}
        
        # Daily request tracking for fallback logic
        self.daily_request_counts: Dict[str, int] = {}
        self.daily_reset_times: Dict[str, datetime] = {}
        self.all_keys_exhausted = False
        
        # Initialize clients for each API key
        self.clients: Dict[str, genai.GenerativeModel] = {}
        for api_key in GEMINI_API_KEYS:
            genai.configure(api_key=api_key)
            # Note: We'll reconfigure for each request to handle multi-key rotation
        
        logging.info(f"Initialized Gemini Embedding Client")
        logging.info(f"Model: {self.model_name}, Dimension: {self.dimension}")
        logging.info(f"Rate limits: {self.rpm_limit} RPM, {self.tpm_limit} TPM, {self.rpd_limit} RPD per key")
        logging.info(f"Available API keys: {len(GEMINI_API_KEYS)}")
    
    def _get_rate_bucket(self, api_key: str, bucket_type: str) -> TokenBucket:
        """Get or create rate limiting bucket for API key."""
        bucket_dict = self.rpm_buckets if bucket_type == "rpm" else self.tpm_buckets
        
        if api_key not in bucket_dict:
            if bucket_type == "rpm":
                bucket_dict[api_key] = TokenBucket(
                    capacity=self.rpm_limit, 
                    refill_rate=self.rpm_limit / 60.0
                )
            else:  # tpm
                bucket_dict[api_key] = TokenBucket(
                    capacity=self.tpm_limit, 
                    refill_rate=self.tpm_limit / 60.0
                )
        
        return bucket_dict[api_key]
    
    def _check_daily_limit(self, api_key: str) -> bool:
        """Check if API key has exceeded daily limit."""
        now = datetime.now()
        
        # Reset daily counter if it's a new day
        if api_key in self.daily_reset_times:
            if now >= self.daily_reset_times[api_key]:
                self.daily_request_counts[api_key] = 0
                self.daily_reset_times[api_key] = now.replace(
                    hour=0, minute=0, second=0, microsecond=0
                ) + timedelta(days=1)
                logging.info(f"Reset daily request count for API key {GEMINI_API_KEYS.index(api_key)+1}")
        else:
            # Initialize tracking for new key
            self.daily_request_counts[api_key] = 0
            self.daily_reset_times[api_key] = now.replace(
                hour=0, minute=0, second=0, microsecond=0
            ) + timedelta(days=1)
        
        current_count = self.daily_request_counts.get(api_key, 0)
        return current_count < self.rpd_limit
    
    def _increment_daily_count(self, api_key: str) -> None:
        """Increment daily request count for API key."""
        self.daily_request_counts[api_key] = self.daily_request_counts.get(api_key, 0) + 1
        
    async def _find_available_key(self, estimated_tokens: int = 1000) -> Optional[str]:
        """Find an API key with available rate limit capacity."""
        if not GEMINI_API_KEYS:
            raise ValueError("No Gemini API keys configured")
        
        # Check if all keys are exhausted for the day
        available_keys = []
        for key in GEMINI_API_KEYS:
            if self._check_daily_limit(key):
                available_keys.append(key)
        
        if not available_keys:
            logging.warning("All Gemini API keys have exceeded daily limits - triggering fallback")
            self.all_keys_exhausted = True
            return None
        
        # Try current key first if it's still available
        current_key = GEMINI_API_KEYS[self.current_key_index]
        if current_key in available_keys:
            rpm_bucket = self._get_rate_bucket(current_key, "rpm")
            tpm_bucket = self._get_rate_bucket(current_key, "tpm")
            
            if await rpm_bucket.consume(1) and await tpm_bucket.consume(estimated_tokens):
                self._increment_daily_count(current_key)
                return current_key
        
        # Try other available keys
        for i, key in enumerate(GEMINI_API_KEYS):
            if key not in available_keys or i == self.current_key_index:
                continue
                
            rpm_bucket = self._get_rate_bucket(key, "rpm")
            tpm_bucket = self._get_rate_bucket(key, "tpm")
            
            if await rpm_bucket.consume(1) and await tpm_bucket.consume(estimated_tokens):
                self.current_key_index = i
                self._increment_daily_count(key)
                daily_count = self.daily_request_counts[key]
                logging.info(f"Switched to API key {i+1} for embedding request (daily: {daily_count}/{self.rpd_limit})")
                return key
        
        return None
    
    async def _make_embedding_request(self, texts: List[str], api_key: str) -> List[List[float]]:
        """Make a single embedding request to Gemini API using the official client."""
        # Configure the client for this API key
        genai.configure(api_key=api_key)
        
        try:
            # Prepare texts - truncate if too long
            processed_texts = []
            for text in texts:
                # Truncate very long texts to avoid API limits
                truncated_text = text[:30000] if len(text) > 30000 else text
                processed_texts.append(truncated_text)
            
            # Use the official client library
            response = genai.embed_content(
                model=f"models/{self.model_name}",
                content=processed_texts,
                task_type=self.task_type,
                output_dimensionality=self.dimension
            )
            
            # Extract embeddings from response
            embeddings = []
            if hasattr(response, 'embedding') and hasattr(response.embedding, 'values'):
                # Single embedding response
                embeddings = [response.embedding.values]
            elif hasattr(response, 'embeddings'):
                # Multiple embeddings response
                embeddings = [emb.values for emb in response.embeddings]
            else:
                logging.error(f"Unexpected response format: {response}")
                return [[0.0] * self.dimension] * len(texts)
            
            return embeddings
            
        except Exception as e:
            logging.error(f"Error in Gemini embedding request: {e}")
            # Return zero embeddings as fallback
            return [[0.0] * self.dimension] * len(texts)
    
    def is_exhausted(self) -> bool:
        """Check if all API keys are exhausted for the day."""
        return self.all_keys_exhausted
    
    async def embed_texts(self, texts: List[str], batch_size: int = 5) -> np.ndarray:
        """
        Generate embeddings for a list of texts using the official Google client.
        
        Args:
            texts: List of text strings to embed
            batch_size: Number of texts to process in each API call (small for rate limits)
            
        Returns:
            numpy array of embeddings with shape (len(texts), dimension)
        """
        if not texts:
            return np.array([])
        
        # Check if already exhausted
        if self.all_keys_exhausted:
            logging.warning("Gemini API keys exhausted, returning zero embeddings")
            return np.zeros((len(texts), self.dimension), dtype=np.float32)
        
        all_embeddings = []
        
        # Process texts in small batches for strict rate limiting
        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i:i + batch_size]
            
            # Estimate token usage (conservative approximation)
            estimated_tokens = sum(len(text.split()) * 1.5 for text in batch_texts)
            
            # Find available API key
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    api_key = await self._find_available_key(int(estimated_tokens))
                    if not api_key:
                        if self.all_keys_exhausted:
                            logging.warning(f"All API keys exhausted during batch processing at {i}/{len(texts)}")
                            # Return zero embeddings for remaining texts
                            remaining_count = len(texts) - len(all_embeddings)
                            if remaining_count > 0:
                                fallback_embeddings = [[0.0] * self.dimension] * remaining_count
                                all_embeddings.extend(fallback_embeddings)
                            break
                        else:
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
            
            # Break if all keys exhausted
            if self.all_keys_exhausted:
                break
            
            # Conservative delay between batches for rate limiting
            if i + batch_size < len(texts):
                await asyncio.sleep(0.7)  # 0.7s delay for 100 RPM compliance
        
        # Convert to numpy array
        embeddings_array = np.array(all_embeddings, dtype=np.float32)
        logging.info(f"Generated {len(embeddings_array)} embeddings with dimension {embeddings_array.shape[1] if len(embeddings_array) > 0 else 'N/A'}")
        
        return embeddings_array
    
    async def embed_single_text(self, text: str) -> np.ndarray:
        """Generate embedding for a single text."""
        embeddings = await self.embed_texts([text])
        return embeddings[0] if len(embeddings) > 0 else np.zeros(self.dimension, dtype=np.float32)


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
        # No explicit close needed for the Google client
        _gemini_embedding_client = None


def is_gemini_exhausted() -> bool:
    """Check if Gemini API keys are exhausted."""
    global _gemini_embedding_client
    return _gemini_embedding_client.is_exhausted() if _gemini_embedding_client else False