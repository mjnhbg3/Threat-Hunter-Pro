"""
Enhanced Vector Store Service for RAG-Enhanced Threat Hunter Pro
Provides FAISS vector database operations with backup, optimization, and monitoring.
"""

import os
import json
import time
import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

import numpy as np
import faiss
import redis
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer

# Configure logging
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

app = FastAPI(title="Threat Hunter Vector Store Service", version="1.0.0")

# =============================================================================
# Configuration
# =============================================================================

VECTOR_DB_PATH = os.getenv("VECTOR_DB_PATH", "/app/data/vector_db.faiss")
METADATA_DB_PATH = os.getenv("METADATA_DB_PATH", "/app/data/metadata.json")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/1")
BACKUP_INTERVAL = int(os.getenv("BACKUP_INTERVAL", "3600"))
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL_NAME", "Snowflake/snowflake-arctic-embed-m")
MAX_MEMORY_MB = int(os.getenv("VECTOR_STORE_MAX_MEMORY", "2048"))

# =============================================================================
# Data Models
# =============================================================================

class SearchRequest(BaseModel):
    query: str
    k: int = 10
    threshold: float = 0.0

class SearchResponse(BaseModel):
    results: List[Dict[str, Any]]
    query_time: float
    total_results: int

class IndexRequest(BaseModel):
    texts: List[str]
    metadata: List[Dict[str, Any]]

class StatusResponse(BaseModel):
    status: str
    index_size: int
    last_backup: Optional[str]
    memory_usage_mb: float
    uptime_seconds: float

# =============================================================================
# Global State
# =============================================================================

class VectorStoreService:
    def __init__(self):
        self.index: Optional[faiss.Index] = None
        self.metadata: List[Dict[str, Any]] = []
        self.model: Optional[SentenceTransformer] = None
        self.redis_client: Optional[redis.Redis] = None
        self.start_time = time.time()
        self.last_backup = None
        
    async def initialize(self):
        """Initialize the vector store service"""
        try:
            # Initialize Redis connection
            self.redis_client = redis.from_url(REDIS_URL, decode_responses=True)
            await asyncio.get_event_loop().run_in_executor(None, self.redis_client.ping)
            logger.info("Connected to Redis")
            
            # Load embedding model
            logger.info(f"Loading embedding model: {EMBEDDING_MODEL}")
            self.model = SentenceTransformer(EMBEDDING_MODEL)
            logger.info("Embedding model loaded successfully")
            
            # Load existing index and metadata
            await self.load_index()
            
            # Start background tasks
            asyncio.create_task(self.backup_scheduler())
            
            logger.info("Vector Store Service initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Vector Store Service: {e}")
            raise
    
    async def load_index(self):
        """Load FAISS index and metadata from disk"""
        try:
            if os.path.exists(VECTOR_DB_PATH) and os.path.exists(METADATA_DB_PATH):
                # Load FAISS index
                self.index = faiss.read_index(VECTOR_DB_PATH)
                logger.info(f"Loaded FAISS index with {self.index.ntotal} vectors")
                
                # Load metadata
                with open(METADATA_DB_PATH, 'r') as f:
                    self.metadata = json.load(f)
                logger.info(f"Loaded {len(self.metadata)} metadata entries")
                
                # Cache index info in Redis
                if self.redis_client:
                    await asyncio.get_event_loop().run_in_executor(
                        None,
                        self.redis_client.hset,
                        "vector_store:info",
                        mapping={
                            "index_size": self.index.ntotal,
                            "last_loaded": datetime.now().isoformat()
                        }
                    )
            else:
                # Create new index
                dimension = self.model.get_sentence_embedding_dimension()
                self.index = faiss.IndexFlatIP(dimension)  # Inner Product for cosine similarity
                self.metadata = []
                logger.info(f"Created new FAISS index with dimension {dimension}")
                
        except Exception as e:
            logger.error(f"Failed to load index: {e}")
            raise
    
    async def save_index(self):
        """Save FAISS index and metadata to disk"""
        try:
            if self.index and self.metadata is not None:
                # Save FAISS index
                faiss.write_index(self.index, VECTOR_DB_PATH)
                
                # Save metadata
                with open(METADATA_DB_PATH, 'w') as f:
                    json.dump(self.metadata, f, indent=2)
                
                self.last_backup = datetime.now().isoformat()
                logger.info(f"Saved index with {self.index.ntotal} vectors at {self.last_backup}")
                
                # Update Redis cache
                if self.redis_client:
                    await asyncio.get_event_loop().run_in_executor(
                        None,
                        self.redis_client.hset,
                        "vector_store:info",
                        mapping={
                            "index_size": self.index.ntotal,
                            "last_backup": self.last_backup
                        }
                    )
                    
        except Exception as e:
            logger.error(f"Failed to save index: {e}")
            raise
    
    async def backup_scheduler(self):
        """Background task for periodic backups"""
        while True:
            try:
                await asyncio.sleep(BACKUP_INTERVAL)
                await self.save_index()
                logger.info("Automatic backup completed")
            except Exception as e:
                logger.error(f"Backup failed: {e}")
    
    async def add_vectors(self, texts: List[str], metadata: List[Dict[str, Any]]):
        """Add new vectors to the index"""
        if len(texts) != len(metadata):
            raise ValueError("Number of texts and metadata entries must match")
        
        try:
            # Generate embeddings
            embeddings = await asyncio.get_event_loop().run_in_executor(
                None, self.model.encode, texts, {"normalize_embeddings": True}
            )
            
            # Add to FAISS index
            self.index.add(embeddings.astype(np.float32))
            
            # Add metadata
            self.metadata.extend(metadata)
            
            logger.info(f"Added {len(texts)} vectors to index")
            
            # Update cache
            if self.redis_client:
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.redis_client.hset,
                    "vector_store:info",
                    "index_size",
                    self.index.ntotal
                )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to add vectors: {e}")
            raise
    
    async def search_vectors(self, query: str, k: int = 10, threshold: float = 0.0) -> Dict[str, Any]:
        """Search for similar vectors"""
        start_time = time.time()
        
        try:
            # Check cache first
            cache_key = f"vector_search:{hash(query)}:{k}:{threshold}"
            if self.redis_client:
                cached_result = await asyncio.get_event_loop().run_in_executor(
                    None, self.redis_client.get, cache_key
                )
                if cached_result:
                    logger.info("Returning cached search result")
                    result = json.loads(cached_result)
                    result["query_time"] = time.time() - start_time
                    return result
            
            # Generate query embedding
            query_embedding = await asyncio.get_event_loop().run_in_executor(
                None, self.model.encode, [query], {"normalize_embeddings": True}
            )
            
            # Search FAISS index
            scores, indices = self.index.search(query_embedding.astype(np.float32), k)
            
            # Filter by threshold and prepare results
            results = []
            for i, (score, idx) in enumerate(zip(scores[0], indices[0])):
                if idx != -1 and score >= threshold:
                    result_metadata = self.metadata[idx].copy()
                    result_metadata["score"] = float(score)
                    result_metadata["rank"] = i
                    results.append(result_metadata)
            
            query_time = time.time() - start_time
            
            search_result = {
                "results": results,
                "query_time": query_time,
                "total_results": len(results)
            }
            
            # Cache result
            if self.redis_client and len(results) > 0:
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    self.redis_client.setex,
                    cache_key,
                    3600,  # 1 hour TTL
                    json.dumps(search_result)
                )
            
            return search_result
            
        except Exception as e:
            logger.error(f"Search failed: {e}")
            raise
    
    def get_status(self) -> Dict[str, Any]:
        """Get service status information"""
        import psutil
        process = psutil.Process()
        memory_mb = process.memory_info().rss / 1024 / 1024
        
        return {
            "status": "healthy" if self.index is not None else "unhealthy",
            "index_size": self.index.ntotal if self.index else 0,
            "last_backup": self.last_backup,
            "memory_usage_mb": round(memory_mb, 2),
            "uptime_seconds": round(time.time() - self.start_time, 2)
        }

# Global service instance
vector_service = VectorStoreService()

# =============================================================================
# API Endpoints
# =============================================================================

@app.on_event("startup")
async def startup_event():
    await vector_service.initialize()

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        status = vector_service.get_status()
        if status["status"] == "healthy":
            return JSONResponse({"status": "healthy", "service": "vector-store"})
        else:
            return JSONResponse(
                {"status": "unhealthy", "service": "vector-store"},
                status_code=503
            )
    except Exception as e:
        return JSONResponse(
            {"status": "error", "error": str(e)},
            status_code=500
        )

@app.get("/status", response_model=StatusResponse)
async def get_status():
    """Get detailed service status"""
    return vector_service.get_status()

@app.post("/search", response_model=SearchResponse)
async def search_vectors(request: SearchRequest):
    """Search for similar vectors"""
    try:
        result = await vector_service.search_vectors(
            request.query, request.k, request.threshold
        )
        return SearchResponse(**result)
    except Exception as e:
        logger.error(f"Search request failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/index")
async def add_to_index(request: IndexRequest, background_tasks: BackgroundTasks):
    """Add new vectors to the index"""
    try:
        await vector_service.add_vectors(request.texts, request.metadata)
        
        # Schedule backup
        background_tasks.add_task(vector_service.save_index)
        
        return {"status": "success", "added": len(request.texts)}
    except Exception as e:
        logger.error(f"Index request failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/backup")
async def manual_backup():
    """Manually trigger a backup"""
    try:
        await vector_service.save_index()
        return {"status": "success", "backup_time": vector_service.last_backup}
    except Exception as e:
        logger.error(f"Manual backup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/metrics")
async def get_metrics():
    """Prometheus metrics endpoint"""
    status = vector_service.get_status()
    
    metrics = f"""# HELP vector_store_index_size Number of vectors in the index
# TYPE vector_store_index_size gauge
vector_store_index_size {status['index_size']}

# HELP vector_store_memory_usage_mb Memory usage in MB
# TYPE vector_store_memory_usage_mb gauge
vector_store_memory_usage_mb {status['memory_usage_mb']}

# HELP vector_store_uptime_seconds Service uptime in seconds
# TYPE vector_store_uptime_seconds counter
vector_store_uptime_seconds {status['uptime_seconds']}
"""
    
    return JSONResponse(content=metrics, media_type="text/plain")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)