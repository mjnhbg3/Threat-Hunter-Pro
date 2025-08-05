"""
Storage and retrieval system for hierarchical summaries.

This module provides efficient storage and retrieval of hierarchical summaries
with time-partitioned indexing, compression, caching, and versioning support.
It integrates with the existing Threat Hunter Pro database infrastructure
while providing optimized access patterns for summary queries.
"""

import asyncio
import logging
import json
import gzip
import hashlib
import os
import pickle
from typing import List, Dict, Any, Optional, Union, Set, Tuple
from datetime import datetime, date, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
import sqlite3
import threading
from contextlib import asynccontextmanager

import redis
import aiofiles
from pydantic import ValidationError

from ..config import DB_DIR
from .models import (
    AnySummary, ClusterSummary, DailySummary, WeeklySummary, 
    MonthlySummary, QuarterlySummary, SummaryLevel, SummaryQuery, 
    SummaryResponse, SummaryConfig, SummaryMetadata
)

logger = logging.getLogger(__name__)


@dataclass
class StorageStats:
    """Statistics about summary storage usage."""
    total_summaries: int = 0
    storage_size_bytes: int = 0
    compressed_size_bytes: int = 0
    compression_ratio: float = 0.0
    cache_hit_rate: float = 0.0
    avg_retrieval_time_ms: float = 0.0
    by_level: Dict[str, int] = None
    
    def __post_init__(self):
        if self.by_level is None:
            self.by_level = {}


class SummaryStorage:
    """
    High-performance storage and retrieval system for hierarchical summaries.
    
    Features:
    - Time-partitioned storage for efficient range queries
    - Compression to reduce storage footprint
    - Redis caching for frequently accessed summaries
    - Version management and conflict resolution
    - Batch operations for bulk storage/retrieval
    - Automatic cleanup and retention management
    """
    
    def __init__(self, config: SummaryConfig):
        self.config = config
        self.storage_dir = Path(DB_DIR) / "hierarchical_summaries"
        self.db_path = self.storage_dir / "summaries.db"
        self.redis_client: Optional[redis.Redis] = None
        self.db_lock = threading.RLock()
        self._cache_stats = {"hits": 0, "misses": 0}
        self._initialized = False
        
    async def initialize(self):
        """Initialize the storage system."""
        if self._initialized:
            return
            
        # Create storage directory
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize SQLite database
        await self._initialize_database()
        
        # Initialize Redis cache if enabled
        if self.config.redis_caching:
            try:
                self.redis_client = redis.Redis(
                    host='localhost', 
                    port=6379, 
                    db=2,  # Use separate DB for summaries
                    decode_responses=False  # We'll handle encoding ourselves
                )
                await asyncio.to_thread(self.redis_client.ping)
                logger.info("Redis cache initialized for summary storage")
            except Exception as e:
                logger.warning(f"Redis cache initialization failed: {e}. Continuing without cache.")
                self.redis_client = None
                
        self._initialized = True
        logger.info("SummaryStorage initialized")
        
    async def _initialize_database(self):
        """Initialize the SQLite database schema."""
        schema_sql = """
        CREATE TABLE IF NOT EXISTS summaries (
            id TEXT PRIMARY KEY,
            level TEXT NOT NULL,
            time_range_start TIMESTAMP NOT NULL,
            time_range_end TIMESTAMP NOT NULL,
            version INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            source_count INTEGER DEFAULT 0,
            token_count INTEGER DEFAULT 0,
            quality_score REAL DEFAULT 0.8,
            tags TEXT DEFAULT '[]',
            parent_summaries TEXT DEFAULT '[]',
            child_summaries TEXT DEFAULT '[]',
            storage_path TEXT NOT NULL,
            compressed_size INTEGER DEFAULT 0,
            checksum TEXT NOT NULL
        );
        
        CREATE INDEX IF NOT EXISTS idx_summaries_level ON summaries(level);
        CREATE INDEX IF NOT EXISTS idx_summaries_time_range ON summaries(time_range_start, time_range_end);
        CREATE INDEX IF NOT EXISTS idx_summaries_created ON summaries(created_at);
        CREATE INDEX IF NOT EXISTS idx_summaries_tags ON summaries(tags);
        CREATE INDEX IF NOT EXISTS idx_summaries_quality ON summaries(quality_score);
        
        CREATE TABLE IF NOT EXISTS summary_relationships (
            parent_id TEXT NOT NULL,
            child_id TEXT NOT NULL,
            relationship_type TEXT DEFAULT 'aggregation',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (parent_id, child_id),
            FOREIGN KEY (parent_id) REFERENCES summaries(id),
            FOREIGN KEY (child_id) REFERENCES summaries(id)
        );
        
        CREATE INDEX IF NOT EXISTS idx_relationships_parent ON summary_relationships(parent_id);
        CREATE INDEX IF NOT EXISTS idx_relationships_child ON summary_relationships(child_id);
        
        CREATE TABLE IF NOT EXISTS storage_stats (
            stat_date DATE PRIMARY KEY,
            total_summaries INTEGER DEFAULT 0,
            storage_size_bytes INTEGER DEFAULT 0,
            compressed_size_bytes INTEGER DEFAULT 0,
            cache_hits INTEGER DEFAULT 0,
            cache_misses INTEGER DEFAULT 0,
            avg_retrieval_time_ms REAL DEFAULT 0.0
        );
        """
        
        def execute_schema():
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.executescript(schema_sql)
                conn.commit()
                
        await asyncio.to_thread(execute_schema)
        
    async def store_summary(self, summary: AnySummary) -> bool:
        """
        Store a summary with compression and caching.
        
        Args:
            summary: The summary object to store
            
        Returns:
            bool: True if successfully stored
        """
        try:
            # Serialize and compress summary
            serialized_data = self._serialize_summary(summary)
            compressed_data = await self._compress_data(serialized_data)
            
            # Calculate storage path and checksum
            storage_path = self._get_storage_path(summary)
            checksum = hashlib.sha256(compressed_data).hexdigest()
            
            # Store compressed data to file
            await self._write_compressed_file(storage_path, compressed_data)
            
            # Store metadata in database
            await self._store_summary_metadata(summary, storage_path, len(compressed_data), checksum)
            
            # Cache the summary if caching is enabled
            if self.redis_client:
                await self._cache_summary(summary.metadata.summary_id, serialized_data)
                
            # Update relationships
            await self._update_summary_relationships(summary)
            
            logger.debug(f"Stored summary {summary.metadata.summary_id} ({len(compressed_data)} bytes)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store summary {summary.metadata.summary_id}: {e}")
            return False
            
    async def retrieve_summary(self, summary_id: str) -> Optional[AnySummary]:
        """
        Retrieve a summary by ID with caching.
        
        Args:
            summary_id: The summary ID to retrieve
            
        Returns:
            The summary object or None if not found
        """
        start_time = datetime.utcnow()
        
        try:
            # Try cache first
            if self.redis_client:
                cached_data = await self._get_cached_summary(summary_id)
                if cached_data:
                    self._cache_stats["hits"] += 1
                    summary = self._deserialize_summary(cached_data)
                    await self._record_retrieval_time(summary_id, start_time)
                    return summary
                    
            self._cache_stats["misses"] += 1
            
            # Retrieve from database
            metadata = await self._get_summary_metadata(summary_id)
            if not metadata:
                return None
                
            # Read and decompress data
            compressed_data = await self._read_compressed_file(metadata['storage_path'])
            if not compressed_data:
                return None
                
            # Verify checksum
            if hashlib.sha256(compressed_data).hexdigest() != metadata['checksum']:
                logger.error(f"Checksum mismatch for summary {summary_id}")
                return None
                
            # Decompress and deserialize
            serialized_data = await self._decompress_data(compressed_data)
            summary = self._deserialize_summary(serialized_data)
            
            # Update cache
            if self.redis_client and summary:
                await self._cache_summary(summary_id, serialized_data)
                
            await self._record_retrieval_time(summary_id, start_time)
            return summary
            
        except Exception as e:
            logger.error(f"Failed to retrieve summary {summary_id}: {e}")
            return None
            
    async def query_summaries(self, query: SummaryQuery) -> SummaryResponse:
        """
        Query summaries with filtering and pagination.
        
        Args:
            query: The query parameters
            
        Returns:
            SummaryResponse with matching summaries
        """
        start_time = datetime.utcnow()
        
        try:
            # Build SQL query
            sql, params = self._build_query_sql(query)
            
            # Execute query
            metadata_results = await self._execute_query(sql, params)
            
            # Retrieve actual summary objects
            summaries = []
            for metadata in metadata_results[:query.limit]:
                summary = await self.retrieve_summary(metadata['id'])
                if summary:
                    summaries.append(summary)
                    
            # Get total count
            total_count = len(metadata_results)
            
            query_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            
            return SummaryResponse(
                summaries=summaries,
                total_count=total_count,
                query_time_ms=query_time,
                cache_hit=False,  # TODO: Implement query-level caching
                aggregation_level=query.level
            )
            
        except Exception as e:
            logger.error(f"Failed to query summaries: {e}")
            return SummaryResponse(summaries=[], total_count=0, query_time_ms=0)
            
    async def batch_store_summaries(self, summaries: List[AnySummary]) -> Dict[str, bool]:
        """
        Store multiple summaries in batch for better performance.
        
        Args:
            summaries: List of summaries to store
            
        Returns:
            Dict mapping summary IDs to success status
        """
        results = {}
        
        if not summaries:
            return results
            
        # Process in parallel batches
        batch_size = min(10, len(summaries))  # Process up to 10 summaries at once
        
        for i in range(0, len(summaries), batch_size):
            batch = summaries[i:i + batch_size]
            batch_tasks = [self.store_summary(summary) for summary in batch]
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for summary, result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    logger.error(f"Batch store failed for {summary.metadata.summary_id}: {result}")
                    results[summary.metadata.summary_id] = False
                else:
                    results[summary.metadata.summary_id] = result
                    
        logger.info(f"Batch stored {len(summaries)} summaries: {sum(results.values())} successful")
        return results
        
    async def get_storage_stats(self) -> StorageStats:
        """Get comprehensive storage statistics."""
        try:
            sql = """
            SELECT 
                COUNT(*) as total_summaries,
                SUM(compressed_size) as compressed_size_bytes,
                AVG(quality_score) as avg_quality,
                level,
                COUNT(*) as level_count
            FROM summaries 
            GROUP BY level
            """
            
            results = await self._execute_query(sql, [])
            
            stats = StorageStats()
            for row in results:
                stats.total_summaries += row['level_count']
                stats.compressed_size_bytes += row['compressed_size_bytes'] or 0
                stats.by_level[row['level']] = row['level_count']
                
            # Calculate cache hit rate
            total_requests = self._cache_stats["hits"] + self._cache_stats["misses"]
            if total_requests > 0:
                stats.cache_hit_rate = self._cache_stats["hits"] / total_requests
                
            # Estimate storage size (compressed size is actual storage)
            stats.storage_size_bytes = stats.compressed_size_bytes
            
            # Calculate directory size for verification
            if self.storage_dir.exists():
                total_size = sum(f.stat().st_size for f in self.storage_dir.rglob('*') if f.is_file())
                stats.storage_size_bytes = max(stats.storage_size_bytes, total_size)
                
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get storage stats: {e}")
            return StorageStats()
            
    async def cleanup_expired_summaries(self) -> int:
        """
        Clean up expired summaries based on retention policies.
        
        Returns:
            Number of summaries cleaned up
        """
        cleanup_count = 0
        current_time = datetime.utcnow()
        
        retention_map = {
            SummaryLevel.CLUSTER: self.config.retention_days_cluster,
            SummaryLevel.DAILY: self.config.retention_days_daily,
            SummaryLevel.WEEKLY: self.config.retention_days_weekly,
            SummaryLevel.MONTHLY: self.config.retention_days_monthly,
            SummaryLevel.QUARTERLY: self.config.retention_days_quarterly
        }
        
        for level, retention_days in retention_map.items():
            cutoff_date = current_time - timedelta(days=retention_days)
            
            # Find expired summaries
            sql = """
            SELECT id, storage_path FROM summaries 
            WHERE level = ? AND created_at < ?
            """
            
            expired_summaries = await self._execute_query(sql, [level.value, cutoff_date])
            
            for summary_info in expired_summaries:
                try:
                    # Remove from cache
                    if self.redis_client:
                        await asyncio.to_thread(self.redis_client.delete, f"summary:{summary_info['id']}")
                        
                    # Remove file
                    storage_path = Path(summary_info['storage_path'])
                    if storage_path.exists():
                        await asyncio.to_thread(storage_path.unlink)
                        
                    # Remove from database
                    await self._delete_summary_metadata(summary_info['id'])
                    
                    cleanup_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to cleanup summary {summary_info['id']}: {e}")
                    
        if cleanup_count > 0:
            logger.info(f"Cleaned up {cleanup_count} expired summaries")
            
        return cleanup_count
        
    async def get_summary_hierarchy(self, summary_id: str) -> Dict[str, List[str]]:
        """
        Get the complete hierarchy (parents and children) for a summary.
        
        Args:
            summary_id: The summary ID to get hierarchy for
            
        Returns:
            Dict with 'parents' and 'children' lists
        """
        try:
            # Get parents
            parent_sql = """
            SELECT parent_id FROM summary_relationships 
            WHERE child_id = ?
            """
            parents = await self._execute_query(parent_sql, [summary_id])
            
            # Get children
            child_sql = """
            SELECT child_id FROM summary_relationships 
            WHERE parent_id = ?
            """
            children = await self._execute_query(child_sql, [summary_id])
            
            return {
                'parents': [row['parent_id'] for row in parents],
                'children': [row['child_id'] for row in children]
            }
            
        except Exception as e:
            logger.error(f"Failed to get hierarchy for {summary_id}: {e}")
            return {'parents': [], 'children': []}
            
    async def get_summaries_by_time_range(self, level: SummaryLevel, 
                                        start_date: datetime, 
                                        end_date: datetime) -> List[AnySummary]:
        """
        Get all summaries of a specific level within a time range.
        
        Args:
            level: Summary level to filter by
            start_date: Start of time range
            end_date: End of time range
            
        Returns:
            List of summaries in the time range
        """
        query = SummaryQuery(
            level=level,
            start_date=start_date,
            end_date=end_date,
            limit=1000  # Large limit for time range queries
        )
        
        response = await self.query_summaries(query)
        return response.summaries
        
    # Private helper methods
    
    def _serialize_summary(self, summary: AnySummary) -> bytes:
        """Serialize a summary to bytes."""
        try:
            # Convert to dict and then to JSON bytes
            summary_dict = summary.dict()
            json_str = json.dumps(summary_dict, default=str, ensure_ascii=False)
            return json_str.encode('utf-8')
        except Exception as e:
            logger.error(f"Failed to serialize summary: {e}")
            raise
            
    def _deserialize_summary(self, data: bytes) -> Optional[AnySummary]:
        """Deserialize bytes to a summary object."""
        try:
            json_str = data.decode('utf-8')
            summary_dict = json.loads(json_str)
            
            # Determine summary type from metadata level
            level = summary_dict['metadata']['level']
            
            if level == SummaryLevel.CLUSTER.value:
                return ClusterSummary(**summary_dict)
            elif level == SummaryLevel.DAILY.value:
                return DailySummary(**summary_dict)
            elif level == SummaryLevel.WEEKLY.value:
                return WeeklySummary(**summary_dict)
            elif level == SummaryLevel.MONTHLY.value:
                return MonthlySummary(**summary_dict)
            elif level == SummaryLevel.QUARTERLY.value:
                return QuarterlySummary(**summary_dict)
            else:
                logger.error(f"Unknown summary level: {level}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to deserialize summary: {e}")
            return None
            
    async def _compress_data(self, data: bytes) -> bytes:
        """Compress data using gzip."""
        if not self.config.compression_enabled:
            return data
            
        return await asyncio.to_thread(gzip.compress, data, compresslevel=6)
        
    async def _decompress_data(self, compressed_data: bytes) -> bytes:
        """Decompress gzipped data."""
        if not self.config.compression_enabled:
            return compressed_data
            
        return await asyncio.to_thread(gzip.decompress, compressed_data)
        
    def _get_storage_path(self, summary: AnySummary) -> Path:
        """Generate storage path for a summary."""
        # Organize by level and date for efficient access
        level_dir = self.storage_dir / summary.metadata.level.value
        
        # Create date-based subdirectories
        date_str = summary.metadata.time_range_start.strftime("%Y/%m")
        date_dir = level_dir / date_str
        
        # Filename based on summary ID
        filename = f"{summary.metadata.summary_id}.gz" if self.config.compression_enabled else f"{summary.metadata.summary_id}.json"
        
        return date_dir / filename
        
    async def _write_compressed_file(self, path: Path, data: bytes):
        """Write compressed data to file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        
        async with aiofiles.open(path, 'wb') as f:
            await f.write(data)
            
    async def _read_compressed_file(self, path: str) -> Optional[bytes]:
        """Read compressed data from file."""
        try:
            async with aiofiles.open(path, 'rb') as f:
                return await f.read()
        except FileNotFoundError:
            logger.error(f"Summary file not found: {path}")
            return None
        except Exception as e:
            logger.error(f"Failed to read summary file {path}: {e}")
            return None
            
    async def _store_summary_metadata(self, summary: AnySummary, storage_path: Path, 
                                    compressed_size: int, checksum: str):
        """Store summary metadata in database."""
        sql = """
        INSERT OR REPLACE INTO summaries (
            id, level, time_range_start, time_range_end, version, 
            source_count, token_count, quality_score, tags, 
            parent_summaries, child_summaries, storage_path, 
            compressed_size, checksum, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """
        
        params = [
            summary.metadata.summary_id,
            summary.metadata.level.value,
            summary.metadata.time_range_start,
            summary.metadata.time_range_end,
            summary.metadata.version,
            summary.metadata.source_count,
            summary.metadata.token_count,
            summary.metadata.quality_score,
            json.dumps(list(summary.metadata.tags)),
            json.dumps(summary.metadata.parent_summaries),
            json.dumps(summary.metadata.child_summaries),
            str(storage_path),
            compressed_size,
            checksum
        ]
        
        def execute_insert():
            with self.db_lock:
                with sqlite3.connect(str(self.db_path)) as conn:
                    conn.execute(sql, params)
                    conn.commit()
                    
        await asyncio.to_thread(execute_insert)
        
    async def _get_summary_metadata(self, summary_id: str) -> Optional[Dict[str, Any]]:
        """Get summary metadata from database."""
        sql = """
        SELECT * FROM summaries WHERE id = ?
        """
        
        def execute_select():
            with self.db_lock:
                with sqlite3.connect(str(self.db_path)) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.execute(sql, [summary_id])
                    row = cursor.fetchone()
                    return dict(row) if row else None
                    
        return await asyncio.to_thread(execute_select)
        
    async def _cache_summary(self, summary_id: str, data: bytes):
        """Cache summary data in Redis."""
        if not self.redis_client:
            return
            
        try:
            cache_key = f"summary:{summary_id}"
            await asyncio.to_thread(
                self.redis_client.setex, 
                cache_key, 
                self.config.cache_ttl_seconds, 
                data
            )
        except Exception as e:
            logger.warning(f"Failed to cache summary {summary_id}: {e}")
            
    async def _get_cached_summary(self, summary_id: str) -> Optional[bytes]:
        """Get cached summary data from Redis."""
        if not self.redis_client:
            return None
            
        try:
            cache_key = f"summary:{summary_id}"
            data = await asyncio.to_thread(self.redis_client.get, cache_key)
            return data
        except Exception as e:
            logger.warning(f"Failed to get cached summary {summary_id}: {e}")
            return None
            
    def _build_query_sql(self, query: SummaryQuery) -> Tuple[str, List[Any]]:
        """Build SQL query from SummaryQuery."""
        where_clauses = []
        params = []
        
        base_sql = "SELECT * FROM summaries"
        
        if query.level:
            where_clauses.append("level = ?")
            params.append(query.level.value)
            
        if query.start_date:
            where_clauses.append("time_range_start >= ?")
            params.append(query.start_date)
            
        if query.end_date:
            where_clauses.append("time_range_end <= ?")
            params.append(query.end_date)
            
        if query.tags:
            # Simple tag matching - in production you'd want more sophisticated JSON querying
            tag_conditions = []
            for tag in query.tags:
                tag_conditions.append("tags LIKE ?")
                params.append(f'%"{tag}"%')
            where_clauses.append(f"({' OR '.join(tag_conditions)})")
            
        if where_clauses:
            base_sql += " WHERE " + " AND ".join(where_clauses)
            
        # Order by time range start (most recent first)
        base_sql += " ORDER BY time_range_start DESC"
        
        # Apply limit
        base_sql += f" LIMIT {query.limit}"
        
        return base_sql, params
        
    async def _execute_query(self, sql: str, params: List[Any]) -> List[Dict[str, Any]]:
        """Execute SQL query and return results."""
        def execute():
            with self.db_lock:
                with sqlite3.connect(str(self.db_path)) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.execute(sql, params)
                    return [dict(row) for row in cursor.fetchall()]
                    
        return await asyncio.to_thread(execute)
        
    async def _update_summary_relationships(self, summary: AnySummary):
        """Update summary relationship table."""
        if not summary.metadata.parent_summaries:
            return
            
        # Insert relationships
        sql = """
        INSERT OR REPLACE INTO summary_relationships (parent_id, child_id, relationship_type)
        VALUES (?, ?, 'aggregation')
        """
        
        def execute_relationships():
            with self.db_lock:
                with sqlite3.connect(str(self.db_path)) as conn:
                    for parent_id in summary.metadata.parent_summaries:
                        conn.execute(sql, [parent_id, summary.metadata.summary_id])
                    conn.commit()
                    
        await asyncio.to_thread(execute_relationships)
        
    async def _delete_summary_metadata(self, summary_id: str):
        """Delete summary metadata from database."""
        sql = "DELETE FROM summaries WHERE id = ?"
        rel_sql = "DELETE FROM summary_relationships WHERE parent_id = ? OR child_id = ?"
        
        def execute_delete():
            with self.db_lock:
                with sqlite3.connect(str(self.db_path)) as conn:
                    conn.execute(rel_sql, [summary_id, summary_id])
                    conn.execute(sql, [summary_id])
                    conn.commit()
                    
        await asyncio.to_thread(execute_delete)
        
    async def _record_retrieval_time(self, summary_id: str, start_time: datetime):
        """Record retrieval time for performance monitoring."""
        retrieval_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        # In a production system, you might want to store this in a time-series database
        logger.debug(f"Retrieved summary {summary_id} in {retrieval_time:.2f}ms")