"""
Nightly job orchestration for hierarchical summarization.

This module handles the automated generation of hierarchical summaries through
scheduled background jobs. It includes dependency management, failure recovery,
parallel processing, and comprehensive monitoring to ensure reliable operation
of the summarization pipeline.
"""

import asyncio
import logging
import json
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime, date, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import traceback
from pathlib import Path
import threading
import signal
import sys

from ..config import DB_DIR
from ..state import vector_lock
from ..vector_db import search_vector_db
from ..persistence import save_dashboard_data
from .models import (
    ClusterSummary, DailySummary, WeeklySummary, MonthlySummary, QuarterlySummary,
    SummaryLevel, SummaryConfig, SummaryMetadata
)
from .cluster_summarizer import ClusterSummarizer
from .temporal_aggregator import TemporalAggregator
from .summary_storage import SummaryStorage

logger = logging.getLogger(__name__)


class JobStatus(Enum):
    """Status of a summarization job."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"


@dataclass
class JobResult:
    """Result of a summarization job."""
    job_id: str
    job_type: str
    status: JobStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    error_message: Optional[str] = None
    summaries_created: int = 0
    processing_time_ms: int = 0
    retry_count: int = 0
    dependencies_met: bool = True
    

@dataclass
class JobDefinition:
    """Definition of a summarization job."""
    job_id: str
    job_type: str  # 'cluster', 'daily', 'weekly', 'monthly', 'quarterly'
    target_date: date
    dependencies: List[str]  # Job IDs this job depends on
    priority: int = 5  # Lower number = higher priority
    max_retries: int = 3
    timeout_minutes: int = 30
    

class DependencyManager:
    """Manages job dependencies and execution order."""
    
    def __init__(self):
        self.job_results: Dict[str, JobResult] = {}
        self.dependency_graph: Dict[str, Set[str]] = {}
        self.reverse_dependencies: Dict[str, Set[str]] = {}
        
    def add_job(self, job_def: JobDefinition):
        """Add a job to the dependency graph."""
        self.dependency_graph[job_def.job_id] = set(job_def.dependencies)
        
        # Build reverse dependency mapping
        for dep in job_def.dependencies:
            if dep not in self.reverse_dependencies:
                self.reverse_dependencies[dep] = set()
            self.reverse_dependencies[dep].add(job_def.job_id)
            
    def can_execute_job(self, job_id: str) -> bool:
        """Check if a job can be executed (all dependencies completed)."""
        dependencies = self.dependency_graph.get(job_id, set())
        
        for dep_id in dependencies:
            dep_result = self.job_results.get(dep_id)
            if not dep_result or dep_result.status != JobStatus.COMPLETED:
                return False
                
        return True
        
    def mark_job_completed(self, job_id: str, result: JobResult):
        """Mark a job as completed."""
        self.job_results[job_id] = result
        
    def get_ready_jobs(self, all_jobs: List[JobDefinition]) -> List[JobDefinition]:
        """Get all jobs that are ready to execute."""
        ready_jobs = []
        
        for job in all_jobs:
            if (job.job_id not in self.job_results and 
                self.can_execute_job(job.job_id)):
                ready_jobs.append(job)
                
        # Sort by priority (lower number = higher priority)
        ready_jobs.sort(key=lambda x: x.priority)
        return ready_jobs
        
    def get_failed_dependencies(self, job_id: str) -> List[str]:
        """Get list of failed dependencies for a job."""
        failed_deps = []
        dependencies = self.dependency_graph.get(job_id, set())
        
        for dep_id in dependencies:
            dep_result = self.job_results.get(dep_id)
            if dep_result and dep_result.status == JobStatus.FAILED:
                failed_deps.append(dep_id)
                
        return failed_deps


class JobExecutor:
    """Executes individual summarization jobs."""
    
    def __init__(self, config: SummaryConfig, cluster_summarizer: ClusterSummarizer,
                 temporal_aggregator: TemporalAggregator, storage: SummaryStorage):
        self.config = config
        self.cluster_summarizer = cluster_summarizer
        self.temporal_aggregator = temporal_aggregator
        self.storage = storage
        self.execution_stats = {
            'jobs_executed': 0,
            'jobs_failed': 0,
            'total_processing_time_ms': 0
        }
        
    async def execute_cluster_job(self, job_def: JobDefinition) -> JobResult:
        """Execute a cluster summarization job."""
        start_time = datetime.utcnow()
        result = JobResult(
            job_id=job_def.job_id,
            job_type=job_def.job_type,
            status=JobStatus.RUNNING,
            start_time=start_time
        )
        
        try:
            logger.info(f"Starting cluster job {job_def.job_id} for {job_def.target_date}")
            
            # Get logs for the target date
            logs = await self._get_logs_for_date(job_def.target_date)
            
            if not logs:
                logger.info(f"No logs found for {job_def.target_date}, skipping cluster job")
                result.status = JobStatus.SKIPPED
                result.end_time = datetime.utcnow()
                return result
                
            # Cluster the logs
            clusters = await self.cluster_summarizer.cluster_logs(logs)
            
            # Generate summaries for each cluster
            cluster_summaries = []
            for cluster in clusters:
                try:
                    summary = await self.cluster_summarizer.summarize_cluster(cluster)
                    cluster_summaries.append(summary)
                except Exception as e:
                    logger.error(f"Failed to summarize cluster {cluster.cluster_id}: {e}")
                    continue
                    
            # Store cluster summaries
            storage_results = await self.storage.batch_store_summaries(cluster_summaries)
            successful_stores = sum(1 for success in storage_results.values() if success)
            
            result.summaries_created = successful_stores
            result.status = JobStatus.COMPLETED
            result.end_time = datetime.utcnow()
            result.processing_time_ms = int((result.end_time - start_time).total_seconds() * 1000)
            
            logger.info(f"Cluster job {job_def.job_id} completed: {successful_stores} summaries created")
            
        except Exception as e:
            result.status = JobStatus.FAILED
            result.error_message = str(e)
            result.end_time = datetime.utcnow()
            logger.error(f"Cluster job {job_def.job_id} failed: {e}")
            logger.error(traceback.format_exc())
            
        return result
        
    async def execute_daily_job(self, job_def: JobDefinition) -> JobResult:
        """Execute a daily summarization job."""
        start_time = datetime.utcnow()
        result = JobResult(
            job_id=job_def.job_id,
            job_type=job_def.job_type,
            status=JobStatus.RUNNING,
            start_time=start_time
        )
        
        try:
            logger.info(f"Starting daily job {job_def.job_id} for {job_def.target_date}")
            
            # Get cluster summaries for the target date
            cluster_summaries = await self.storage.get_summaries_by_time_range(
                SummaryLevel.CLUSTER,
                datetime.combine(job_def.target_date, datetime.min.time()),
                datetime.combine(job_def.target_date, datetime.max.time())
            )
            
            if not cluster_summaries:
                logger.info(f"No cluster summaries found for {job_def.target_date}, creating empty daily summary")
                
            # Generate daily summary
            daily_summary = await self.temporal_aggregator.aggregate_to_daily(
                cluster_summaries, job_def.target_date
            )
            
            # Store daily summary
            success = await self.storage.store_summary(daily_summary)
            
            result.summaries_created = 1 if success else 0
            result.status = JobStatus.COMPLETED if success else JobStatus.FAILED
            result.end_time = datetime.utcnow()
            result.processing_time_ms = int((result.end_time - start_time).total_seconds() * 1000)
            
            if not success:
                result.error_message = "Failed to store daily summary"
                
            logger.info(f"Daily job {job_def.job_id} completed: {'success' if success else 'failed'}")
            
        except Exception as e:
            result.status = JobStatus.FAILED
            result.error_message = str(e)
            result.end_time = datetime.utcnow()
            logger.error(f"Daily job {job_def.job_id} failed: {e}")
            logger.error(traceback.format_exc())
            
        return result
        
    async def execute_weekly_job(self, job_def: JobDefinition) -> JobResult:
        """Execute a weekly summarization job."""
        start_time = datetime.utcnow()
        result = JobResult(
            job_id=job_def.job_id,
            job_type=job_def.job_type,
            status=JobStatus.RUNNING,
            start_time=start_time
        )
        
        try:
            logger.info(f"Starting weekly job {job_def.job_id} for week starting {job_def.target_date}")
            
            # Calculate week range
            week_start = job_def.target_date
            week_end = week_start + timedelta(days=6)
            
            # Get daily summaries for the week
            daily_summaries = await self.storage.get_summaries_by_time_range(
                SummaryLevel.DAILY,
                datetime.combine(week_start, datetime.min.time()),
                datetime.combine(week_end, datetime.max.time())
            )
            
            # Generate weekly summary
            weekly_summary = await self.temporal_aggregator.aggregate_to_weekly(
                daily_summaries, week_start
            )
            
            # Store weekly summary
            success = await self.storage.store_summary(weekly_summary)
            
            result.summaries_created = 1 if success else 0
            result.status = JobStatus.COMPLETED if success else JobStatus.FAILED
            result.end_time = datetime.utcnow()
            result.processing_time_ms = int((result.end_time - start_time).total_seconds() * 1000)
            
            if not success:
                result.error_message = "Failed to store weekly summary"
                
            logger.info(f"Weekly job {job_def.job_id} completed: {'success' if success else 'failed'}")
            
        except Exception as e:
            result.status = JobStatus.FAILED
            result.error_message = str(e)
            result.end_time = datetime.utcnow()
            logger.error(f"Weekly job {job_def.job_id} failed: {e}")
            logger.error(traceback.format_exc())
            
        return result
        
    async def execute_monthly_job(self, job_def: JobDefinition) -> JobResult:
        """Execute a monthly summarization job."""
        start_time = datetime.utcnow()
        result = JobResult(
            job_id=job_def.job_id,
            job_type=job_def.job_type,
            status=JobStatus.RUNNING,
            start_time=start_time
        )
        
        try:
            logger.info(f"Starting monthly job {job_def.job_id} for {job_def.target_date.strftime('%Y-%m')}")
            
            # Calculate month range
            month_start = job_def.target_date.replace(day=1)
            if month_start.month == 12:
                month_end = month_start.replace(year=month_start.year + 1, month=1) - timedelta(days=1)
            else:
                month_end = month_start.replace(month=month_start.month + 1) - timedelta(days=1)
                
            # Get weekly summaries for the month
            weekly_summaries = await self.storage.get_summaries_by_time_range(
                SummaryLevel.WEEKLY,
                datetime.combine(month_start, datetime.min.time()),
                datetime.combine(month_end, datetime.max.time())
            )
            
            # Generate monthly summary
            monthly_summary = await self.temporal_aggregator.aggregate_to_monthly(
                weekly_summaries, month_start.month, month_start.year
            )
            
            # Store monthly summary
            success = await self.storage.store_summary(monthly_summary)
            
            result.summaries_created = 1 if success else 0
            result.status = JobStatus.COMPLETED if success else JobStatus.FAILED
            result.end_time = datetime.utcnow()
            result.processing_time_ms = int((result.end_time - start_time).total_seconds() * 1000)
            
            if not success:
                result.error_message = "Failed to store monthly summary"
                
            logger.info(f"Monthly job {job_def.job_id} completed: {'success' if success else 'failed'}")
            
        except Exception as e:
            result.status = JobStatus.FAILED
            result.error_message = str(e)
            result.end_time = datetime.utcnow()
            logger.error(f"Monthly job {job_def.job_id} failed: {e}")
            logger.error(traceback.format_exc())
            
        return result
        
    async def execute_quarterly_job(self, job_def: JobDefinition) -> JobResult:
        """Execute a quarterly summarization job."""
        start_time = datetime.utcnow()
        result = JobResult(
            job_id=job_def.job_id,
            job_type=job_def.job_type,
            status=JobStatus.RUNNING,
            start_time=start_time
        )
        
        try:
            # Calculate quarter from target date
            quarter = ((job_def.target_date.month - 1) // 3) + 1
            year = job_def.target_date.year
            
            logger.info(f"Starting quarterly job {job_def.job_id} for Q{quarter} {year}")
            
            # Calculate quarter range
            quarter_start_month = (quarter - 1) * 3 + 1
            quarter_start = date(year, quarter_start_month, 1)
            
            if quarter == 4:
                quarter_end = date(year + 1, 1, 1) - timedelta(days=1)
            else:
                quarter_end = date(year, quarter_start_month + 3, 1) - timedelta(days=1)
                
            # Get monthly summaries for the quarter
            monthly_summaries = await self.storage.get_summaries_by_time_range(
                SummaryLevel.MONTHLY,
                datetime.combine(quarter_start, datetime.min.time()),
                datetime.combine(quarter_end, datetime.max.time())
            )
            
            # Generate quarterly summary
            quarterly_summary = await self.temporal_aggregator.aggregate_to_quarterly(
                monthly_summaries, quarter, year
            )
            
            # Store quarterly summary
            success = await self.storage.store_summary(quarterly_summary)
            
            result.summaries_created = 1 if success else 0
            result.status = JobStatus.COMPLETED if success else JobStatus.FAILED
            result.end_time = datetime.utcnow()
            result.processing_time_ms = int((result.end_time - start_time).total_seconds() * 1000)
            
            if not success:
                result.error_message = "Failed to store quarterly summary"
                
            logger.info(f"Quarterly job {job_def.job_id} completed: {'success' if success else 'failed'}")
            
        except Exception as e:
            result.status = JobStatus.FAILED
            result.error_message = str(e)
            result.end_time = datetime.utcnow()
            logger.error(f"Quarterly job {job_def.job_id} failed: {e}")
            logger.error(traceback.format_exc())
            
        return result
        
    async def execute_job(self, job_def: JobDefinition) -> JobResult:
        """Execute a job based on its type."""
        if job_def.job_type == 'cluster':
            return await self.execute_cluster_job(job_def)
        elif job_def.job_type == 'daily':
            return await self.execute_daily_job(job_def)
        elif job_def.job_type == 'weekly':
            return await self.execute_weekly_job(job_def)
        elif job_def.job_type == 'monthly':
            return await self.execute_monthly_job(job_def)
        elif job_def.job_type == 'quarterly':
            return await self.execute_quarterly_job(job_def)
        else:
            raise ValueError(f"Unknown job type: {job_def.job_type}")
            
    async def _get_logs_for_date(self, target_date: date) -> List[Dict[str, Any]]:
        """Get logs for a specific date from the vector database."""
        try:
            # This is a simplified implementation
            # In practice, you'd want more sophisticated date filtering
            
            # Search for logs with a broad query to get recent logs
            logs = await search_vector_db("*", k=10000)  # Get many logs
            
            # Filter logs by date
            filtered_logs = []
            target_datetime = datetime.combine(target_date, datetime.min.time())
            next_day = target_datetime + timedelta(days=1)
            
            for log_result in logs:
                log_metadata = log_result.get('metadata', {})
                log_timestamp_str = log_metadata.get('timestamp')
                
                if log_timestamp_str:
                    try:
                        if isinstance(log_timestamp_str, str):
                            log_timestamp = datetime.fromisoformat(log_timestamp_str.replace('Z', '+00:00'))
                        else:
                            log_timestamp = log_timestamp_str
                            
                        if target_datetime <= log_timestamp < next_day:
                            filtered_logs.append(log_metadata)
                    except Exception as e:
                        logger.debug(f"Failed to parse timestamp {log_timestamp_str}: {e}")
                        continue
                        
            logger.info(f"Found {len(filtered_logs)} logs for {target_date}")
            return filtered_logs
            
        except Exception as e:
            logger.error(f"Failed to get logs for {target_date}: {e}")
            return []


class NightlyJobScheduler:
    """
    Main scheduler for hierarchical summarization jobs.
    
    Orchestrates the execution of summarization jobs with proper dependency
    management, parallel processing, error handling, and monitoring.
    """
    
    def __init__(self, config: SummaryConfig):
        self.config = config
        self.cluster_summarizer: Optional[ClusterSummarizer] = None
        self.temporal_aggregator: Optional[TemporalAggregator] = None
        self.storage: Optional[SummaryStorage] = None
        self.job_executor: Optional[JobExecutor] = None
        self.dependency_manager = DependencyManager()
        
        self.job_history_file = Path(DB_DIR) / "job_history.json"
        self.is_running = False
        self.shutdown_event = asyncio.Event()
        
        # Performance tracking
        self.execution_stats = {
            'total_runs': 0,
            'successful_runs': 0,
            'failed_runs': 0,
            'total_summaries_created': 0,
            'avg_execution_time_ms': 0.0,
            'last_run_time': None
        }
        
    async def initialize(self, embedding_model):
        """Initialize all components."""
        # Initialize cluster summarizer
        self.cluster_summarizer = ClusterSummarizer(self.config)
        await self.cluster_summarizer.initialize(embedding_model)
        
        # Initialize temporal aggregator
        self.temporal_aggregator = TemporalAggregator(self.config)
        await self.temporal_aggregator.initialize()
        
        # Initialize storage
        self.storage = SummaryStorage(self.config)
        await self.storage.initialize()
        
        # Initialize job executor
        self.job_executor = JobExecutor(
            self.config, self.cluster_summarizer, 
            self.temporal_aggregator, self.storage
        )
        
        # Load job history
        await self._load_job_history()
        
        logger.info("NightlyJobScheduler initialized")
        
    async def run_nightly_summarization(self, target_date: Optional[date] = None) -> Dict[str, Any]:
        """
        Run the complete nightly summarization pipeline.
        
        Args:
            target_date: Optional target date (defaults to yesterday)
            
        Returns:
            Dict with execution results and statistics
        """
        if not target_date:
            target_date = date.today() - timedelta(days=1)
            
        run_start_time = datetime.utcnow()
        logger.info(f"Starting nightly summarization for {target_date}")
        
        try:
            self.is_running = True
            
            # Generate job definitions
            jobs = await self._generate_job_definitions(target_date)
            
            # Execute jobs with dependency management
            job_results = await self._execute_jobs_with_dependencies(jobs)
            
            # Update statistics
            await self._update_execution_stats(job_results, run_start_time)
            
            # Save job history
            await self._save_job_history(job_results)
            
            # Cleanup expired summaries
            cleanup_count = await self.storage.cleanup_expired_summaries()
            
            # Generate execution report
            execution_report = await self._generate_execution_report(
                target_date, job_results, cleanup_count, run_start_time
            )
            
            logger.info(f"Nightly summarization completed for {target_date}: {execution_report['summary']}")
            return execution_report
            
        except Exception as e:
            logger.error(f"Nightly summarization failed for {target_date}: {e}")
            logger.error(traceback.format_exc())
            return {
                'success': False,
                'error': str(e),
                'target_date': target_date.isoformat(),
                'execution_time_ms': int((datetime.utcnow() - run_start_time).total_seconds() * 1000)
            }
        finally:
            self.is_running = False
            
    async def _generate_job_definitions(self, target_date: date) -> List[JobDefinition]:
        """Generate job definitions for the target date with proper dependencies."""
        jobs = []
        
        # Cluster job (no dependencies)
        cluster_job = JobDefinition(
            job_id=f"cluster_{target_date.isoformat()}",
            job_type="cluster",
            target_date=target_date,
            dependencies=[],
            priority=1,  # Highest priority
            timeout_minutes=45
        )
        jobs.append(cluster_job)
        
        # Daily job (depends on cluster job)
        daily_job = JobDefinition(
            job_id=f"daily_{target_date.isoformat()}",
            job_type="daily",
            target_date=target_date,
            dependencies=[cluster_job.job_id],
            priority=2,
            timeout_minutes=30
        )
        jobs.append(daily_job)
        
        # Weekly jobs (run on Sundays, depend on daily jobs)
        if target_date.weekday() == 6:  # Sunday
            week_start = target_date - timedelta(days=6)  # Monday of the week
            
            # Collect daily job dependencies for the week
            daily_deps = []
            for i in range(7):
                day = week_start + timedelta(days=i)
                daily_deps.append(f"daily_{day.isoformat()}")
                
            weekly_job = JobDefinition(
                job_id=f"weekly_{week_start.isoformat()}",
                job_type="weekly",
                target_date=week_start,
                dependencies=daily_deps,
                priority=3,
                timeout_minutes=60
            )
            jobs.append(weekly_job)
            
        # Monthly jobs (run on last day of month, depend on weekly jobs)
        if target_date == self._last_day_of_month(target_date):
            month_start = target_date.replace(day=1)
            
            # Collect weekly job dependencies for the month
            weekly_deps = []
            current_monday = self._get_first_monday_of_month(month_start)
            while current_monday <= target_date:
                weekly_deps.append(f"weekly_{current_monday.isoformat()}")
                current_monday += timedelta(days=7)
                
            monthly_job = JobDefinition(
                job_id=f"monthly_{target_date.strftime('%Y_%m')}",
                job_type="monthly",
                target_date=month_start,
                dependencies=weekly_deps,
                priority=4,
                timeout_minutes=90
            )
            jobs.append(monthly_job)
            
        # Quarterly jobs (run on last day of quarter, depend on monthly jobs)
        if target_date == self._last_day_of_quarter(target_date):
            quarter = ((target_date.month - 1) // 3) + 1
            year = target_date.year
            
            # Collect monthly job dependencies for the quarter
            monthly_deps = []
            quarter_start_month = (quarter - 1) * 3 + 1
            for month_offset in range(3):
                month = quarter_start_month + month_offset
                monthly_deps.append(f"monthly_{year}_{month:02d}")
                
            quarterly_job = JobDefinition(
                job_id=f"quarterly_{year}_Q{quarter}",
                job_type="quarterly",
                target_date=date(year, quarter_start_month, 1),
                dependencies=monthly_deps,
                priority=5,
                timeout_minutes=120
            )
            jobs.append(quarterly_job)
            
        return jobs
        
    async def _execute_jobs_with_dependencies(self, jobs: List[JobDefinition]) -> List[JobResult]:
        """Execute jobs respecting dependency constraints."""
        # Add jobs to dependency manager
        for job in jobs:
            self.dependency_manager.add_job(job)
            
        job_results = []
        remaining_jobs = jobs.copy()
        max_parallel = min(self.config.max_concurrent_jobs, len(jobs))
        
        while remaining_jobs and not self.shutdown_event.is_set():
            # Get jobs ready to execute
            ready_jobs = self.dependency_manager.get_ready_jobs(remaining_jobs)
            
            if not ready_jobs:
                # Check if we have any jobs that can never execute due to failed dependencies
                unexecutable_jobs = []
                for job in remaining_jobs:
                    failed_deps = self.dependency_manager.get_failed_dependencies(job.job_id)
                    if failed_deps:
                        logger.error(f"Job {job.job_id} cannot execute due to failed dependencies: {failed_deps}")
                        
                        # Create failed result
                        result = JobResult(
                            job_id=job.job_id,
                            job_type=job.job_type,
                            status=JobStatus.FAILED,
                            start_time=datetime.utcnow(),
                            end_time=datetime.utcnow(),
                            error_message=f"Dependencies failed: {failed_deps}",
                            dependencies_met=False
                        )
                        job_results.append(result)
                        self.dependency_manager.mark_job_completed(job.job_id, result)
                        unexecutable_jobs.append(job)
                        
                # Remove unexecutable jobs
                for job in unexecutable_jobs:
                    remaining_jobs.remove(job)
                    
                if not unexecutable_jobs:
                    # No progress possible, wait a bit
                    await asyncio.sleep(1)
                continue
                
            # Execute ready jobs in parallel (up to max_parallel)
            batch = ready_jobs[:max_parallel]
            
            # Create timeout for batch execution
            timeout_seconds = max(job.timeout_minutes * 60 for job in batch)
            
            try:
                # Execute jobs with timeout
                tasks = [self.job_executor.execute_job(job) for job in batch]
                batch_results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=timeout_seconds
                )
                
                # Process results
                for job, result in zip(batch, batch_results):
                    if isinstance(result, Exception):
                        logger.error(f"Job {job.job_id} failed with exception: {result}")
                        result = JobResult(
                            job_id=job.job_id,
                            job_type=job.job_type,
                            status=JobStatus.FAILED,
                            start_time=datetime.utcnow(),
                            end_time=datetime.utcnow(),
                            error_message=str(result)
                        )
                        
                    job_results.append(result)
                    self.dependency_manager.mark_job_completed(job.job_id, result)
                    remaining_jobs.remove(job)
                    
            except asyncio.TimeoutError:
                logger.error(f"Batch execution timed out after {timeout_seconds}s")
                
                # Mark all jobs in batch as failed
                for job in batch:
                    result = JobResult(
                        job_id=job.job_id,
                        job_type=job.job_type,
                        status=JobStatus.FAILED,
                        start_time=datetime.utcnow(),
                        end_time=datetime.utcnow(),
                        error_message=f"Job timed out after {timeout_seconds}s"
                    )
                    job_results.append(result)
                    self.dependency_manager.mark_job_completed(job.job_id, result)
                    remaining_jobs.remove(job)
                    
        return job_results
        
    async def _update_execution_stats(self, job_results: List[JobResult], 
                                    run_start_time: datetime):
        """Update execution statistics."""
        self.execution_stats['total_runs'] += 1
        
        successful_jobs = [r for r in job_results if r.status == JobStatus.COMPLETED]
        failed_jobs = [r for r in job_results if r.status == JobStatus.FAILED]
        
        if len(successful_jobs) > len(failed_jobs):
            self.execution_stats['successful_runs'] += 1
        else:
            self.execution_stats['failed_runs'] += 1
            
        total_summaries = sum(r.summaries_created for r in job_results)
        self.execution_stats['total_summaries_created'] += total_summaries
        
        run_time_ms = int((datetime.utcnow() - run_start_time).total_seconds() * 1000)
        
        # Update average execution time
        total_runs = self.execution_stats['total_runs']
        current_avg = self.execution_stats['avg_execution_time_ms']
        self.execution_stats['avg_execution_time_ms'] = (
            (current_avg * (total_runs - 1) + run_time_ms) / total_runs
        )
        
        self.execution_stats['last_run_time'] = datetime.utcnow().isoformat()
        
    async def _generate_execution_report(self, target_date: date, 
                                       job_results: List[JobResult],
                                       cleanup_count: int,
                                       run_start_time: datetime) -> Dict[str, Any]:
        """Generate comprehensive execution report."""
        successful_jobs = [r for r in job_results if r.status == JobStatus.COMPLETED]
        failed_jobs = [r for r in job_results if r.status == JobStatus.FAILED]
        skipped_jobs = [r for r in job_results if r.status == JobStatus.SKIPPED]
        
        total_summaries = sum(r.summaries_created for r in job_results)
        total_processing_time = sum(r.processing_time_ms for r in job_results)
        run_time_ms = int((datetime.utcnow() - run_start_time).total_seconds() * 1000)
        
        # Get storage stats
        storage_stats = await self.storage.get_storage_stats()
        
        report = {
            'success': len(successful_jobs) > len(failed_jobs),
            'target_date': target_date.isoformat(),
            'execution_time_ms': run_time_ms,
            'jobs': {
                'total': len(job_results),
                'successful': len(successful_jobs),
                'failed': len(failed_jobs),
                'skipped': len(skipped_jobs)
            },
            'summaries_created': total_summaries,
            'processing_time_ms': total_processing_time,
            'cleanup_count': cleanup_count,
            'storage_stats': asdict(storage_stats),
            'job_details': [asdict(result) for result in job_results],
            'summary': f"Created {total_summaries} summaries, {len(successful_jobs)}/{len(job_results)} jobs successful"
        }
        
        return report
        
    async def _save_job_history(self, job_results: List[JobResult]):
        """Save job execution history."""
        try:
            history_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'job_results': [asdict(result) for result in job_results],
                'execution_stats': self.execution_stats.copy()
            }
            
            # Load existing history
            history = []
            if self.job_history_file.exists():
                try:
                    async with aiofiles.open(self.job_history_file, 'r') as f:
                        content = await f.read()
                        history = json.loads(content) if content.strip() else []
                except Exception as e:
                    logger.warning(f"Failed to load job history: {e}")
                    
            # Add new entry and limit history size
            history.append(history_entry)
            history = history[-100:]  # Keep last 100 entries
            
            # Save updated history
            async with aiofiles.open(self.job_history_file, 'w') as f:
                await f.write(json.dumps(history, indent=2))
                
        except Exception as e:
            logger.error(f"Failed to save job history: {e}")
            
    async def _load_job_history(self):
        """Load job execution history."""
        try:
            if self.job_history_file.exists():
                async with aiofiles.open(self.job_history_file, 'r') as f:
                    content = await f.read()
                    if content.strip():
                        history = json.loads(content)
                        if history:
                            # Load latest execution stats
                            latest_entry = history[-1]
                            if 'execution_stats' in latest_entry:
                                self.execution_stats.update(latest_entry['execution_stats'])
                                
        except Exception as e:
            logger.warning(f"Failed to load job history: {e}")
            
    def _last_day_of_month(self, target_date: date) -> date:
        """Get the last day of the month for the given date."""
        if target_date.month == 12:
            return date(target_date.year + 1, 1, 1) - timedelta(days=1)
        else:
            return date(target_date.year, target_date.month + 1, 1) - timedelta(days=1)
            
    def _last_day_of_quarter(self, target_date: date) -> date:
        """Get the last day of the quarter for the given date."""
        quarter = ((target_date.month - 1) // 3) + 1
        
        if quarter == 1:
            return date(target_date.year, 3, 31)
        elif quarter == 2:
            return date(target_date.year, 6, 30)
        elif quarter == 3:
            return date(target_date.year, 9, 30)
        else:
            return date(target_date.year, 12, 31)
            
    def _get_first_monday_of_month(self, month_start: date) -> date:
        """Get the first Monday of the month."""
        # Find the first Monday on or after month_start
        days_until_monday = (7 - month_start.weekday()) % 7
        if month_start.weekday() == 0:  # Already Monday
            return month_start
        else:
            return month_start + timedelta(days=days_until_monday)
            
    async def get_job_status(self) -> Dict[str, Any]:
        """Get current job execution status."""
        return {
            'is_running': self.is_running,
            'execution_stats': self.execution_stats.copy(),
            'last_run_summary': f"Last run: {self.execution_stats.get('last_run_time', 'Never')}"
        }
        
    async def shutdown(self):
        """Gracefully shutdown the scheduler."""
        logger.info("Shutting down NightlyJobScheduler...")
        self.shutdown_event.set()
        
        # Wait for any running jobs to complete (with timeout)
        if self.is_running:
            try:
                await asyncio.wait_for(
                    self._wait_for_completion(), 
                    timeout=300  # 5 minute timeout
                )
            except asyncio.TimeoutError:
                logger.warning("Shutdown timeout exceeded, forcing shutdown")
                
        logger.info("NightlyJobScheduler shutdown complete")
        
    async def _wait_for_completion(self):
        """Wait for running jobs to complete."""
        while self.is_running:
            await asyncio.sleep(1)