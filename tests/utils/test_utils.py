import asyncio
import time
import psutil
import logging
from typing import Callable, Any, Awaitable

class TestPerformanceTracker:
    """Utility for tracking test performance metrics."""
    
    @staticmethod
    async def measure_performance(
        func: Callable[..., Awaitable[Any]], 
        *args, 
        **kwargs
    ) -> dict:
        """
        Measure performance of an async function.
        
        Args:
            func: Async function to measure
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function
        
        Returns:
            Dictionary with performance metrics
        """
        start_memory = psutil.Process().memory_info().rss / (1024 * 1024)  # MB
        start_cpu = psutil.cpu_percent()
        start_time = time.time()
        
        try:
            result = await func(*args, **kwargs)
        except Exception as e:
            logging.error(f"Performance test failed: {e}")
            raise
        
        end_time = time.time()
        end_memory = psutil.Process().memory_info().rss / (1024 * 1024)  # MB
        end_cpu = psutil.cpu_percent()
        
        return {
            'execution_time_ms': (end_time - start_time) * 1000,
            'memory_usage_mb': end_memory - start_memory,
            'cpu_usage_percent': end_cpu - start_cpu,
            'result': result
        }

def validate_performance_metrics(metrics: dict, config: dict) -> bool:
    """
    Validate performance metrics against configuration thresholds.
    
    Args:
        metrics: Performance metrics dictionary
        config: Test configuration dictionary
    
    Returns:
        Boolean indicating if metrics meet performance requirements
    """
    checks = [
        metrics['execution_time_ms'] <= config['MAX_QUERY_LATENCY_MS'],
        metrics['memory_usage_mb'] <= config['MAX_MEMORY_INCREASE_PERCENT'],
        metrics['cpu_usage_percent'] <= config['MAX_CPU_INCREASE_PERCENT']
    ]
    
    return all(checks)
EOL < /dev/null
