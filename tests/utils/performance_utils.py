import statistics
from typing import List, Dict, Any

class PerformanceAnalyzer:
    """Comprehensive performance analysis for Threat Hunter Pro."""
    
    @staticmethod
    def analyze_query_performance(performance_data: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Analyze performance metrics for a set of queries.
        
        Args:
            performance_data: List of performance metric dictionaries
        
        Returns:
            Dictionary with performance statistics
        """
        execution_times = [data['execution_time_ms'] for data in performance_data]
        memory_usages = [data['memory_usage_mb'] for data in performance_data]
        cpu_usages = [data['cpu_usage_percent'] for data in performance_data]
        
        return {
            'query_count': len(performance_data),
            'avg_execution_time_ms': statistics.mean(execution_times),
            'median_execution_time_ms': statistics.median(execution_times),
            'max_execution_time_ms': max(execution_times),
            'min_execution_time_ms': min(execution_times),
            
            'avg_memory_usage_mb': statistics.mean(memory_usages),
            'median_memory_usage_mb': statistics.median(memory_usages),
            'max_memory_usage_mb': max(memory_usages),
            
            'avg_cpu_usage_percent': statistics.mean(cpu_usages),
            'median_cpu_usage_percent': statistics.median(cpu_usages),
            'max_cpu_usage_percent': max(cpu_usages)
        }
    
    @staticmethod
    def calculate_token_reduction_efficiency(
        original_tokens: int, 
        reduced_tokens: int
    ) -> float:
        """
        Calculate token reduction efficiency.
        
        Args:
            original_tokens: Number of tokens before reduction
            reduced_tokens: Number of tokens after reduction
        
        Returns:
            Token reduction efficiency percentage
        """
        if original_tokens == 0:
            return 0.0
        
        reduction_percentage = 1 - (reduced_tokens / original_tokens)
        return max(0.0, min(1.0, reduction_percentage))
EOL < /dev/null
