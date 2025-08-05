"""
Custom exceptions for the RAG system.

This module defines all custom exceptions used throughout the RAG pipeline,
providing structured error handling and meaningful error messages.
"""


class RAGException(Exception):
    """
    Base exception for all RAG-related errors.
    
    This is the root exception that all other RAG exceptions inherit from,
    allowing for broad exception handling when needed.
    """
    
    def __init__(self, message: str, error_code: str = None, details: dict = None):
        self.message = message
        self.error_code = error_code or "RAG_GENERAL_ERROR"  
        self.details = details or {}
        super().__init__(self.message)


class SearchException(RAGException):
    """
    Exception raised during search operations.
    
    This includes errors from vector search, keyword search, hybrid search,
    and agentic search operations.
    """
    
    def __init__(self, message: str, search_strategy: str = None, query: str = None, **kwargs):
        self.search_strategy = search_strategy
        self.query = query
        super().__init__(message, error_code="SEARCH_ERROR", **kwargs)


class SummarizationException(RAGException):
    """
    Exception raised during summarization operations.
    
    This includes errors from cluster summarization, temporal aggregation,
    and hierarchical summary generation.
    """
    
    def __init__(self, message: str, scope: str = None, content_count: int = None, **kwargs):
        self.scope = scope
        self.content_count = content_count
        super().__init__(message, error_code="SUMMARIZATION_ERROR", **kwargs)


class RelationshipException(RAGException):
    """
    Exception raised during relationship analysis operations.
    
    This includes errors from entity relationship detection, correlation analysis,
    and relationship graph generation.
    """
    
    def __init__(self, message: str, entities: list = None, timeframe: str = None, **kwargs):
        self.entities = entities or []
        self.timeframe = timeframe
        super().__init__(message, error_code="RELATIONSHIP_ERROR", **kwargs)


class TrendException(RAGException):
    """
    Exception raised during trend analysis operations.
    
    This includes errors from pattern analysis, anomaly detection,
    and forecasting operations.
    """
    
    def __init__(self, message: str, patterns: list = None, period: str = None, **kwargs):
        self.patterns = patterns or []
        self.period = period
        super().__init__(message, error_code="TREND_ERROR", **kwargs)


class ExplanationException(RAGException):
    """
    Exception raised during explanation generation operations.
    
    This includes errors from evidence analysis, reasoning generation,
    and citation extraction.
    """
    
    def __init__(self, message: str, findings: dict = None, evidence_count: int = None, **kwargs):
        self.findings = findings or {}
        self.evidence_count = evidence_count
        super().__init__(message, error_code="EXPLANATION_ERROR", **kwargs)


class AgenticSearchException(RAGException):
    """
    Exception raised during agentic search operations.
    
    This includes errors from multi-turn search, query refinement,
    and iterative search processes.
    """
    
    def __init__(self, message: str, iteration: int = None, refinement_query: str = None, **kwargs):
        self.iteration = iteration
        self.refinement_query = refinement_query
        super().__init__(message, error_code="AGENTIC_SEARCH_ERROR", **kwargs)


class BudgetExhaustedError(RAGException):
    """
    Exception raised when search budget constraints are exceeded.
    
    This includes token limits, time limits, and iteration limits
    during search operations.
    """
    
    def __init__(self, message: str, budget_type: str = None, limit_exceeded: str = None, **kwargs):
        self.budget_type = budget_type
        self.limit_exceeded = limit_exceeded
        super().__init__(message, error_code="BUDGET_EXHAUSTED", **kwargs)


class SecurityException(RAGException):
    """
    Exception raised for security-related issues.
    
    This includes PII detection failures, redaction errors, and
    security policy violations.
    """
    
    def __init__(self, message: str, security_issue: str = None, content_hash: str = None, **kwargs):
        self.security_issue = security_issue
        self.content_hash = content_hash
        super().__init__(message, error_code="SECURITY_ERROR", **kwargs)


class ConfigurationException(RAGException):
    """
    Exception raised for configuration-related issues.
    
    This includes missing configuration, invalid settings, and
    initialization failures.
    """
    
    def __init__(self, message: str, config_key: str = None, config_value: str = None, **kwargs):
        self.config_key = config_key
        self.config_value = config_value
        super().__init__(message, error_code="CONFIGURATION_ERROR", **kwargs)


class IntegrationException(RAGException):
    """
    Exception raised for integration-related issues.
    
    This includes external service failures, API errors, and
    data source connectivity issues.
    """
    
    def __init__(self, message: str, service_name: str = None, endpoint: str = None, **kwargs):
        self.service_name = service_name
        self.endpoint = endpoint
        super().__init__(message, error_code="INTEGRATION_ERROR", **kwargs)


class ValidationException(RAGException):
    """
    Exception raised for input validation failures.
    
    This includes invalid query formats, malformed data, and
    constraint violations.
    """
    
    def __init__(self, message: str, field_name: str = None, field_value: str = None, **kwargs):
        self.field_name = field_name
        self.field_value = field_value
        super().__init__(message, error_code="VALIDATION_ERROR", **kwargs)


class CacheException(RAGException):
    """
    Exception raised for cache-related issues.
    
    This includes cache misses, serialization errors, and
    cache invalidation failures.
    """
    
    def __init__(self, message: str, cache_key: str = None, operation: str = None, **kwargs):
        self.cache_key = cache_key
        self.operation = operation
        super().__init__(message, error_code="CACHE_ERROR", **kwargs)


# Utility functions for exception handling
def wrap_exception(func):
    """
    Decorator to wrap functions and convert generic exceptions to RAG exceptions.
    
    This helps maintain consistent exception handling across the RAG pipeline.
    """
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except RAGException:
            # Re-raise RAG exceptions as-is
            raise
        except Exception as e:
            # Convert generic exceptions to RAG exceptions
            raise RAGException(f"Unexpected error in {func.__name__}: {str(e)}")
    
    return wrapper


def log_exception(logger, exception: RAGException, context: dict = None):
    """
    Log a RAG exception with structured information.
    
    Args:
        logger: Logger instance to use
        exception: The RAG exception to log
        context: Additional context information
    """
    context = context or {}
    
    log_data = {
        'error_code': exception.error_code,
        'message': exception.message,
        'details': exception.details,
        'context': context
    }
    
    # Add specific fields based on exception type
    if isinstance(exception, SearchException):
        log_data.update({
            'search_strategy': exception.search_strategy,
            'query': exception.query
        })
    elif isinstance(exception, SummarizationException):
        log_data.update({
            'scope': exception.scope,
            'content_count': exception.content_count
        })
    elif isinstance(exception, AgenticSearchException):
        log_data.update({
            'iteration': exception.iteration,
            'refinement_query': exception.refinement_query
        })
    elif isinstance(exception, BudgetExhaustedError):
        log_data.update({
            'budget_type': exception.budget_type,
            'limit_exceeded': exception.limit_exceeded
        })
    elif isinstance(exception, SecurityException):
        log_data.update({
            'security_issue': exception.security_issue,
            'content_hash': exception.content_hash
        })
    
    logger.error(f"RAG Exception: {exception.error_code}", extra=log_data)