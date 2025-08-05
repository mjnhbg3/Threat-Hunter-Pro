import os
import pytest
import asyncio
from typing import Dict, Any

# Global configuration for tests
pytest_plugins = [
    'pytest_asyncio',
]

def pytest_configure(config):
    """Configure pytest with global settings."""
    config.addinivalue_line(
        "markers", 
        "integration: mark test as an integration test."
    )
    config.addinivalue_line(
        "markers", 
        "performance: mark test as a performance benchmark."
    )
    config.addinivalue_line(
        "markers", 
        "security: mark test as a security validation test."
    )

@pytest.fixture(scope='session')
def test_config() -> Dict[str, Any]:
    """Provide a consistent test configuration."""
    return {
        'BASE_URL': os.getenv('TEST_BASE_URL', 'http://localhost:8000'),
        'MAX_QUERY_LATENCY_MS': 2000,  # 2-second max latency
        'MIN_COVERAGE_PERCENTAGE': 90,
        'MAX_MEMORY_INCREASE_PERCENT': 30,
        'MAX_CPU_INCREASE_PERCENT': 20,
        'TOKEN_REDUCTION_TARGET': 0.85,  # 85% reduction target
    }

@pytest.fixture(scope='function')
async def async_client():
    """Async HTTP client for API testing."""
    import httpx
    async with httpx.AsyncClient() as client:
        yield client

@pytest.fixture(scope='session')
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
EOL < /dev/null
