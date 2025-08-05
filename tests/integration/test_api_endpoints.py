import pytest
import httpx
from typing import Dict, Any

from ..utils.test_utils import TestPerformanceTracker, validate_performance_metrics
from ..utils.data_generator import TestDataGenerator

class TestAPIEndpoints:
    """Comprehensive API endpoint testing for Threat Hunter Pro."""
    
    @pytest.mark.integration
    @pytest.mark.parametrize('endpoint', [
        '/logs/search', 
        '/threat/analyze', 
        '/summary/generate', 
        '/rag/retrieve', 
        '/security/status'
    ])
    async def test_endpoint_performance(
        self, 
        async_client: httpx.AsyncClient, 
        test_config: Dict[str, Any], 
        endpoint: str
    ):
        """
        Test performance and functionality of API endpoints.
        
        Validates:
        - Endpoint responds successfully
        - Performance meets defined thresholds
        - Response structure is correct
        """
        data_generator = TestDataGenerator()
        query_scenarios = data_generator.generate_query_scenarios()
        
        for scenario in query_scenarios:
            performance_metrics = await TestPerformanceTracker.measure_performance(
                async_client.post, 
                url=f"{test_config['BASE_URL']}{endpoint}", 
                json=scenario
            )
            
            # Validate metrics
            assert validate_performance_metrics(performance_metrics, test_config),                 f"Performance metrics for {endpoint} failed validation"
            
            # Validate response
            response = performance_metrics['result']
            assert response.status_code == 200,                 f"Endpoint {endpoint} did not return 200 OK"
            
            response_data = response.json()
            assert isinstance(response_data, dict),                 f"Response from {endpoint} is not a dictionary"
    
    @pytest.mark.integration
    async def test_comprehensive_workflow(
        self, 
        async_client: httpx.AsyncClient, 
        test_config: Dict[str, Any]
    ):
        """
        Test a comprehensive end-to-end threat hunting workflow.
        
        Validates entire data flow:
        - Log ingestion
        - Analysis
        - Summary generation
        - RAG retrieval
        """
        data_generator = TestDataGenerator()
        log_batch = data_generator.generate_log_batch(count=50)
        
        # Log ingestion
        ingest_metrics = await TestPerformanceTracker.measure_performance(
            async_client.post, 
            url=f"{test_config['BASE_URL']}/logs/ingest", 
            json={'logs': log_batch}
        )
        assert validate_performance_metrics(ingest_metrics, test_config)
        
        # Trigger analysis
        analysis_metrics = await TestPerformanceTracker.measure_performance(
            async_client.post, 
            url=f"{test_config['BASE_URL']}/threat/analyze", 
            json={'batch_id': ingest_metrics['result'].json()['batch_id']}
        )
        assert validate_performance_metrics(analysis_metrics, test_config)
        
        # Generate summary
        summary_metrics = await TestPerformanceTracker.measure_performance(
            async_client.post, 
            url=f"{test_config['BASE_URL']}/summary/generate", 
            json={'analysis_id': analysis_metrics['result'].json()['analysis_id']}
        )
        assert validate_performance_metrics(summary_metrics, test_config)
EOL < /dev/null
