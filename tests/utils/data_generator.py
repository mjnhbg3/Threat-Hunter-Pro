import random
from typing import List, Dict, Any
from faker import Faker

class TestDataGenerator:
    """Generate synthetic test data for Threat Hunter Pro."""
    
    def __init__(self):
        self.fake = Faker()
    
    def generate_log_entry(self) -> Dict[str, Any]:
        """
        Generate a synthetic log entry mimicking threat hunting scenarios.
        
        Returns:
            Dictionary representing a log entry
        """
        return {
            'timestamp': self.fake.date_time_this_year(),
            'source_ip': self.fake.ipv4(),
            'destination_ip': self.fake.ipv4(),
            'source_port': random.randint(1024, 65535),
            'destination_port': random.randint(1024, 65535),
            'protocol': random.choice(['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']),
            'event_type': random.choice([
                'network_connection', 
                'login_attempt', 
                'file_access', 
                'process_execution'
            ]),
            'severity': random.choice(['low', 'medium', 'high', 'critical']),
            'details': self.fake.text(max_nb_chars=500)
        }
    
    def generate_log_batch(self, count: int = 100) -> List[Dict[str, Any]]:
        """
        Generate a batch of log entries.
        
        Args:
            count: Number of log entries to generate
        
        Returns:
            List of log entry dictionaries
        """
        return [self.generate_log_entry() for _ in range(count)]
    
    def generate_query_scenarios(self) -> List[Dict[str, Any]]:
        """
        Generate diverse query scenarios for testing.
        
        Returns:
            List of query scenario dictionaries
        """
        scenarios = [
            {
                'scenario_name': 'network_anomaly_detection',
                'query_type': 'advanced_search',
                'filters': {
                    'severity': 'high',
                    'event_type': 'network_connection',
                    'protocol': ['TCP', 'UDP']
                }
            },
            {
                'scenario_name': 'login_attempt_analysis',
                'query_type': 'correlation',
                'filters': {
                    'event_type': 'login_attempt',
                    'severity': ['medium', 'high']
                }
            },
            # Add more complex query scenarios
        ]
        return scenarios
EOL < /dev/null
