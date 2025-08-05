# Hierarchical Summarization System for Threat Hunter Pro

## Overview

The Hierarchical Summarization System is a comprehensive multi-level summarization solution that dramatically reduces query token usage while maintaining answer quality through intelligent clustering and progressive summarization. It provides efficient querying at different time granularities and supports automated background processing.

## Key Features

### 🎯 **Multi-Level Summary Hierarchy**
- **Cluster Summaries**: Groups of 5-50 related logs with pattern detection
- **Daily Summaries**: Aggregated daily security posture with trend analysis  
- **Weekly Summaries**: Week-over-week comparisons and campaign detection
- **Monthly Summaries**: Strategic security assessment and policy effectiveness
- **Quarterly Summaries**: Executive reporting and annual planning inputs

### 🤖 **Intelligent Processing**
- **Smart Clustering**: Semantic similarity, temporal proximity, and entity relationships
- **AI-Powered Summarization**: Uses Gemini models for high-quality summaries
- **Progressive Aggregation**: Each level builds insights from lower levels
- **Entity Tracking**: Comprehensive entity activity analysis across time periods

### ⚡ **Performance Optimization**
- **Token Reduction**: Target 90% fewer tokens while maintaining answer quality
- **Efficient Storage**: Time-partitioned indexing with compression
- **Redis Caching**: Fast retrieval for frequently accessed summaries
- **Parallel Processing**: Concurrent job execution with dependency management

### 🔄 **Automated Operations**
- **Nightly Jobs**: Automated summarization with dependency resolution
- **Incremental Processing**: Only processes new/changed data
- **Failure Recovery**: Robust error handling and retry mechanisms
- **Quality Assurance**: Validation and scoring of generated summaries

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Hierarchical Summary System                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌─────────────────┐    ┌─────────────────┐ │
│  │   Raw Logs   │───▶│ Cluster         │───▶│   Daily         │ │
│  │   (Vector    │    │ Summarizer      │    │ Aggregator      │ │
│  │   Database)  │    │                 │    │                 │ │
│  └──────────────┘    └─────────────────┘    └─────────────────┘ │
│                                                      │           │
│  ┌──────────────┐    ┌─────────────────┐            ▼           │
│  │  Time-       │◀───│  Summary        │    ┌─────────────────┐ │
│  │  Partitioned │    │  Storage        │◀───│   Temporal      │ │
│  │  Storage     │    │  (SQLite +      │    │  Aggregator     │ │
│  │  + Redis     │    │   Redis)        │    │  (Weekly,       │ │
│  │  Cache       │    │                 │    │   Monthly,      │ │
│  └──────────────┘    └─────────────────┘    │   Quarterly)    │ │
│                                              └─────────────────┘ │
│                                                      ▲           │
│  ┌──────────────┐    ┌─────────────────┐            │           │
│  │   Nightly    │───▶│  Job Scheduler  │────────────┘           │
│  │   Jobs       │    │  (Dependency    │                        │
│  │  (Cron/GH    │    │   Management)   │                        │
│  │   Actions)   │    │                 │                        │
│  └──────────────┘    └─────────────────┘                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────────────┐
                    │     RAG Interface           │
                    │   (Query Routing &          │
                    │    Token Optimization)      │
                    └─────────────────────────────┘
```

## Installation & Setup

### Dependencies

The hierarchical summarization system requires additional Python packages:

```bash
# Install core dependencies
pip install scikit-learn hdbscan redis aiofiles

# Optional: For advanced clustering
pip install umap-learn

# Install existing Threat Hunter Pro dependencies
pip install -r requirements.txt
```

### Configuration

The system uses `SummaryConfig` for configuration. Key settings:

```python
from hierarchical_summary.models import SummaryConfig

config = SummaryConfig(
    # Clustering configuration  
    cluster_size_min=5,
    cluster_size_max=50,
    clustering_algorithm="hdbscan",  # or "dbscan", "kmeans", "semantic"
    similarity_threshold=0.7,
    
    # Summarization configuration
    summary_model="gemini-2.5-flash",
    max_summary_tokens=2000,
    quality_threshold=0.7,
    
    # Storage configuration
    compression_enabled=True,
    retention_days_cluster=90,
    retention_days_daily=365,
    retention_days_weekly=730,
    retention_days_monthly=1825,
    retention_days_quarterly=3650,
    
    # Performance configuration
    parallel_processing=True,
    max_concurrent_jobs=4,
    redis_caching=True,
    cache_ttl_seconds=3600
)
```

### Initialization

```python
from hierarchical_summary import HierarchicalSummarizer

# Initialize with default configuration
summarizer = HierarchicalSummarizer()
await summarizer.initialize()

# Or with custom configuration
config = SummaryConfig(clustering_algorithm="hdbscan")
summarizer = HierarchicalSummarizer(config)
await summarizer.initialize()
```

## Usage Examples

### 1. Command Line Interface (CLI)

The `thunker_cli.py` provides easy command-line access to all features:

```bash
# Check system status
python thunker_cli.py status

# Run ad-hoc summarization for last 7 days
python thunker_cli.py summarise --since 7d

# Query summaries with natural language
python thunker_cli.py query "show me brute force attacks this week"

# Query with filters
python thunker_cli.py query "authentication failures" --level daily --start-date 2025-01-01

# Run nightly summarization for specific date
python thunker_cli.py run-nightly --date 2025-01-15

# Show available summary levels
python thunker_cli.py levels

# Run performance optimization
python thunker_cli.py optimize
```

### 2. Programmatic API

```python
from hierarchical_summary import HierarchicalSummarizer
from hierarchical_summary.models import SummaryLevel, SummaryQuery
from datetime import datetime, timedelta

# Initialize
summarizer = HierarchicalSummarizer()
await summarizer.initialize()

# Generate cluster summary for logs
logs = [...]  # List of log dictionaries
result = await summarizer.generate_cluster_summary(logs)
print(f"Summary: {result.summary}")
print(f"Key insights: {result.key_insights}")

# Query summaries
response = await summarizer.query_summaries(
    query="security incidents", 
    level=SummaryLevel.DAILY,
    start_date=datetime.now() - timedelta(days=7),
    limit=10
)

for summary in response.summaries:
    print(f"{summary.metadata.summary_id}: {summary.executive_summary}")

# Run nightly summarization
result = await summarizer.run_nightly_summarization()
print(f"Created {result['summaries_created']} summaries")

# Get system status  
status = await summarizer.get_system_status()
print(f"Storage: {status['storage_stats']['total_summaries']} summaries")
```

### 3. REST API Endpoints

The system integrates with the existing FastAPI application:

```bash
# Get system status
curl -u user:pass http://localhost:8000/api/hierarchical_summary/status

# Run nightly summarization
curl -u user:pass -X POST http://localhost:8000/api/hierarchical_summary/run_nightly

# Query summaries
curl -u user:pass "http://localhost:8000/api/hierarchical_summary/query?query=brute+force&level=daily&limit=5"

# Get available levels
curl -u user:pass http://localhost:8000/api/hierarchical_summary/levels

# Generate summary for content
curl -u user:pass -X POST http://localhost:8000/api/hierarchical_summary/generate \
  -H "Content-Type: application/json" \
  -d '{"content": [...], "scope": "cluster"}'

# Get performance metrics
curl -u user:pass http://localhost:8000/api/hierarchical_summary/performance

# Run optimization
curl -u user:pass -X POST http://localhost:8000/api/hierarchical_summary/optimize
```

### 4. Integration with RAG Interface

The system seamlessly integrates with the existing RAG interface:

```python
from rag_interface import RAGInterface

rag = RAGInterface()

# Summarization automatically uses hierarchical system if available
result = await rag.summarize(logs, scope="cluster")

# Query hierarchical summaries
summaries = await rag.query_hierarchical_summaries("show me this week's trends")

# Get system status
status = await rag.get_hierarchical_summary_status()
```

## Data Models

### Core Summary Types

```python
# Cluster Summary - Groups of related logs
class ClusterSummary(BaseModel):
    cluster_id: str
    summary_text: str
    key_insights: List[str]
    security_patterns: List[SecurityPattern]
    entity_activities: List[EntityActivity]
    risk_assessment: str  # low, medium, high, critical
    cluster_coherence: float

# Daily Summary - Aggregated daily view
class DailySummary(BaseModel):
    date: date
    executive_summary: str
    key_findings: List[str]
    security_trends: List[SecurityTrend]
    incident_count: int
    alert_volume: int
    system_health: Dict[str, Any]
    
# Weekly Summary - Weekly trends and incidents
class WeeklySummary(BaseModel):
    week_start: date
    week_end: date
    executive_summary: str
    weekly_trends: List[SecurityTrend]
    major_incidents: List[Dict[str, Any]]
    campaign_detection: List[Dict[str, Any]]
    week_over_week_comparison: Dict[str, Any]

# Monthly Summary - Strategic assessment
class MonthlySummary(BaseModel):
    month: int
    year: int
    executive_summary: str
    security_posture_assessment: Dict[str, Any]
    threat_intelligence: Dict[str, Any]
    policy_effectiveness: Dict[str, Any]
    budget_impact_analysis: Dict[str, Any]

# Quarterly Summary - Executive reporting
class QuarterlySummary(BaseModel):
    quarter: int
    year: int
    executive_summary: str
    security_program_assessment: Dict[str, Any]
    strategic_security_metrics: Dict[str, float]
    investment_recommendations: List[Dict[str, Any]]
    board_presentation_highlights: List[str]
```

### Supporting Models

```python
# Security Pattern Detection
class SecurityPattern(BaseModel):
    pattern_type: str  # brute_force, lateral_movement, etc.
    description: str
    confidence: float
    severity: str
    occurrence_count: int
    affected_systems: List[str]

# Entity Activity Tracking  
class EntityActivity(BaseModel):
    entity: str
    entity_type: str  # ip, user, host, process
    activity_score: float
    risk_score: float
    event_count: int
    top_behaviors: List[str]
    anomaly_indicators: List[str]

# Security Trend Analysis
class SecurityTrend(BaseModel):
    trend_name: str
    category: str
    direction: str  # increasing, decreasing, stable
    magnitude: float
    confidence: float
    time_period: str
    significance: str  # low, medium, high
```

## Automated Background Processing

### Nightly Job Schedule

The system automatically processes summaries with proper dependency management:

```
Daily Flow (runs every night at 2 AM):
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Cluster   │───▶│    Daily    │───▶│   Weekly    │
│ Summarization│    │Aggregation  │    │(Sundays only)│
│             │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
                                              │
                                              ▼
                                     ┌─────────────┐
                                     │   Monthly   │
                                     │(End of month)│
                                     │             │
                                     └─────────────┘
                                              │
                                              ▼
                                     ┌─────────────┐
                                     │ Quarterly   │
                                     │(End of quarter)│
                                     │             │
                                     └─────────────┘
```

### Job Dependencies

- **Cluster jobs**: No dependencies (run first)
- **Daily jobs**: Depend on cluster jobs for the same day
- **Weekly jobs**: Depend on all daily jobs for the week (run on Sundays)  
- **Monthly jobs**: Depend on all weekly jobs for the month (run on last day)
- **Quarterly jobs**: Depend on all monthly jobs for the quarter

### Scheduling Options

1. **Cron Jobs** (Linux/Mac):
```bash
# Add to crontab
0 2 * * * cd /path/to/threat_hunter && python thunker_cli.py run-nightly
```

2. **GitHub Actions** (for cloud deployments):
```yaml
name: Nightly Summarization
on:
  schedule:
    - cron: '0 2 * * *'  # 2 AM daily
jobs:
  summarize:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run nightly summarization
        run: python thunker_cli.py run-nightly
```

3. **Windows Task Scheduler**:
- Create task to run `python thunker_cli.py run-nightly` daily at 2 AM

## Performance Optimization

### Token Reduction Strategy

The system achieves ~90% token reduction through:

1. **Progressive Summarization**: Each level distills key information from lower levels
2. **Intelligent Query Routing**: Route queries to appropriate summary levels
3. **Caching**: Redis caching for frequently accessed summaries
4. **Compression**: Gzip compression for stored summaries

### Query Optimization

```python
# Instead of processing 1000s of raw logs (high token cost)
raw_logs = await search_vector_db("brute force attacks", k=1000)

# Query relevant daily summaries (low token cost)  
summaries = await summarizer.query_summaries(
    "brute force attacks",
    level=SummaryLevel.DAILY,
    start_date=datetime.now() - timedelta(days=7)
)
```

### Storage Efficiency

- **Time Partitioning**: Organizes summaries by date for fast range queries
- **Compression**: Reduces storage footprint by ~70%
- **Indexing**: SQLite indexes for fast metadata queries
- **Retention Policies**: Automatic cleanup of expired summaries

## Monitoring & Observability

### System Metrics

The system tracks comprehensive metrics:

```python
{
    "performance_metrics": {
        "summaries_generated": 15420,
        "queries_executed": 3240,
        "cache_hits": 2890,
        "avg_generation_time_ms": 2340,
        "avg_query_time_ms": 85,
        "estimated_token_reduction": 0.91
    },
    "storage_stats": {
        "total_summaries": 15420,
        "storage_size_mb": 248.5,
        "compression_ratio": 0.68,
        "cache_hit_rate": 0.89,
        "by_level": {
            "cluster": 12500,
            "daily": 2800,
            "weekly": 120,
            "monthly": 24,
            "quarterly": 8
        }
    }
}
```

### Quality Assurance

- **Coherence Scoring**: Measures cluster quality and summary coherence
- **Entity Validation**: Ensures entity extraction accuracy
- **Trend Validation**: Statistical significance testing for trends
- **Summary Quality**: AI-based quality scoring for generated summaries

## Troubleshooting

### Common Issues

1. **Initialization Fails**:
   ```bash
   # Check dependencies
   pip install scikit-learn hdbscan redis aiofiles
   
   # Check Redis connection
   redis-cli ping
   
   # Check embedding model
   python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('Snowflake/snowflake-arctic-embed-m')"
   ```

2. **No Summaries Generated**:
   ```bash
   # Check if logs exist
   python thunker_cli.py status
   
   # Try manual summarization
   python thunker_cli.py summarise --since 1d --verbose
   ```

3. **Poor Clustering Quality**:
   ```python
   # Adjust clustering parameters
   config = SummaryConfig(
       cluster_size_min=3,  # Lower minimum
       similarity_threshold=0.6,  # Lower threshold
       clustering_algorithm="dbscan"  # Try different algorithm
   )
   ```

4. **High Memory Usage**:
   ```python
   config = SummaryConfig(
       parallel_processing=False,  # Disable parallel processing
       max_concurrent_jobs=2,      # Reduce concurrency
       batch_size=50              # Smaller batch sizes
   )
   ```

### Debugging

Enable verbose logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Or via CLI
python thunker_cli.py status --verbose
```

### Performance Tuning

1. **Clustering Performance**:
   - Use HDBSCAN for better quality but slower processing
   - Use K-means for faster processing but potentially lower quality
   - Adjust similarity thresholds based on your data characteristics

2. **Storage Performance**:
   - Enable Redis caching for frequently accessed summaries
   - Tune cache TTL based on query patterns
   - Use compression for storage savings

3. **Memory Optimization**:
   - Process smaller batches if memory constrained
   - Disable parallel processing on resource-limited systems
   - Adjust retention policies to limit storage growth

## Security Considerations

- **PII Redaction**: Automatically redacts personally identifiable information
- **Access Control**: Integrates with existing HTTP Basic authentication
- **Audit Trail**: Comprehensive logging of all summarization operations
- **Data Retention**: Configurable retention policies for compliance
- **Secure Storage**: SQLite database with proper file permissions

## Future Enhancements

- **Real-time Processing**: Stream processing for immediate cluster detection
- **Advanced Analytics**: Machine learning-based anomaly detection
- **Custom Patterns**: User-defined security patterns and rules
- **Multi-tenant Support**: Isolated summarization per organization
- **API Rate Limiting**: Advanced rate limiting and quota management
- **Export Capabilities**: PDF/Word export for executive reports

## Contributing

When contributing to the hierarchical summarization system:

1. **Follow Existing Patterns**: Use the established architecture and naming conventions
2. **Add Tests**: Include unit tests for new components
3. **Update Documentation**: Keep this README and code comments current
4. **Performance**: Consider performance implications of changes
5. **Backwards Compatibility**: Maintain compatibility with existing APIs

## File Structure

```
hierarchical_summary/
├── __init__.py                 # Main exports and initialization
├── models.py                   # Pydantic data models
├── cluster_summarizer.py       # Log clustering and cluster summarization
├── temporal_aggregator.py      # Time-based summary aggregation
├── summary_storage.py          # Storage and retrieval system
├── nightly_jobs.py            # Background job orchestration
└── hierarchical_summarizer.py  # Main orchestrator class

# Integration files
rag_interface/__init__.py       # RAG interface integration
app.py                         # REST API endpoints
thunker_cli.py                 # Command-line interface
```

This hierarchical summarization system provides a comprehensive solution for dramatically reducing token usage while maintaining high-quality security analysis capabilities. The multi-level approach ensures that users can get appropriate levels of detail for different use cases, from tactical cluster analysis to strategic executive reporting.