# Current State Analysis - Threat Hunter Pro

## Repository Structure

### Core Python Modules
- **`app.py`** - FastAPI application with HTTP routes and authentication
- **`main.py`** - Application entry point with server startup logic
- **`ai_logic.py`** - AI interaction, token counting, and Gemini API integration
- **`vector_db.py`** - FAISS vector database operations and hybrid search
- **`enhanced_retrieval.py`** - Multi-stage comprehensive log retrieval system
- **`log_processing.py`** - Background log processing and Wazuh integration
- **`worker.py`** - Background worker thread management
- **`ner_utils.py`** - Named Entity Recognition for cybersecurity entities
- **`state.py`** - Global application state management
- **`config.py`** - Configuration constants and environment variables
- **`models.py`** - Pydantic models for API and data validation
- **`persistence.py`** - Data persistence operations
- **`metrics.py`** - Prometheus metrics collection
- **`token_bucket.py`** - Rate limiting implementation
- **`html_template.py`** - Dashboard HTML template

### Support Files
- **`requirements.txt`** - Python dependencies
- **`run_app.py`** - Alternative entry point
- **`install_dependencies.py`** - Setup script
- **`setup_improvements.py`** - Enhancement script
- **`test_startup.py`** - Startup validation
- **`debug_dashboard.py`** - Debug utilities

## Current Web Routes & API Endpoints

### Core Routes
1. **`GET /`** - Dashboard HTML interface (authenticated)
2. **`GET /api/dashboard`** - Dashboard data JSON API (authenticated)
3. **`GET /api/logs/{log_id}`** - Individual log retrieval (authenticated)
4. **`GET /metrics`** - Prometheus metrics (no auth)

### Chat & Analysis
5. **`POST /api/chat/analyze`** - NER-enhanced query analysis (authenticated)
6. **`POST /api/chat/execute`** - Execute chat plan with hybrid search (authenticated)
7. **`POST /api/analyze`** - Manual log analysis trigger (authenticated)

### Issue Management
8. **`POST /api/issues/{issue_id}/ignore`** - Ignore specific issue (authenticated)
9. **`POST /api/issues/{issue_id}/query`** - Question about specific issue (authenticated)
10. **`POST /api/issues/{issue_id}/generate-script`** - Generate remediation script (authenticated)

### Configuration
11. **`GET /api/settings`** - Retrieve current settings (authenticated)
12. **`POST /api/settings`** - Update settings (authenticated)
13. **`POST /api/clear_db`** - Clear vector database (authenticated)

## Current Features Analysis

### Search & Retrieval
- **Multi-stage Retrieval**: 5-stage search strategy (entity-exact, related-term, semantic-context, broad-context, rule-based)
- **Hybrid Search**: FAISS vector search combined with BM25 keyword search (60% semantic, 40% BM25)
- **Entity Recognition**: spaCy-based NER with cybersecurity-specific entities
- **Entity Boosting**: 3x repetition of extracted entities in embeddings
- **Comprehensive Search**: Up to 500 results per query with multiple search strategies

### AI Integration
- **Multi-Model Support**: Gemini 2.5 Pro, Flash, and Flash-Lite with automatic fallback
- **Rate Limiting**: Per-model token buckets (Pro: 5 RPM, Flash: 10 RPM, Flash-Lite: 15 RPM)
- **API Key Rotation**: Multiple API keys with automatic rotation on rate limits
- **Context Windows**: 200,000 tokens input, 32,000 tokens output
- **Enhanced Context**: 150-200+ log context vs traditional 5-10 logs

### Storage Layer
- **Vector Database**: FAISS IndexFlatL2 with IndexIDMap for semantic search
- **Metadata Storage**: JSON-based metadata mapping SHA256 → log data
- **Hybrid Index**: BM25 index for keyword-based search
- **Persistence**: Automatic save/load of vector DB and metadata

### User Interface
- **Real-time Dashboard**: Live status updates with countdown timers
- **Issue Tracking**: Categorized security issues with severity levels
- **Interactive Chat**: Context-aware threat hunting conversations
- **Script Generation**: Automated remediation script creation
- **Settings Management**: Configurable scan intervals and parameters

### Background Processing
- **Continuous Monitoring**: 10-minute scan intervals for new logs
- **Wazuh Integration**: Reads from `/var/ossec/logs/alerts/alerts.json`
- **Batch Processing**: 100,000 log batch size with chunked embedding
- **Deduplication**: SHA256-based log deduplication
- **Position Tracking**: Persistent log file position tracking

### Security & Authentication
- **HTTP Basic Auth**: Username/password authentication on all routes except metrics
- **Environment-based Config**: API keys and credentials via environment variables
- **Input Validation**: Pydantic models for API request validation
- **Sanitization**: HTML escaping for log content display

## Current Architecture Analysis

### Data Flow
1. **Log Ingestion**: Wazuh alerts → JSON parsing → deduplication
2. **Embedding**: Entity extraction → boosting → SentenceTransformer encoding
3. **Storage**: FAISS vector DB + JSON metadata + BM25 index
4. **Retrieval**: Multi-stage search → hybrid ranking → result compilation
5. **Analysis**: Gemini AI processing → issue detection → dashboard updates
6. **UI**: FastAPI routes → HTML dashboard → real-time updates

### Current "Hot Store" Implementation
- **Primary Storage**: FAISS vector database with metadata JSON
- **Search**: Hybrid semantic + keyword search via BM25
- **Indexing**: Real-time indexing of new logs with batched embeddings
- **Performance**: In-memory FAISS index with disk persistence

### Current AI Processing
- **Query Analysis**: NER-enhanced query understanding
- **Context Gathering**: Comprehensive multi-stage retrieval
- **Answer Generation**: Gemini models with extensive log context
- **Issue Detection**: Pattern recognition and anomaly identification
- **Script Generation**: Automated remediation with safety checks

## Technical Debt & Limitations

### Architecture Concerns
1. **Monolithic Structure**: All functionality in single process
2. **No Service Separation**: Vector DB, AI logic, and web server tightly coupled
3. **Limited Scalability**: Single FAISS index, no distributed processing
4. **No Caching Layer**: Every search hits vector DB directly
5. **Memory Constraints**: Entire vector DB loaded in memory

### Missing RAG Components
1. **No Agent/Router Layer**: Direct calls from web handlers to AI logic
2. **No Hierarchical Summaries**: No cluster → month → quarter summary structure
3. **No Multi-turn Search**: Single-shot retrieval, no iterative refinement
4. **No Result Ranking**: Basic relevance scoring without advanced ranking
5. **No Cost Tracking**: Limited token usage monitoring

### Operational Gaps
1. **No Containerization**: Python process deployment only
2. **No Service Discovery**: Hardcoded paths and configurations
3. **No Health Checks**: Basic status reporting only
4. **No Backup Strategy**: Manual database management
5. **Limited Observability**: Basic logging and metrics

### Security Limitations
1. **No PII Redaction**: Raw log content in embeddings
2. **Basic Authentication**: HTTP Basic Auth only
3. **No RBAC**: Single user role
4. **Secret Management**: Environment variables only
5. **No Audit Logging**: Limited security event tracking

## Performance Characteristics

### Current Metrics
- **Query Latency**: Variable based on search complexity and AI model
- **Embedding Throughput**: 64 logs per chunk, 32 batch size
- **Context Window**: 200,000 tokens (very large for current models)
- **Search Results**: Up to 500 results per comprehensive search
- **Background Processing**: 10-minute intervals

### Bottlenecks
1. **Single-threaded Embedding**: No parallel embedding generation
2. **AI API Limits**: Rate limiting to 5-15 RPM per model
3. **Memory Usage**: Full vector DB in memory
4. **Search Latency**: Multiple search stages in sequence
5. **Web Server**: Single FastAPI instance

## Integration Points

### External Dependencies
- **Wazuh**: Log file reading from `/var/ossec/logs/alerts/alerts.json`
- **Google Gemini**: API-based AI processing
- **SentenceTransformers**: Local embedding model
- **FAISS**: Vector similarity search
- **spaCy**: Named Entity Recognition

### Data Persistence
- **Vector DB**: `/var/ossec/integrations/threat_hunter_db/vector_db.faiss`
- **Metadata**: `/var/ossec/integrations/threat_hunter_db/metadata.json`
- **Settings**: `/var/ossec/integrations/threat_hunter_db/settings.json`
- **Dashboard**: `/var/ossec/integrations/threat_hunter_db/dashboard_data.json`
- **Position**: `/var/ossec/integrations/threat_hunter_db/log_position.txt`

## Code Quality Assessment

### Strengths
- **Type Hints**: Comprehensive type annotations throughout
- **Error Handling**: Robust exception handling with fallbacks
- **Logging**: Detailed logging for debugging and monitoring
- **Documentation**: Well-documented modules and functions
- **Validation**: Pydantic models for data validation

### Areas for Improvement
- **Module Coupling**: High coupling between modules
- **Test Coverage**: No visible test suite
- **Configuration**: Hardcoded paths and values
- **Code Duplication**: Some repeated patterns across modules
- **Async Usage**: Mixed sync/async patterns

This analysis forms the baseline for the RAG refactoring effort, ensuring all current functionality is preserved while adding enhanced capabilities.