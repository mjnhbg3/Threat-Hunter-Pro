# RAG Architecture Design - Threat Hunter Pro

## Executive Summary

This document outlines the comprehensive transformation of Threat Hunter Pro from a monolithic log analytics application into a modular Retrieval-Augmented Generation (RAG) platform. The design preserves all existing functionality while introducing advanced multi-turn retrieval, hierarchical summarization, and comprehensive observability.

## Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Web Server & UI Layer                        │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│  │   Dashboard  │ │  Chat API    │ │  Issue Mgmt  │            │
│  │   (HTML/JS)  │ │  Endpoints   │ │  Endpoints   │            │
│  └──────────────┘ └──────────────┘ └──────────────┘            │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     RAG Interface Layer                         │
│  ┌─────────────────────────────────────────────────────────────┤
│  │  retrieve() │ summarize() │ relate() │ trend() │ explain()  │
│  └─────────────────────────────────────────────────────────────┤
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Agent Router                               │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│  │  Query       │ │  Strategy    │ │  Execution   │            │
│  │  Analysis    │ │  Selection   │ │  Orchestration│            │
│  └──────────────┘ └──────────────┘ └──────────────┘            │
└─────────────────────────────────────────────────────────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            ▼                   ▼                   ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│   Hot Store      │ │   Vector Store   │ │  Agentic Search  │
│                  │ │                  │ │                  │
│ • BM25 Search    │ │ • FAISS Index    │ │ • Multi-turn     │
│ • Metadata       │ │ • Embeddings     │ │ • Query Refine   │
│ • Time Filters   │ │ • Similarity     │ │ • Budget Control │
│ • Rule Matching  │ │ • NER Enhanced   │ │ • Traceability   │
└──────────────────┘ └──────────────────┘ └──────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Hierarchical Summaries                         │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐             │
│  │   Cluster    │ │    Month     │ │   Quarter    │             │
│  │  Summaries   │ │  Summaries   │ │  Summaries   │             │
│  └──────────────┘ └──────────────┘ └──────────────┘             │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Security Pipeline                            │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐             │
│  │ PII Redaction│ │ Entity       │ │ Audit        │             │
│  │ & Masking    │ │ Preservation │ │ Logging      │             │
│  └──────────────┘ └──────────────┘ └──────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. RAG Interface Layer

The `rag_interface` module provides a stable contract between the web layer and storage engines:

```python
class RAGInterface:
    async def retrieve(self, query: str, context: Dict[str, Any], 
                      filters: Optional[Dict[str, Any]] = None) -> RetrievalResult
    
    async def summarize(self, content: List[Dict[str, Any]], 
                       scope: str = "cluster") -> SummaryResult
    
    async def relate(self, entities: List[str], 
                    timeframe: str = "24h") -> RelationshipResult
    
    async def trend(self, patterns: List[str], 
                   period: str = "7d") -> TrendResult
    
    async def explain(self, findings: Dict[str, Any], 
                     evidence: List[Dict[str, Any]]) -> ExplanationResult
```

#### Responsibilities
- **Decoupling**: Isolates web handlers from storage implementation details
- **Abstraction**: Provides high-level operations for common use cases
- **Routing**: Delegates to appropriate storage engines and processing pipelines
- **Aggregation**: Combines results from multiple sources
- **Caching**: Implements intelligent caching for frequently accessed data

### 2. Agent Router

The agent router intelligently selects and coordinates search strategies:

#### Decision Logic
```python
class AgentRouter:
    async def route_query(self, query: str, context: Dict[str, Any]) -> RoutingDecision:
        """Determine optimal search strategy based on query characteristics."""
        
        # Entity analysis
        entities = await self.extract_entities(query)
        entity_density = len(entities) / len(query.split())
        
        # Query complexity analysis
        complexity = await self.analyze_complexity(query)
        
        # Historical performance
        performance_history = await self.get_performance_history(query)
        
        # Routing decisions
        if entity_density > 0.3 and entities:
            return RoutingDecision.ENTITY_FOCUSED
        elif complexity > 0.7:
            return RoutingDecision.AGENTIC_SEARCH
        elif performance_history.indicates_vector_search():
            return RoutingDecision.VECTOR_SEARCH
        else:
            return RoutingDecision.HYBRID_SEARCH
```

#### Strategy Selection
- **Entity-Focused**: High entity density queries use NER-enhanced search
- **Agentic Search**: Complex queries benefit from multi-turn refinement
- **Vector Search**: Semantic similarity queries use pure vector search
- **Hybrid Search**: Balanced queries use BM25 + vector combination
- **Hot Store**: Time-bounded and metadata-filtered queries

### 3. Agentic Search Implementation

Multi-turn retrieval system with LLM-guided query refinement:

#### Search Loop
```python
class AgenticSearchEngine:
    async def execute_search(self, initial_query: str, 
                           budget: SearchBudget) -> AgenticResult:
        
        trace_id = await self.start_trace(initial_query)
        results = []
        
        # Seed step
        seed_results = await self.seed_search(initial_query, trace_id)
        results.extend(seed_results)
        
        # Refinement iterations
        for iteration in range(budget.max_iterations):
            if await self.should_terminate(results, budget, iteration):
                break
                
            # LLM analyzes current results and formulates refinement
            refinement = await self.generate_refinement(
                initial_query, results, iteration, trace_id
            )
            
            # Execute refined search
            refined_results = await self.execute_refinement(
                refinement, trace_id
            )
            
            results.extend(refined_results)
            
            # Update budget tracking
            budget.consume_tokens(refinement.token_usage)
            budget.consume_time(refinement.duration_ms)
        
        return await self.finalize_results(results, trace_id)
```

#### Budget Controls
- **Token Budget**: Configurable token limits per search session
- **Time Budget**: Maximum latency constraints
- **Iteration Budget**: Maximum refinement rounds
- **Quality Threshold**: Confidence score requirements for continuation

#### Termination Conditions
- Budget exhaustion (tokens/time/iterations)
- Convergence detection (no new relevant results)
- Quality threshold reached
- Stalling detection (repeated refinements with no improvement)
- User-defined stop conditions

### 4. Hierarchical Summaries

Multi-level summarization for efficient overview generation:

#### Summary Hierarchy
```
Quarterly Summary (3 months)
├── Monthly Summary (30 days)
│   ├── Weekly Summary (7 days)
│   │   ├── Daily Summary (24 hours)
│   │   │   └── Cluster Summary (related logs)
│   │   └── ...
│   └── ...
└── ...
```

#### Generation Strategy
```python
class HierarchicalSummarizer:
    async def generate_cluster_summary(self, logs: List[Dict]) -> ClusterSummary:
        """Generate summary for related log cluster."""
        entities = self.extract_common_entities(logs)
        patterns = self.identify_patterns(logs)
        timeline = self.build_timeline(logs)
        
        return ClusterSummary(
            entity_summary=entities,
            pattern_summary=patterns,
            timeline=timeline,
            log_count=len(logs),
            severity_distribution=self.analyze_severity(logs)
        )
    
    async def aggregate_to_daily(self, clusters: List[ClusterSummary]) -> DailySummary:
        """Aggregate cluster summaries into daily summary."""
        # Implementation for daily aggregation
        
    async def aggregate_to_weekly(self, daily: List[DailySummary]) -> WeeklySummary:
        """Aggregate daily summaries into weekly summary."""
        # Implementation for weekly aggregation
```

#### Nightly Job Architecture
- **Incremental Processing**: Only process new/changed data
- **Parallel Generation**: Concurrent summary generation for different time periods
- **Quality Assurance**: Validation of generated summaries
- **Storage Optimization**: Compression and efficient storage of summaries
- **Cache Invalidation**: Smart cache updates when underlying data changes

### 5. Security Pipeline

Comprehensive security architecture with PII protection:

#### PII Redaction Pipeline
```python
class SecurityPipeline:
    def __init__(self):
        self.redaction_rules = [
            PIIRule.EMAIL_ADDRESSES,
            PIIRule.PHONE_NUMBERS,
            PIIRule.SSN,
            PIIRule.CREDIT_CARDS,
            PIIRule.CUSTOM_PATTERNS
        ]
        
        self.entity_preservers = [
            EntityPreserver.IP_ADDRESSES,
            EntityPreserver.DOMAIN_NAMES,
            EntityPreserver.FILE_HASHES,
            EntityPreserver.SYSTEM_IDENTIFIERS
        ]
    
    async def process_for_embedding(self, log_content: str) -> ProcessedContent:
        """Process log content for safe embedding generation."""
        
        # Step 1: Identify security-relevant entities to preserve
        preserved_entities = await self.extract_security_entities(log_content)
        
        # Step 2: Apply PII redaction rules
        redacted_content = await self.apply_redaction_rules(log_content)
        
        # Step 3: Restore security entities with placeholders
        processed_content = await self.restore_security_entities(
            redacted_content, preserved_entities
        )
        
        # Step 4: Log redaction actions for audit
        await self.log_redaction_actions(log_content, processed_content)
        
        return ProcessedContent(
            original_hash=self.hash_content(log_content),
            processed_text=processed_content,
            redaction_count=len(self.redaction_actions),
            entities_preserved=len(preserved_entities)
        )
```

#### Entity Preservation Strategy
- **IP Addresses**: Preserved with tokenization (192.168.1.1 → IP_TOKEN_001)
- **Domain Names**: Preserved for threat intelligence correlation
- **File Hashes**: Critical for malware detection, always preserved
- **System Identifiers**: Preserve for system correlation, mask sensitive parts
- **User Identifiers**: Redact personal info, preserve role indicators

## Data Flow Diagrams

### Query Processing Flow

```
User Query
    │
    ▼
┌─────────────────┐
│  Query Analysis │
│  • NER          │
│  • Complexity   │
│  • Intent       │
└─────────────────┘
    │
    ▼
┌─────────────────┐
│  Agent Router   │
│  • Strategy     │
│  • Budget       │
│  • Performance │
└─────────────────┘
    │
    ├─── Hot Store ────┐
    ├─── Vector Store ─┤
    ├─── Agentic ──────┤
    └─── Summary ──────┘
                       │
                       ▼
                ┌─────────────────┐
                │ Result Ranking  │
                │ • Relevance     │
                │ • Confidence    │
                │ • Diversity     │
                └─────────────────┘
                       │
                       ▼
                ┌─────────────────┐
                │ Answer Gen      │
                │ • Context       │
                │ • Explanation   │
                │ • Evidence      │
                └─────────────────┘
```

### Log Ingestion Flow

```
Wazuh Logs
    │
    ▼
┌─────────────────┐
│ Log Processing  │
│ • Parse JSON    │
│ • Deduplicate   │
│ • Batch         │
└─────────────────┘
    │
    ▼
┌─────────────────┐
│ Security        │
│ Pipeline        │
│ • PII Redaction │
│ • Entity Preserve│
└─────────────────┘
    │
    ▼
┌─────────────────┐
│ Embedding       │
│ Generation      │
│ • NER Boost     │
│ • Vectorize     │
└─────────────────┘
    │
    ├─── FAISS Index ──┐
    ├─── BM25 Index ───┤
    └─── Metadata ─────┘
                       │
                       ▼
                ┌─────────────────┐
                │ Summary         │
                │ Generation      │
                │ • Cluster       │
                │ • Schedule      │
                └─────────────────┘
```

### Agentic Search Flow

```
Initial Query
    │
    ▼
┌─────────────────┐
│ Seed Search     │
│ • Vector Query  │
│ • Initial Results│
└─────────────────┘
    │
    ▼
┌─────────────────┐      ┌─────────────────┐
│ LLM Analysis    │────▶ │ Budget Check    │
│ • Result Quality│      │ • Tokens        │
│ • Coverage Gaps │      │ • Time          │
│ • Refinement    │      │ • Iterations    │
└─────────────────┘      └─────────────────┘
    │                            │
    ▼                            │
┌─────────────────┐              │
│ Query Refinement│              │
│ • Sub-queries   │              │
│ • Filters/Meta  │              │
│ • Focus Areas   │              │
└─────────────────┘              │
    │                            │
    ▼                            │
┌─────────────────┐              │
│ Refined Search  │              │
│ • Execute Query │              │
│ • Merge Results │              │
│ • Trace Update  │              │
└─────────────────┘              │
    │                            │
    └──── Continue Loop ─────────┘
                │
            Budget Exhausted
            or Convergence
                │
                ▼
        ┌─────────────────┐
        │ Final Results   │
        │ • Rank/Filter   │
        │ • Confidence    │
        │ • Trace Complete│
        └─────────────────┘
```

## Migration Strategy

### Phase 1: Foundation (Weeks 1-2)
1. **Create RAG Interface**: Implement the contract layer
2. **Extract Agent Router**: Move routing logic from existing code
3. **Implement Security Pipeline**: Add PII redaction capabilities
4. **Enhanced Observability**: Extend metrics and tracing

**Success Criteria**: All existing functionality working through RAG interface

### Phase 2: Agentic Search (Weeks 3-4)
1. **Agentic Search Engine**: Implement multi-turn refinement
2. **Budget Controls**: Add token/time/iteration limits
3. **Traceability**: Complete trace logging and analysis
4. **Integration**: Connect agentic search to router

**Success Criteria**: Agentic search available as optional enhancement

### Phase 3: Hierarchical Summaries (Weeks 5-6)
1. **Summary Engine**: Implement cluster → daily → weekly → monthly
2. **Nightly Jobs**: Background summary generation
3. **Summary Storage**: Efficient storage and retrieval
4. **Summary Integration**: Connect summaries to query processing

**Success Criteria**: Fast overview queries using hierarchical summaries

### Phase 4: Optimization & Polish (Weeks 7-8)
1. **Performance Tuning**: Optimize based on benchmarks
2. **Advanced Features**: Enhance based on user feedback
3. **Documentation**: Complete user and developer documentation
4. **CI/CD**: Automated testing and deployment pipelines

**Success Criteria**: Production-ready system with full documentation

### Backward Compatibility Strategy

#### Data Migration
- **Vector Database**: Preserve existing FAISS index and metadata
- **Settings**: Automatic migration of configuration files
- **Persistent State**: Maintain dashboard data and ignored issues
- **Log Position**: Continue from current position in Wazuh logs

#### API Compatibility
- **Route Preservation**: All 13 existing routes maintain identical behavior
- **Response Format**: JSON responses remain unchanged
- **Authentication**: HTTP Basic Auth continues to work
- **Error Handling**: Error responses maintain existing format

#### Configuration Compatibility
- **Environment Variables**: All existing env vars continue to work
- **File Paths**: Database and log file paths unchanged
- **Processing Intervals**: Default 10-minute intervals preserved
- **Rate Limits**: Existing Gemini API rate limiting maintained

## Service Boundaries

### Internal Services
1. **RAG Interface Service**: Contract layer and orchestration
2. **Agent Router Service**: Query analysis and strategy selection
3. **Search Engine Service**: Multi-modal search execution
4. **Summary Service**: Hierarchical summary generation and management
5. **Security Service**: PII redaction and entity preservation
6. **Observability Service**: Metrics, tracing, and performance monitoring

### External Integrations
1. **Wazuh Integration**: Log file monitoring and parsing
2. **Gemini AI Integration**: Model interactions with rate limiting
3. **Vector Database**: FAISS index operations
4. **Embedding Model**: SentenceTransformer operations
5. **Metrics Export**: Prometheus metrics endpoint

### Communication Patterns
- **Synchronous**: Web API calls through RAG interface
- **Asynchronous**: Background processing and summary generation
- **Event-Driven**: Log ingestion and processing pipeline
- **Batch Processing**: Embedding generation and database updates

## Technology Stack

### Core Technologies (Preserved)
- **FastAPI**: Web framework and API server
- **FAISS**: Vector similarity search
- **SentenceTransformers**: Text embedding generation
- **spaCy**: Named Entity Recognition
- **BM25**: Keyword search and hybrid ranking
- **Google Gemini**: Large language model integration

### New Technologies (Added)
- **Distributed Tracing**: OpenTelemetry-compatible tracing
- **Advanced Metrics**: Enhanced Prometheus metrics
- **PII Detection**: Advanced pattern matching and ML-based detection
- **Summary Storage**: Efficient hierarchical storage system
- **Budget Management**: Token and time budget tracking

### Deployment Technologies (Future)
- **Docker**: Containerization for all services
- **Docker Compose**: Local development and testing
- **Health Checks**: Service health monitoring
- **Log Aggregation**: Centralized logging
- **Backup/Recovery**: Automated data protection

## Performance Characteristics

### Target Performance
- **Query Latency**: 95th percentile ≤ 2x baseline
- **Throughput**: Concurrent queries ≥ baseline
- **Memory Usage**: ≤ baseline + 30% for enhanced features
- **CPU Usage**: ≤ baseline + 20% for additional processing
- **Disk Usage**: ≤ baseline + 50% for summaries and traces

### Optimization Strategies
- **Caching**: Intelligent caching at multiple layers
- **Parallel Processing**: Concurrent embedding and search operations
- **Result Streaming**: Progressive result delivery for long searches
- **Summary Precomputation**: Background summary generation
- **Index Optimization**: Optimized FAISS index configuration

### Scalability Considerations
- **Horizontal Scaling**: Preparation for multi-instance deployment
- **Load Balancing**: Ready for load balancer integration
- **Database Sharding**: Preparation for large-scale data
- **Async Processing**: Non-blocking operations where possible
- **Resource Limits**: Configurable resource consumption limits

## Security Architecture

### Defense in Depth
1. **Input Validation**: Comprehensive input sanitization
2. **Authentication**: HTTP Basic Auth with future RBAC preparation
3. **Authorization**: Route-level access control
4. **Data Protection**: PII redaction and entity preservation
5. **Audit Logging**: Comprehensive security event logging
6. **Secret Management**: Environment-based secret handling

### PII Protection Strategy
- **Detection**: Pattern-based and ML-based PII identification
- **Redaction**: Configurable redaction rules and replacement strategies
- **Preservation**: Security entity preservation for analysis effectiveness
- **Audit**: Complete audit trail of redaction actions
- **Compliance**: GDPR and other privacy regulation preparation

### Threat Model
- **Data Exposure**: PII in embeddings and logs
- **API Abuse**: Rate limiting and authentication bypass
- **Injection Attacks**: SQL injection, prompt injection, XSS
- **Data Integrity**: Tampering with vector database or summaries
- **Availability**: DoS attacks and resource exhaustion

## Quality Assurance

### Testing Strategy
- **Unit Tests**: Comprehensive coverage of all new components
- **Integration Tests**: End-to-end workflow testing
- **Performance Tests**: Benchmark comparisons with baseline
- **Security Tests**: PII redaction and security feature validation
- **Compatibility Tests**: Backward compatibility verification
- **User Acceptance Tests**: Full user workflow validation

### Monitoring and Alerting
- **Performance Monitoring**: Real-time performance metrics
- **Error Tracking**: Comprehensive error logging and alerting
- **Security Monitoring**: Security event detection and alerting
- **Resource Monitoring**: CPU, memory, and disk usage tracking
- **Business Metrics**: Search success rates and user satisfaction

### Continuous Improvement
- **Performance Optimization**: Ongoing performance tuning
- **Feature Enhancement**: User feedback-driven improvements
- **Security Updates**: Regular security review and updates
- **Documentation Maintenance**: Keep documentation current
- **Code Quality**: Regular code review and refactoring

This comprehensive design ensures the transformation of Threat Hunter Pro into a powerful RAG platform while maintaining complete backward compatibility and enhancing security, performance, and observability.