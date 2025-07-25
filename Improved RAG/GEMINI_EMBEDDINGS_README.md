# Gemini Embeddings Integration

This document describes the integration of Google's Gemini embedding API (gemini-embedding-001) into the Threat Hunter Pro application, providing enhanced semantic search capabilities for security log analysis.

## Overview

The Gemini embedding integration replaces the default local SentenceTransformers model with Google's cloud-based Gemini embedding API, offering:

- **Higher Quality Embeddings**: Gemini embeddings are trained on massive datasets and optimized for various tasks
- **Larger Context Window**: Better handling of long security logs and complex threat descriptions
- **Task-Specific Optimization**: Configured for document retrieval tasks optimal for security analysis
- **Scalability**: Cloud-based processing without local GPU requirements

## Features

### ✅ Implemented Features

1. **Gemini API Client** (`gemini_embeddings.py`)
   - Rate limiting with token bucket algorithm
   - Automatic API key rotation
   - Batch processing for efficiency
   - Error handling and retry logic
   - Async/await support

2. **Dual Provider Support** (`config.py`)
   - Configurable embedding provider (Gemini vs SentenceTransformers)
   - Environment variable configuration
   - Dynamic model selection

3. **Vector Database Integration** (`vector_db.py`)
   - Seamless integration with FAISS index
   - Async initialization and operations
   - Support for both embedding providers
   - Entity boosting for enhanced search

4. **Enhanced Search Capabilities**
   - Semantic similarity search
   - Hybrid search with BM25
   - Entity-aware retrieval
   - Multi-stage comprehensive search

## Configuration

### Environment Variables

```bash
# Required: Gemini API key(s)
export GEMINI_API_KEY="your_primary_api_key_here"
export GEMINI_API_KEY_2="your_secondary_api_key_here"  # Optional
export GEMINI_API_KEY_3="your_third_api_key_here"      # Optional

# Optional: Embedding provider selection
export EMBEDDING_PROVIDER="gemini"  # Default: "gemini", Alternative: "sentence_transformers"

# Required: Basic authentication
export BASIC_AUTH_USER="your_username"
export BASIC_AUTH_PASS="your_password"
```

### Gemini API Configuration

The system is configured with the following Gemini embedding settings:

- **Model**: `gemini-embedding-001`
- **Dimension**: 3072 (configurable to 768 or 1536)
- **Task Type**: `RETRIEVAL_DOCUMENT` (optimized for document search)
- **Rate Limits**: 100 RPM, 30K TPM, 1,000 RPD

## Architecture

### Core Components

```
┌─────────────────────┐    ┌──────────────────────┐    ┌─────────────────────┐
│   Gemini API        │    │  Vector Database     │    │  Enhanced Search    │
│                     │    │                      │    │                     │
│ ┌─────────────────┐ │    │ ┌──────────────────┐ │    │ ┌─────────────────┐ │
│ │ Embedding       │ │    │ │ FAISS Index      │ │    │ │ Semantic Search │ │
│ │ Generation      │ │    │ │                  │ │    │ │                 │ │
│ └─────────────────┘ │    │ └──────────────────┘ │    │ └─────────────────┘ │
│                     │    │                      │    │                     │
│ ┌─────────────────┐ │    │ ┌──────────────────┐ │    │ ┌─────────────────┐ │
│ │ Rate Limiting   │ │    │ │ Metadata Store   │ │    │ │ Hybrid Search   │ │
│ │                 │ │    │ │                  │ │    │ │ (BM25 + Vector) │ │
│ └─────────────────┘ │    │ └──────────────────┘ │    │ └─────────────────┘ │
│                     │    │                      │    │                     │
│ ┌─────────────────┐ │    │ ┌──────────────────┐ │    │ ┌─────────────────┐ │
│ │ API Key         │ │    │ │ Entity Boosting  │ │    │ │ Multi-stage     │ │
│ │ Rotation        │ │    │ │                  │ │    │ │ Retrieval       │ │
│ └─────────────────┘ │    │ └──────────────────┘ │    │ └─────────────────┘ │
└─────────────────────┘    └──────────────────────┘    └─────────────────────┘
```

### Data Flow

1. **Log Ingestion**: Security logs are processed and prepared for embedding
2. **Entity Extraction**: NER identifies key entities (IPs, hostnames, users)
3. **Entity Boosting**: Entities are repeated 3x to increase semantic weight
4. **Batch Embedding**: Texts are sent to Gemini API in optimized batches
5. **Vector Storage**: Embeddings are stored in FAISS index with metadata
6. **Semantic Search**: Queries are embedded and matched against stored vectors
7. **Hybrid Reranking**: Results are reranked using BM25 for keyword relevance

## Usage

### Basic Setup

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Set Environment Variables**:
   ```bash
   export GEMINI_API_KEY="your_api_key_here"
   export BASIC_AUTH_USER="admin"
   export BASIC_AUTH_PASS="your_password"
   export EMBEDDING_PROVIDER="gemini"
   ```

3. **Run the Application**:
   ```bash
   python run_app.py
   ```

### Testing the Integration

Run the comprehensive test suite:

```bash
python test_gemini_embeddings.py
```

This will validate:
- Configuration correctness
- API connectivity
- Embedding generation
- Vector database integration
- Rate limiting functionality

## API Integration Details

### Gemini Embedding API

The integration uses Google's Gemini embedding API with the following specifications:

```python
# API Endpoint
BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
ENDPOINT = f"{BASE_URL}/models/gemini-embedding-001:embedContent"

# Request Format
{
  "requests": [
    {
      "model": "models/gemini-embedding-001",
      "content": {
        "parts": [{"text": "log text to embed"}]
      },
      "taskType": "RETRIEVAL_DOCUMENT",
      "outputDimensionality": 3072
    }
  ]
}

# Response Format
{
  "embeddings": [
    {
      "values": [0.1, -0.2, 0.3, ...]  // 3072 dimensions
    }
  ]
}
```

### Rate Limiting Strategy

The system implements sophisticated rate limiting:

- **Token Bucket Algorithm**: Smooth rate limiting across multiple API keys
- **Automatic Key Rotation**: Switches to available keys when limits are hit
- **Exponential Backoff**: Graceful handling of temporary failures
- **Batch Optimization**: Groups requests to maximize throughput

## Performance Considerations

### Embedding Generation

- **Batch Size**: 5 texts per API call (optimized for strict rate limits)
- **Concurrent Requests**: Single-threaded to respect API limits
- **Caching**: Vector database provides persistent storage
- **Intelligent Fallback**: Automatic switching to SentenceTransformers when all API keys exhaust daily limits

### Search Performance

- **Vector Search**: O(n) similarity search using FAISS
- **Hybrid Search**: Combined semantic + keyword relevance
- **Result Caching**: Metadata cached for fast retrieval
- **Entity Boosting**: 3x entity repetition for improved relevance

## Security Considerations

### API Key Management

- **Multiple Keys**: Support for up to 3 API keys for redundancy
- **Key Rotation**: Automatic rotation when rate limits are hit
- **Secure Storage**: Keys stored in environment variables only
- **No Logging**: API keys never logged or stored in files

### Data Privacy

- **Cloud Processing**: Text data sent to Google's servers
- **No Persistence**: Google doesn't store embedding requests
- **Local Fallback**: Option to use local SentenceTransformers
- **Audit Trail**: All API calls logged for monitoring

## Monitoring and Debugging

### Logging

The system provides comprehensive logging:

```python
# Configuration logging
logging.info(f"Initialized Gemini Embedding Client with model: {model_name}")
logging.info(f"Rate limits: {rpm_limit} RPM, {tpm_limit} TPM, {rpd_limit} RPD")

# Embedding generation
logging.info(f"Generated {len(embeddings)} embeddings with dimension {dimension}")
logging.debug(f"Generated embeddings for batch {batch_num}/{total_batches}")

# Rate limiting
logging.warning(f"Rate limit hit for embedding API: {error}")
logging.info(f"Switched to API key {key_index} for embedding request")
```

### Health Checks

Monitor the system health through:

- **Metrics Endpoint**: `/metrics` provides Prometheus-compatible metrics
- **Dashboard Status**: Real-time status in the web interface
- **Log Analysis**: Detailed error and performance logging
- **Test Script**: Regular validation using `test_gemini_embeddings.py`

## Troubleshooting

### Common Issues

1. **API Key Issues**
   ```
   Error: No Gemini API keys configured
   Solution: Set GEMINI_API_KEY environment variable
   ```

2. **Rate Limit Errors**
   ```
   Error: Rate limit hit for embedding API
   Solution: Add additional API keys or reduce batch size
   ```

3. **Dimension Mismatch**
   ```
   Error: Vector dimension mismatch
   Solution: Clear vector database when changing models
   ```

4. **Network Connectivity**
   ```
   Error: HTTP error in embedding request
   Solution: Check internet connectivity and API status
   ```

### Fallback Mode

If Gemini API is unavailable, the system can fall back to local embeddings:

```bash
export EMBEDDING_PROVIDER="sentence_transformers"
```

This provides continued functionality with reduced performance.

## Future Enhancements

### Planned Features

1. **Model Selection**: Support for future Gemini embedding models
2. **Custom Dimensions**: Dynamic dimension configuration
3. **Task Optimization**: Task-specific embedding optimization
4. **Caching Layer**: Redis-based embedding cache
5. **Multi-modal**: Support for image and document embeddings

### Performance Improvements

1. **Parallel Processing**: Multi-threaded embedding generation
2. **Smart Batching**: Dynamic batch size optimization
3. **Compression**: Vector quantization for storage efficiency
4. **Incremental Updates**: Partial index updates for new logs

## Support

For issues related to Gemini embeddings integration:

1. Check the logs for detailed error messages
2. Run the test script to validate configuration
3. Verify API key validity and quotas
4. Review rate limiting and network connectivity

The integration is designed to be robust and fail gracefully, ensuring continuous operation even when cloud services are temporarily unavailable.