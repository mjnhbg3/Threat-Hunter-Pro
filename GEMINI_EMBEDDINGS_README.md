# Gemini Embeddings Integration - Threat Hunter Pro

This enhanced version of Threat Hunter Pro integrates Google's Gemini embedding API (`gemini-embedding-001`) with intelligent fallback to local SentenceTransformers models when daily API limits are exhausted.

## 🚀 Key Features

### **Production-Ready Gemini Integration**
- **Model**: `gemini-embedding-001` with 3072-dimensional embeddings
- **Rate Limiting**: Correctly implemented with 100 RPM, 30K TPM, 1,000 RPD per API key
- **Multi-Key Support**: Automatic rotation between up to 3 API keys for redundancy
- **Task Optimization**: Configured for `RETRIEVAL_DOCUMENT` task type

### **Intelligent Fallback System**
- **Smart Switching**: Only falls back when ALL API keys exhaust daily limits (1,000 RPD each)
- **Pre-loaded Models**: SentenceTransformers fallback pre-loaded for instant switching
- **Seamless Operation**: No service interruption during fallback
- **Automatic Recovery**: Switches back to Gemini when daily limits reset at midnight

### **Enhanced Performance**
- **Conservative Batching**: 5 texts per API call with 0.7s delays for rate compliance
- **Daily Tracking**: Per-key request counting with automatic midnight reset
- **Entity Boosting**: NER-enhanced embeddings for improved semantic search
- **Hybrid Search**: Combined vector similarity + BM25 keyword matching

## 📋 Configuration

### **Environment Variables**
```bash
# Required: Gemini API key(s)
export GEMINI_API_KEY="your_primary_api_key"
export GEMINI_API_KEY_2="your_secondary_api_key"  # Optional
export GEMINI_API_KEY_3="your_third_api_key"      # Optional

# Authentication (required)
export BASIC_AUTH_USER="admin"
export BASIC_AUTH_PASS="your_secure_password"

# Optional: Override default provider
export EMBEDDING_PROVIDER="gemini"  # Default setting
```

### **Rate Limits (Per API Key)**
- **Requests Per Minute (RPM)**: 100
- **Tokens Per Minute (TPM)**: 30,000
- **Requests Per Day (RPD)**: 1,000

## 🔧 Installation & Setup

### **1. Install Dependencies**
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### **2. Configure Environment**
```bash
# Set your Gemini API key(s)
export GEMINI_API_KEY="your_api_key_here"

# Set authentication credentials
export BASIC_AUTH_USER="admin"
export BASIC_AUTH_PASS="your_password"
```

### **3. Test Configuration**
```bash
python test_gemini_embeddings.py
```

### **4. Run Application**
```bash
python run_app.py
```

## 🏗️ Architecture

### **Embedding Flow**
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Log Ingestion │───▶│  Entity Extract. │───▶│  Entity Boost   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Gemini API    │    │  Rate Limiting   │    │  Daily Tracking │
│   Embedding     │───▶│  & Key Rotation  │───▶│  & Fallback     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   FAISS Vector  │    │  Semantic Search │    │  Hybrid Results │
│   Database      │───▶│  + BM25 Rerank   │───▶│  & Scoring      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### **Fallback Logic**
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Gemini API    │    │  Daily Limit     │    │  SentenceT.     │
│   (Primary)     │───▶│  Check (1K RPD)  │───▶│  (Fallback)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Key 1         │    │   All Keys       │    │   Local Model   │
│   Available?    │───▶│   Exhausted?     │───▶│   Processing    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 📊 Monitoring & Observability

### **Real-Time Monitoring**
- **Dashboard Status**: Shows current embedding provider (Gemini/Fallback)
- **API Key Rotation**: Logs show automatic key switching
- **Daily Usage**: Per-key request counts with reset notifications
- **Fallback Events**: Clear logging when switching to/from local models

### **Metrics Endpoint**
Access detailed metrics at: `http://localhost:8000/metrics`

### **Log Analysis**
```bash
# Monitor embedding provider switching
tail -f /var/log/threat-hunter.log | grep "Switched to API key"

# Track daily limit resets
tail -f /var/log/threat-hunter.log | grep "Reset daily request count"

# Watch fallback events
tail -f /var/log/threat-hunter.log | grep "Gemini.*exhausted"
```

## 🔍 Usage Examples

### **Basic Operation**
```python
# The system automatically uses Gemini embeddings
# No code changes required - it's transparent
```

### **Manual Testing**
```python
import asyncio
from gemini_embeddings import get_gemini_embedding_client

async def test_embedding():
    client = await get_gemini_embedding_client()
    embeddings = await client.embed_texts([
        "Failed authentication attempt",
        "Suspicious network activity"
    ])
    print(f"Generated embeddings: {embeddings.shape}")

asyncio.run(test_embedding())
```

### **Check Exhaustion Status**
```python
from gemini_embeddings import is_gemini_exhausted

if is_gemini_exhausted():
    print("All Gemini API keys exhausted - using fallback")
else:
    print("Gemini API available")
```

## 🛠️ Troubleshooting

### **Common Issues**

#### **1. API Key Issues**
```
Error: No Gemini API keys configured
Solution: Set GEMINI_API_KEY environment variable
```

#### **2. Rate Limiting**
```
Warning: Rate limit hit for embedding API
Solution: Add additional API keys (GEMINI_API_KEY_2, GEMINI_API_KEY_3)
```

#### **3. Daily Limits Exhausted**
```
Warning: All Gemini API keys have exceeded daily limits
Solution: Normal behavior - system automatically falls back to local models
```

#### **4. Fallback Model Missing**
```
Warning: No fallback model available
Solution: Ensure sentence-transformers is installed: pip install sentence-transformers
```

### **Debugging Steps**

1. **Verify Configuration**
   ```bash
   python test_gemini_embeddings.py
   ```

2. **Check API Key Validity**
   ```bash
   curl -H "x-goog-api-key: $GEMINI_API_KEY" \
        "https://generativelanguage.googleapis.com/v1beta/models"
   ```

3. **Monitor Logs**
   ```bash
   tail -f /var/log/threat-hunter.log | grep -E "(Gemini|embedding|fallback)"
   ```

4. **Test Fallback**
   ```bash
   # Temporarily exhaust API keys to test fallback
   export GEMINI_API_KEY="invalid_key"
   python run_app.py
   ```

## ⚡ Performance Characteristics

### **Gemini Embeddings**
- **Quality**: Superior semantic understanding with 3072 dimensions
- **Speed**: ~100ms per batch (5 texts) including network latency
- **Throughput**: Up to 100 requests/minute per API key
- **Cost**: Pay-per-use based on Google AI Studio pricing

### **SentenceTransformers Fallback**
- **Quality**: Good semantic understanding with 768 dimensions
- **Speed**: ~50ms per batch (local processing)
- **Throughput**: Limited by local hardware
- **Cost**: Free (local processing)

### **Optimization Tips**
- **Use Multiple API Keys**: Increases effective rate limits
- **Monitor Daily Usage**: Plan processing around daily resets
- **Batch Intelligently**: System automatically optimizes batch sizes
- **Cache Results**: Vector database provides persistent storage

## 🔒 Security Considerations

### **API Key Management**
- **Environment Variables**: Keys stored securely in environment only
- **No Logging**: API keys never logged or stored in files
- **Rotation Support**: Automatic switching between multiple keys
- **Secure Transmission**: HTTPS-only communication with Google APIs

### **Data Privacy**
- **Cloud Processing**: Text data sent to Google's servers for embedding
- **No Persistence**: Google doesn't store embedding requests
- **Local Fallback**: Option to use fully local processing
- **Audit Trail**: All API calls logged for monitoring

## 📈 Production Deployment

### **Recommended Setup**
- **Multiple API Keys**: 2-3 keys for redundancy
- **Monitoring**: Real-time dashboard and log monitoring
- **Alerting**: Set up alerts for fallback events
- **Backup Strategy**: Regular vector database backups

### **Scaling Considerations**
- **Daily Limits**: 1,000 requests per day per key (3,000 total with 3 keys)
- **Rate Limits**: 100 requests per minute per key (300 total with 3 keys)
- **Fallback Capacity**: Local processing continues when API exhausted
- **Storage**: Vector database scales with log volume

## 📚 References

- **Gemini Embedding API**: https://ai.google.dev/gemini-api/docs/embeddings
- **Rate Limits**: Google AI Studio quotas and limits
- **FAISS Documentation**: https://faiss.ai/
- **SentenceTransformers**: https://www.sbert.net/

---

## 🎯 Summary

This enhanced version provides production-ready Gemini embedding integration with:

✅ **Correct Rate Limiting** (100 RPM, 30K TPM, 1K RPD)  
✅ **Intelligent Fallback** (only when ALL keys exhausted)  
✅ **Multi-Key Support** (up to 3 keys for redundancy)  
✅ **Seamless Operation** (no service interruption)  
✅ **Enhanced Quality** (3072D Gemini embeddings)  
✅ **Production Ready** (comprehensive monitoring & logging)

The system maximizes the use of high-quality Gemini embeddings while ensuring continuous operation through intelligent fallback to local models when API limits are reached.