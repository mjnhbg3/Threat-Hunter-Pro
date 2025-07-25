# Wazuh Threat Hunter Pro (Gemini Edition)

An advanced AI-powered threat hunting application designed for comprehensive security log analysis using Google's Gemini AI models.

## 🚀 Features

### Core Capabilities
- **Multi-stage Comprehensive Retrieval**: Advanced log search with 5 different strategies (entity-exact, related-term, semantic-context, broad-context, rule-based)
- **Hybrid Search**: Combines FAISS semantic search with BM25 keyword search for optimal relevance
- **Named Entity Recognition (NER)**: Extracts cybersecurity entities using spaCy with entity boosting (3x repetition)
- **AI-Powered Analysis**: Enhanced threat detection with 150-200+ log context vs traditional 5-10 logs
- **Real-time Dashboard**: Interactive web interface with live status updates and countdown timers
- **Intelligent Rate Limiting**: Model-specific API key rotation with immediate failover on rate limits

### Technical Features
- **FastAPI Framework**: High-performance async web framework with authentication
- **Vector Database**: FAISS-based semantic search with metadata management
- **Token Bucket Rate Limiting**: Per-model rate limiting (Pro: 5 RPM, Flash: 10 RPM, Flash-Lite: 15 RPM)
- **Automatic Error Recovery**: AI-assisted JSON repair and model fallback chains
- **Settings Migration**: Automatic upgrade of configuration parameters
- **Background Processing**: Continuous log monitoring with 10-minute scan intervals

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- Google AI Studio API keys
- Wazuh installation (optional, for live log processing)

### Setup
1. Clone the repository:
```bash
git clone https://github.com/mjnhbg3/Threat-Hunter-Pro.git
cd Threat-Hunter-Pro
```

2. Install dependencies:
```bash
pip install -r requirements.txt
python install_dependencies.py
```

3. Configure environment variables:
```bash
export GEMINI_API_KEY="your_primary_api_key"
export GEMINI_API_KEY_2="your_secondary_api_key"  # Optional
export GEMINI_API_KEY_3="your_tertiary_api_key"   # Optional
export BASIC_AUTH_USER="admin"
export BASIC_AUTH_PASS="your_secure_password"
```

4. Run the application:
```bash
python run_app.py
```

5. Access the dashboard:
```
http://localhost:8000
```

## 🔧 Configuration

### API Rate Limits
The application automatically manages Google AI Studio rate limits:
- **Gemini 2.5 Pro**: 5 RPM, 250K TPM, 100 RPD
- **Gemini 2.5 Flash**: 10 RPM, 250K TPM, 250 RPD  
- **Gemini 2.5 Flash-Lite**: 15 RPM, 250K TPM, 1,000 RPD

### Settings
- **Processing Interval**: 10 minutes (600 seconds)
- **Search Results**: Up to 500 logs per query
- **Max Output Tokens**: 32,000 per response
- **Context Window**: 200,000 tokens

## 📊 Usage

### Dashboard Features
- **Real-time Status**: Live application status with countdown to next scan
- **Issue Tracking**: Categorized security issues with severity levels
- **Log Analysis**: Detailed log examination with AI-powered insights
- **Chat Interface**: Interactive threat hunting with context-aware responses
- **Settings Management**: Configurable scan intervals and analysis parameters

### API Endpoints
- `/api/dashboard` - Dashboard data
- `/api/chat` - Interactive chat interface
- `/api/analyze/{issue_id}` - Issue analysis
- `/api/generate-script/{issue_id}` - Remediation script generation
- `/metrics` - Prometheus metrics

## 🧠 AI Models

The application uses Google's Gemini 2.5 models:
- **Pro Model**: Advanced reasoning for complex analysis
- **Flash Model**: Balanced performance for general tasks
- **Flash-Lite Model**: Fast processing for simple queries

Automatic model fallback ensures continuous operation even if specific models are unavailable.

## 🔍 Search Capabilities

### Multi-stage Retrieval
1. **Entity-Exact Search**: Direct entity matching
2. **Related-Term Search**: Semantic similarity for entities
3. **Semantic-Context Search**: Vector-based contextual search
4. **Broad-Context Search**: Expanded semantic matching
5. **Rule-Based Search**: Pattern-based log filtering

### Entity Recognition
Extracts and prioritizes:
- IP addresses and domains
- File paths and hashes
- User accounts and processes
- Security rule identifiers
- Network protocols and ports

## 📈 Monitoring

Built-in metrics collection for:
- API request rates and errors
- Processing cycle times
- Rate limit usage per model
- Search performance statistics
- Background worker health

## 🔐 Security

- HTTP Basic Authentication
- API key rotation and management
- Secure configuration storage
- Rate limit protection
- Input validation and sanitization

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is open source. Please ensure you comply with Google AI Studio's terms of service when using their API.

## 🙏 Acknowledgments

- Built with Claude Code assistance
- Powered by Google Gemini AI models
- Uses spaCy for NER capabilities
- FAISS for vector similarity search
- FastAPI for web framework

---

**Note**: This application is designed for defensive security purposes only. Always ensure proper authorization before analyzing network logs and systems.