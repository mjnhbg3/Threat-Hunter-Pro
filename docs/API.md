# Threat Hunter Pro: API Reference

## Overview
Threat Hunter Pro provides a comprehensive set of API endpoints for threat hunting, log analysis, and system interaction.

## Authentication
All API endpoints require authentication via:
- HTTP Basic Authentication
- Bearer Token
- API Key

### Authentication Headers
```
Authorization: Basic base64(username:password)
Authorization: Bearer {token}
X-API-Key: {your_api_key}
```

## API Endpoints

### 1. Dashboard Endpoints

#### GET /api/dashboard
Retrieve current system dashboard metrics

**Response**:
```json
{
    "system_status": "operational",
    "active_scans": 3,
    "pending_issues": 12,
    "last_scan_time": "2025-08-01T14:30:22Z",
    "models_status": {
        "gemini_pro": "active",
        "gemini_flash": "active"
    }
}
```

### 2. Log Analysis Endpoints

#### POST /api/analyze/logs
Perform comprehensive log analysis

**Request Body**:
```json
{
    "log_sources": ["wazuh", "firewall"],
    "time_range": "last_24h",
    "search_strategies": ["semantic", "rule_based"],
    "entities_of_interest": ["ip", "user"]
}
```

**Response**:
```json
{
    "total_logs_analyzed": 15342,
    "potential_threats": 37,
    "key_findings": [
        {
            "threat_level": "high",
            "description": "Unusual login pattern detected",
            "affected_entities": ["user:admin", "ip:192.168.1.100"]
        }
    ]
}
```

### 3. Threat Hunting Endpoints

#### GET /api/threats
Retrieve current and historical threat information

**Query Parameters**:
- `severity`: Filter by threat severity
- `start_date`: Start of time range
- `end_date`: End of time range

#### POST /api/generate-script/{issue_id}
Generate remediation script for a specific issue

### 4. Search Endpoints

#### POST /api/search
Perform multi-strategy log search

**Supported Search Strategies**:
- Entity-Exact
- Related-Term
- Semantic-Context
- Broad-Context
- Rule-Based

### 5. Configuration Endpoints

#### GET /api/config
Retrieve current system configuration

#### PUT /api/config
Update system configuration

## Rate Limiting
- **Gemini Pro**: 5 requests/minute
- **Gemini Flash**: 10 requests/minute
- **Gemini Flash-Lite**: 15 requests/minute

## Error Handling
Standard error response format:
```json
{
    "error": true,
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit for Gemini Pro model exceeded",
    "retry_after": 60
}
```

## Webhooks
Configure external integrations via webhook endpoints for real-time threat notifications.

## SDK Availability
- Python SDK
- JavaScript/TypeScript Client
- Golang Client
- Rust Client

## Compliance and Security
- HTTPS only
- TLS 1.3
- RBAC enforced
- Comprehensive audit logging