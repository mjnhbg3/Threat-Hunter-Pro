"""
Security Middleware for Threat Hunter Pro.

This module provides comprehensive security middleware including security headers,
CORS configuration, rate limiting, and request filtering.
"""

from __future__ import annotations

import time
import logging
import hashlib
from typing import Dict, Any, Optional, List, Callable, Awaitable
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from fastapi import Request, Response, HTTPException
from fastapi.middleware.base import BaseHTTPMiddleware
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import JSONResponse


@dataclass
class SecurityHeaders:
    """Security headers configuration."""
    content_security_policy: str = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'"
    x_content_type_options: str = "nosniff"
    x_frame_options: str = "DENY"
    x_xss_protection: str = "1; mode=block"
    strict_transport_security: str = "max-age=31536000; includeSubDomains"
    referrer_policy: str = "strict-origin-when-cross-origin"
    permissions_policy: str = "geolocation=(), microphone=(), camera=()"
    cache_control: str = "no-cache, no-store, must-revalidate"
    pragma: str = "no-cache"
    expires: str = "0"


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    requests_per_day: int = 10000
    burst_limit: int = 10
    enabled: bool = True
    whitelist_ips: List[str] = None
    
    def __post_init__(self):
        if self.whitelist_ips is None:
            self.whitelist_ips = []


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive security middleware.
    
    Features:
    - Security headers injection
    - Rate limiting per IP
    - Request size limiting
    - Suspicious request detection
    - IP filtering and blocking
    - Request timing and monitoring
    """
    
    def __init__(
        self,
        app,
        config: Optional[Dict[str, Any]] = None,
        security_headers: Optional[SecurityHeaders] = None,
        rate_limit_config: Optional[RateLimitConfig] = None
    ):
        """Initialize security middleware."""
        super().__init__(app)
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Security configuration
        self.security_headers = security_headers or SecurityHeaders()
        self.rate_limit_config = rate_limit_config or RateLimitConfig()
        
        # Request filtering
        self.max_request_size = self.config.get('max_request_size', 10 * 1024 * 1024)  # 10MB
        self.blocked_ips: set = set(self.config.get('blocked_ips', []))
        self.allowed_ips: set = set(self.config.get('allowed_ips', []))
        self.suspicious_user_agents = self.config.get('suspicious_user_agents', [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'nessus', 'openvas'
        ])
        
        # Rate limiting storage
        self.rate_limit_storage: Dict[str, Dict[str, Any]] = {}
        
        # Request monitoring
        self.request_stats: Dict[str, Any] = {
            'total_requests': 0,
            'blocked_requests': 0,
            'rate_limited_requests': 0,
            'suspicious_requests': 0,
            'start_time': time.time()
        }
        
        # Security event callback
        self.security_event_callback: Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]] = None
    
    def set_security_event_callback(self, callback: Callable[[str, Dict[str, Any]], Awaitable[None]]) -> None:
        """Set callback for security events."""
        self.security_event_callback = callback
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Process request through security middleware."""
        start_time = time.time()
        self.request_stats['total_requests'] += 1
        
        try:
            # Get client IP
            client_ip = self._get_client_ip(request)
            
            # Pre-request security checks
            security_check_result = await self._pre_request_security_checks(request, client_ip)
            if security_check_result is not None:
                return security_check_result
            
            # Process request
            response = await call_next(request)
            
            # Post-request processing
            await self._post_request_processing(request, response, client_ip, start_time)
            
            # Add security headers
            self._add_security_headers(response)
            
            return response
            
        except Exception as e:
            self.logger.error(f"Security middleware error: {e}")
            
            # Log security event
            await self._log_security_event("middleware_error", {
                'error': str(e),
                'client_ip': client_ip if 'client_ip' in locals() else 'unknown',
                'path': request.url.path,
                'method': request.method
            })
            
            # Return error response with security headers
            error_response = JSONResponse(
                status_code=500,
                content={'error': 'Internal server error'}
            )
            self._add_security_headers(error_response)
            return error_response
    
    async def _pre_request_security_checks(self, request: Request, client_ip: str) -> Optional[Response]:
        """Perform pre-request security checks."""
        try:
            # IP filtering
            if await self._is_ip_blocked(client_ip):
                self.request_stats['blocked_requests'] += 1
                await self._log_security_event("ip_blocked", {
                    'client_ip': client_ip,
                    'path': request.url.path,
                    'method': request.method
                })
                return self._create_blocked_response("Access denied")
            
            # Rate limiting
            if self.rate_limit_config.enabled and not await self._check_rate_limit(client_ip):
                self.request_stats['rate_limited_requests'] += 1
                await self._log_security_event("rate_limit_exceeded", {
                    'client_ip': client_ip,
                    'path': request.url.path,
                    'method': request.method
                })
                return self._create_rate_limit_response()
            
            # Request size check
            content_length = request.headers.get('content-length')
            if content_length and int(content_length) > self.max_request_size:
                await self._log_security_event("request_too_large", {
                    'client_ip': client_ip,
                    'content_length': content_length,
                    'max_size': self.max_request_size
                })
                return self._create_blocked_response("Request too large")
            
            # User agent checks
            user_agent = request.headers.get('user-agent', '').lower()
            if any(suspicious in user_agent for suspicious in self.suspicious_user_agents):
                self.request_stats['suspicious_requests'] += 1
                await self._log_security_event("suspicious_user_agent", {
                    'client_ip': client_ip,
                    'user_agent': user_agent,
                    'path': request.url.path
                })
                return self._create_blocked_response("Suspicious user agent")
            
            # Path traversal check
            if '../' in str(request.url.path) or '..\\' in str(request.url.path):
                await self._log_security_event("path_traversal_attempt", {
                    'client_ip': client_ip,
                    'path': request.url.path
                })
                return self._create_blocked_response("Invalid path")
            
            # Method filtering (if configured)
            allowed_methods = self.config.get('allowed_methods')
            if allowed_methods and request.method not in allowed_methods:
                await self._log_security_event("method_not_allowed", {
                    'client_ip': client_ip,
                    'method': request.method,
                    'path': request.url.path
                })
                return self._create_blocked_response("Method not allowed", status_code=405)
            
            return None  # All checks passed
            
        except Exception as e:
            self.logger.error(f"Pre-request security check failed: {e}")
            return self._create_blocked_response("Security check failed")
    
    async def _post_request_processing(self, request: Request, response: Response, client_ip: str, start_time: float) -> None:
        """Perform post-request processing."""
        try:
            processing_time = time.time() - start_time
            
            # Log slow requests
            slow_request_threshold = self.config.get('slow_request_threshold', 5.0)
            if processing_time > slow_request_threshold:
                await self._log_security_event("slow_request", {
                    'client_ip': client_ip,
                    'path': request.url.path,
                    'method': request.method,
                    'processing_time': processing_time
                })
            
            # Log error responses
            if response.status_code >= 400:
                await self._log_security_event("error_response", {
                    'client_ip': client_ip,
                    'path': request.url.path,
                    'method': request.method,
                    'status_code': response.status_code,
                    'processing_time': processing_time
                })
            
        except Exception as e:
            self.logger.error(f"Post-request processing failed: {e}")
    
    async def _is_ip_blocked(self, client_ip: str) -> bool:
        """Check if IP is blocked."""
        # Check explicit block list
        if client_ip in self.blocked_ips:
            return True
        
        # Check allow list (if configured, only allow listed IPs)
        if self.allowed_ips and client_ip not in self.allowed_ips:
            return True
        
        # Check for automatic blocking based on behavior
        ip_stats = self.rate_limit_storage.get(client_ip, {})
        
        # Block if too many violations
        violations = ip_stats.get('violations', 0)
        if violations > self.config.get('max_violations', 10):
            return True
        
        return False
    
    async def _check_rate_limit(self, client_ip: str) -> bool:
        """Check rate limiting for IP."""
        if client_ip in self.rate_limit_config.whitelist_ips:
            return True
        
        now = datetime.now(timezone.utc)
        
        # Get or create IP stats
        if client_ip not in self.rate_limit_storage:
            self.rate_limit_storage[client_ip] = {
                'requests': [],
                'violations': 0,
                'last_violation': None
            }
        
        ip_stats = self.rate_limit_storage[client_ip]
        
        # Clean old requests
        cutoff_time = now - timedelta(minutes=1)
        ip_stats['requests'] = [
            req_time for req_time in ip_stats['requests']
            if req_time > cutoff_time
        ]
        
        # Check rate limits
        requests_in_minute = len(ip_stats['requests'])
        
        if requests_in_minute >= self.rate_limit_config.requests_per_minute:
            ip_stats['violations'] += 1
            ip_stats['last_violation'] = now
            return False
        
        # Check burst limit
        recent_requests = [
            req_time for req_time in ip_stats['requests']
            if req_time > now - timedelta(seconds=10)
        ]
        
        if len(recent_requests) >= self.rate_limit_config.burst_limit:
            ip_stats['violations'] += 1
            ip_stats['last_violation'] = now
            return False
        
        # Add current request
        ip_stats['requests'].append(now)
        
        return True
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        # Check X-Forwarded-For header (from proxy/load balancer)
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            # Take the first IP (original client)
            return forwarded_for.split(',')[0].strip()
        
        # Check X-Real-IP header
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip.strip()
        
        # Fallback to client host
        return request.client.host if request.client else 'unknown'
    
    def _add_security_headers(self, response: Response) -> None:
        """Add security headers to response."""
        headers = {
            'Content-Security-Policy': self.security_headers.content_security_policy,
            'X-Content-Type-Options': self.security_headers.x_content_type_options,
            'X-Frame-Options': self.security_headers.x_frame_options,
            'X-XSS-Protection': self.security_headers.x_xss_protection,
            'Strict-Transport-Security': self.security_headers.strict_transport_security,
            'Referrer-Policy': self.security_headers.referrer_policy,
            'Permissions-Policy': self.security_headers.permissions_policy,
            'Cache-Control': self.security_headers.cache_control,
            'Pragma': self.security_headers.pragma,
            'Expires': self.security_headers.expires,
            'X-Request-ID': self._generate_request_id()
        }
        
        for header_name, header_value in headers.items():
            response.headers[header_name] = header_value
    
    def _create_blocked_response(self, message: str = "Access denied", status_code: int = 403) -> Response:
        """Create a blocked request response."""
        response = JSONResponse(
            status_code=status_code,
            content={'error': message}
        )
        self._add_security_headers(response)
        return response
    
    def _create_rate_limit_response(self) -> Response:
        """Create a rate limit exceeded response."""
        response = JSONResponse(
            status_code=429,
            content={'error': 'Rate limit exceeded'}
        )
        
        # Add rate limit headers
        response.headers['Retry-After'] = '60'
        response.headers['X-RateLimit-Limit'] = str(self.rate_limit_config.requests_per_minute)
        response.headers['X-RateLimit-Remaining'] = '0'
        response.headers['X-RateLimit-Reset'] = str(int(time.time()) + 60)
        
        self._add_security_headers(response)
        return response
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID."""
        return hashlib.md5(f"{time.time()}:{self.request_stats['total_requests']}".encode()).hexdigest()[:12]
    
    async def _log_security_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Log security event."""
        try:
            if self.security_event_callback:
                await self.security_event_callback(event_type, details)
            else:
                self.logger.warning(f"Security event: {event_type} - {details}")
        except Exception as e:
            self.logger.error(f"Failed to log security event: {e}")
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security statistics."""
        uptime = time.time() - self.request_stats['start_time']
        
        return {
            'uptime_seconds': uptime,
            'total_requests': self.request_stats['total_requests'],
            'blocked_requests': self.request_stats['blocked_requests'],
            'rate_limited_requests': self.request_stats['rate_limited_requests'],
            'suspicious_requests': self.request_stats['suspicious_requests'],
            'requests_per_second': self.request_stats['total_requests'] / max(uptime, 1),
            'blocked_percentage': (self.request_stats['blocked_requests'] / max(self.request_stats['total_requests'], 1)) * 100,
            'active_ips': len(self.rate_limit_storage),
            'blocked_ips': list(self.blocked_ips)
        }
    
    def block_ip(self, ip_address: str, reason: str = "Manual block") -> None:
        """Manually block an IP address."""
        self.blocked_ips.add(ip_address)
        self.logger.info(f"IP blocked: {ip_address} - {reason}")
    
    def unblock_ip(self, ip_address: str) -> None:
        """Unblock an IP address."""
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            self.logger.info(f"IP unblocked: {ip_address}")
    
    def clear_rate_limit(self, ip_address: str) -> None:
        """Clear rate limit data for an IP."""
        if ip_address in self.rate_limit_storage:
            del self.rate_limit_storage[ip_address]
            self.logger.info(f"Rate limit cleared for IP: {ip_address}")


def create_cors_middleware(config: Optional[Dict[str, Any]] = None) -> CORSMiddleware:
    """Create CORS middleware with secure defaults."""
    cors_config = config or {}
    
    return CORSMiddleware(
        allow_origins=cors_config.get('allow_origins', []),
        allow_credentials=cors_config.get('allow_credentials', False),
        allow_methods=cors_config.get('allow_methods', ['GET', 'POST']),
        allow_headers=cors_config.get('allow_headers', [
            'Content-Type',
            'Authorization',
            'X-Requested-With',
            'X-Request-ID'
        ]),
        expose_headers=cors_config.get('expose_headers', ['X-Request-ID']),
        max_age=cors_config.get('max_age', 86400)
    )