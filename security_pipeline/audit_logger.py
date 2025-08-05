"""
Security Audit Logger for Threat Hunter Pro.

This module provides comprehensive audit logging and security monitoring
capabilities including event tracking, anomaly detection, and compliance
reporting for all security-related activities.
"""

from __future__ import annotations

import json
import logging
import time
import hashlib
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timezone
import asyncio
from pathlib import Path


class AuditEventType(Enum):
    """Types of audit events."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    DATA_EXPORT = "data_export"
    PII_DETECTION = "pii_detection"
    CONTENT_REDACTION = "content_redaction"
    CONFIGURATION_CHANGE = "configuration_change"
    SECURITY_VIOLATION = "security_violation"
    SYSTEM_ERROR = "system_error"
    PROCESSING_EVENT = "processing_event"
    USER_ACTION = "user_action"
    API_ACCESS = "api_access"


class SeverityLevel(Enum):
    """Severity levels for audit events."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Represents a security audit event."""
    event_id: str
    event_type: AuditEventType
    timestamp: datetime
    severity: SeverityLevel
    user_id: Optional[str]
    session_id: Optional[str]
    source_ip: Optional[str]
    user_agent: Optional[str]
    action: str
    resource: Optional[str]
    outcome: str  # SUCCESS, FAILURE, PARTIAL
    details: Dict[str, Any]
    risk_score: float
    compliance_tags: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary."""
        data = asdict(self)
        data['event_type'] = self.event_type.value
        data['severity'] = self.severity.value
        data['timestamp'] = self.timestamp.isoformat()
        return data


@dataclass
class SecurityMetrics:
    """Security metrics for monitoring."""
    total_events: int
    events_by_type: Dict[str, int]
    events_by_severity: Dict[str, int]
    failed_authentications: int
    pii_detections: int
    security_violations: int
    high_risk_events: int
    compliance_violations: int
    last_updated: datetime


class SecurityAuditLogger:
    """
    Comprehensive security audit logging system.
    
    Features:
    - Structured audit event logging
    - Real-time security monitoring
    - Anomaly detection and alerting
    - Compliance reporting (GDPR, HIPAA, SOC 2)
    - Risk scoring and threat assessment
    - Event correlation and analysis
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the security audit logger."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Audit log configuration
        self.audit_log_path = Path(self.config.get('audit_log_path', '/var/log/threat_hunter/audit.log'))
        self.compliance_log_path = Path(self.config.get('compliance_log_path', '/var/log/threat_hunter/compliance.log'))
        self.security_log_path = Path(self.config.get('security_log_path', '/var/log/threat_hunter/security.log'))
        
        # Create log directories
        for log_path in [self.audit_log_path, self.compliance_log_path, self.security_log_path]:
            log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Event tracking
        self.event_buffer = []
        self.buffer_size = self.config.get('buffer_size', 100)
        self.flush_interval = self.config.get('flush_interval', 60)  # seconds
        
        # Security monitoring
        self.security_metrics = SecurityMetrics(
            total_events=0,
            events_by_type={},
            events_by_severity={},
            failed_authentications=0,
            pii_detections=0,
            security_violations=0,
            high_risk_events=0,
            compliance_violations=0,
            last_updated=datetime.now(timezone.utc)
        )
        
        # Anomaly detection
        self.anomaly_thresholds = self.config.get('anomaly_thresholds', {
            'failed_auth_rate': 10,  # per minute
            'pii_detection_rate': 50,  # per hour
            'high_risk_events': 5,  # per hour
            'api_error_rate': 20  # per minute
        })
        
        # Event counters for anomaly detection
        self.event_counters = {}
        
        # Background tasks
        self._flush_task = None
        self._monitoring_task = None
        
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the audit logger."""
        if self._initialized:
            return
        
        try:
            # Initialize log files
            await self._initialize_log_files()
            
            # Start background tasks
            self._flush_task = asyncio.create_task(self._flush_buffer_periodically())
            self._monitoring_task = asyncio.create_task(self._monitor_security_events())
            
            self._initialized = True
            self.logger.info("Security Audit Logger initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize audit logger: {e}")
            raise
    
    async def log_authentication(
        self,
        user_id: str,
        outcome: str,
        source_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log authentication events."""
        await self._log_event(
            event_type=AuditEventType.AUTHENTICATION,
            action="user_authentication",
            outcome=outcome,
            user_id=user_id,
            source_ip=source_ip,
            details=details or {},
            severity=SeverityLevel.HIGH if outcome == "FAILURE" else SeverityLevel.MEDIUM
        )
    
    async def log_authorization(
        self,
        user_id: str,
        resource: str,
        action: str,
        outcome: str,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log authorization events."""
        await self._log_event(
            event_type=AuditEventType.AUTHORIZATION,
            action=f"access_{action}",
            outcome=outcome,
            user_id=user_id,
            resource=resource,
            details=details or {},
            severity=SeverityLevel.HIGH if outcome == "FAILURE" else SeverityLevel.LOW
        )
    
    async def log_data_access(
        self,
        user_id: str,
        resource: str,
        action: str,
        record_count: int = 0,
        contains_pii: bool = False,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log data access events."""
        event_details = details or {}
        event_details.update({
            'record_count': record_count,
            'contains_pii': contains_pii
        })
        
        severity = SeverityLevel.HIGH if contains_pii else SeverityLevel.MEDIUM
        
        await self._log_event(
            event_type=AuditEventType.DATA_ACCESS,
            action=action,
            outcome="SUCCESS",
            user_id=user_id,
            resource=resource,
            details=event_details,
            severity=severity,
            compliance_tags=['GDPR', 'HIPAA'] if contains_pii else []
        )
    
    async def log_processing(
        self,
        content_hash: str,
        processing_mode: str,
        pii_detected: int,
        entities_preserved: int,
        confidence_score: float,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log content processing events."""
        details = {
            'content_hash': content_hash,
            'processing_mode': processing_mode,
            'pii_detected': pii_detected,
            'entities_preserved': entities_preserved,
            'confidence_score': confidence_score
        }
        
        if context:
            details['context'] = context
        
        severity = SeverityLevel.HIGH if pii_detected > 0 else SeverityLevel.LOW
        compliance_tags = ['GDPR', 'HIPAA'] if pii_detected > 0 else []
        
        await self._log_event(
            event_type=AuditEventType.CONTENT_REDACTION,
            action="content_processing",
            outcome="SUCCESS",
            details=details,
            severity=severity,
            compliance_tags=compliance_tags
        )
    
    async def log_pii_detection(
        self,
        detection_count: int,
        detection_types: List[str],
        confidence_scores: List[float],
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log PII detection events."""
        details = {
            'detection_count': detection_count,
            'detection_types': detection_types,
            'avg_confidence': sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0,
            'max_confidence': max(confidence_scores) if confidence_scores else 0
        }
        
        if context:
            details['context'] = context
        
        await self._log_event(
            event_type=AuditEventType.PII_DETECTION,
            action="pii_detection",
            outcome="SUCCESS",
            details=details,
            severity=SeverityLevel.HIGH,
            compliance_tags=['GDPR', 'HIPAA', 'PCI-DSS']
        )
    
    async def log_security_violation(
        self,
        violation_type: str,
        description: str,
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log security violations."""
        event_details = details or {}
        event_details.update({
            'violation_type': violation_type,
            'description': description
        })
        
        await self._log_event(
            event_type=AuditEventType.SECURITY_VIOLATION,
            action="security_violation",
            outcome="DETECTED",
            user_id=user_id,
            source_ip=source_ip,
            details=event_details,
            severity=SeverityLevel.CRITICAL,
            risk_score=0.9
        )
    
    async def log_configuration_change(
        self,
        user_id: str,
        setting_name: str,
        old_value: Any,
        new_value: Any,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log configuration changes."""
        event_details = details or {}
        event_details.update({
            'setting_name': setting_name,
            'old_value': str(old_value),
            'new_value': str(new_value)
        })
        
        await self._log_event(
            event_type=AuditEventType.CONFIGURATION_CHANGE,
            action="configuration_change",
            outcome="SUCCESS",
            user_id=user_id,
            details=event_details,
            severity=SeverityLevel.MEDIUM
        )
    
    async def log_api_access(
        self,
        endpoint: str,
        method: str,
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        status_code: int = 200,
        response_time_ms: float = 0,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log API access events."""
        event_details = details or {}
        event_details.update({
            'endpoint': endpoint,
            'method': method,
            'status_code': status_code,
            'response_time_ms': response_time_ms
        })
        
        outcome = "SUCCESS" if 200 <= status_code < 400 else "FAILURE"
        severity = SeverityLevel.HIGH if status_code >= 400 else SeverityLevel.LOW
        
        await self._log_event(
            event_type=AuditEventType.API_ACCESS,
            action="api_request",
            outcome=outcome,
            user_id=user_id,
            source_ip=source_ip,
            user_agent=user_agent,
            resource=endpoint,
            details=event_details,
            severity=severity
        )
    
    async def log_action(self, action: str, context: Dict[str, Any]) -> None:
        """Log a generic user action."""
        await self._log_event(
            event_type=AuditEventType.USER_ACTION,
            action=action,
            outcome="SUCCESS",
            user_id=context.get('user_id'),
            source_ip=context.get('source_ip'),
            details=context,
            severity=SeverityLevel.LOW
        )
    
    async def log_error(
        self,
        error_type: str,
        error_message: str,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log system errors."""
        details = context or {}
        details.update({
            'error_type': error_type,
            'error_message': error_message
        })
        
        await self._log_event(
            event_type=AuditEventType.SYSTEM_ERROR,
            action="system_error",
            outcome="FAILURE",
            details=details,
            severity=SeverityLevel.HIGH
        )
    
    async def _log_event(
        self,
        event_type: AuditEventType,
        action: str,
        outcome: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        resource: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: SeverityLevel = SeverityLevel.LOW,
        risk_score: float = 0.0,
        compliance_tags: Optional[List[str]] = None
    ) -> None:
        """Internal method to log audit events."""
        if not self._initialized:
            await self.initialize()
        
        # Generate event ID
        event_id = self._generate_event_id()
        
        # Calculate risk score if not provided
        if risk_score == 0.0:
            risk_score = self._calculate_risk_score(event_type, outcome, severity, details or {})
        
        # Create audit event
        event = AuditEvent(
            event_id=event_id,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            severity=severity,
            user_id=user_id,
            session_id=session_id,
            source_ip=source_ip,
            user_agent=user_agent,
            action=action,
            resource=resource,
            outcome=outcome,
            details=details or {},
            risk_score=risk_score,
            compliance_tags=compliance_tags or []
        )
        
        # Add to buffer
        self.event_buffer.append(event)
        
        # Update metrics
        await self._update_metrics(event)
        
        # Check for immediate flush conditions
        if (len(self.event_buffer) >= self.buffer_size or 
            severity == SeverityLevel.CRITICAL or
            event_type == AuditEventType.SECURITY_VIOLATION):
            await self._flush_buffer()
        
        # Check for anomalies
        await self._check_anomalies(event)
    
    async def _flush_buffer(self) -> None:
        """Flush event buffer to log files."""
        if not self.event_buffer:
            return
        
        events_to_flush = self.event_buffer.copy()
        self.event_buffer.clear()
        
        try:
            # Write to main audit log
            await self._write_to_audit_log(events_to_flush)
            
            # Write compliance events to compliance log
            compliance_events = [e for e in events_to_flush if e.compliance_tags]
            if compliance_events:
                await self._write_to_compliance_log(compliance_events)
            
            # Write high-risk events to security log
            security_events = [e for e in events_to_flush if e.risk_score >= 0.7 or e.severity == SeverityLevel.CRITICAL]
            if security_events:
                await self._write_to_security_log(security_events)
            
        except Exception as e:
            self.logger.error(f"Failed to flush audit buffer: {e}")
    
    async def _write_to_audit_log(self, events: List[AuditEvent]) -> None:
        """Write events to the main audit log."""
        with open(self.audit_log_path, 'a', encoding='utf-8') as f:
            for event in events:
                log_line = json.dumps(event.to_dict()) + '\n'
                f.write(log_line)
    
    async def _write_to_compliance_log(self, events: List[AuditEvent]) -> None:
        """Write compliance-relevant events to compliance log."""
        with open(self.compliance_log_path, 'a', encoding='utf-8') as f:
            for event in events:
                compliance_record = {
                    'event_id': event.event_id,
                    'timestamp': event.timestamp.isoformat(),
                    'compliance_tags': event.compliance_tags,
                    'action': event.action,
                    'outcome': event.outcome,
                    'user_id': event.user_id,
                    'details': event.details
                }
                log_line = json.dumps(compliance_record) + '\n'
                f.write(log_line)
    
    async def _write_to_security_log(self, events: List[AuditEvent]) -> None:
        """Write high-risk events to security log."""
        with open(self.security_log_path, 'a', encoding='utf-8') as f:
            for event in events:
                security_record = {
                    'event_id': event.event_id,
                    'timestamp': event.timestamp.isoformat(),
                    'event_type': event.event_type.value,
                    'severity': event.severity.value,
                    'risk_score': event.risk_score,
                    'action': event.action,
                    'outcome': event.outcome,
                    'user_id': event.user_id,
                    'source_ip': event.source_ip,
                    'details': event.details
                }
                log_line = json.dumps(security_record) + '\n'
                f.write(log_line)
    
    async def _update_metrics(self, event: AuditEvent) -> None:
        """Update security metrics."""
        self.security_metrics.total_events += 1
        
        # Update type counters
        event_type_str = event.event_type.value
        self.security_metrics.events_by_type[event_type_str] = \
            self.security_metrics.events_by_type.get(event_type_str, 0) + 1
        
        # Update severity counters
        severity_str = event.severity.value
        self.security_metrics.events_by_severity[severity_str] = \
            self.security_metrics.events_by_severity.get(severity_str, 0) + 1
        
        # Update specific counters
        if event.event_type == AuditEventType.AUTHENTICATION and event.outcome == "FAILURE":
            self.security_metrics.failed_authentications += 1
        
        if event.event_type == AuditEventType.PII_DETECTION:
            self.security_metrics.pii_detections += 1
        
        if event.event_type == AuditEventType.SECURITY_VIOLATION:
            self.security_metrics.security_violations += 1
        
        if event.risk_score >= 0.7:
            self.security_metrics.high_risk_events += 1
        
        if event.compliance_tags:
            self.security_metrics.compliance_violations += 1
        
        self.security_metrics.last_updated = datetime.now(timezone.utc)
    
    async def _check_anomalies(self, event: AuditEvent) -> None:
        """Check for security anomalies and trigger alerts."""
        current_time = time.time()
        
        # Check authentication failure rate
        if event.event_type == AuditEventType.AUTHENTICATION and event.outcome == "FAILURE":
            await self._check_rate_anomaly('failed_auth', current_time, 60)  # per minute
        
        # Check PII detection rate
        if event.event_type == AuditEventType.PII_DETECTION:
            await self._check_rate_anomaly('pii_detection', current_time, 3600)  # per hour
        
        # Check high-risk event rate
        if event.risk_score >= 0.7:
            await self._check_rate_anomaly('high_risk', current_time, 3600)  # per hour
    
    async def _check_rate_anomaly(self, event_type: str, current_time: float, window_seconds: int) -> None:
        """Check if event rate exceeds threshold."""
        if event_type not in self.event_counters:
            self.event_counters[event_type] = []
        
        # Add current event
        self.event_counters[event_type].append(current_time)
        
        # Remove old events outside the window
        cutoff_time = current_time - window_seconds
        self.event_counters[event_type] = [
            t for t in self.event_counters[event_type] if t >= cutoff_time
        ]
        
        # Check against threshold
        count = len(self.event_counters[event_type])
        threshold = self.anomaly_thresholds.get(f"{event_type}_rate", float('inf'))
        
        if count >= threshold:
            await self.log_security_violation(
                violation_type="rate_anomaly",
                description=f"High {event_type} rate detected: {count} events in {window_seconds}s",
                details={
                    'event_type': event_type,
                    'count': count,
                    'threshold': threshold,
                    'window_seconds': window_seconds
                }
            )
    
    def _calculate_risk_score(
        self,
        event_type: AuditEventType,
        outcome: str,
        severity: SeverityLevel,
        details: Dict[str, Any]
    ) -> float:
        """Calculate risk score for an event."""
        base_scores = {
            AuditEventType.AUTHENTICATION: 0.3,
            AuditEventType.AUTHORIZATION: 0.2,
            AuditEventType.DATA_ACCESS: 0.4,
            AuditEventType.PII_DETECTION: 0.7,
            AuditEventType.SECURITY_VIOLATION: 0.9,
            AuditEventType.CONFIGURATION_CHANGE: 0.5,
            AuditEventType.SYSTEM_ERROR: 0.3
        }
        
        base_score = base_scores.get(event_type, 0.1)
        
        # Adjust for outcome
        if outcome == "FAILURE":
            base_score *= 1.5
        elif outcome == "PARTIAL":
            base_score *= 1.2
        
        # Adjust for severity
        severity_multipliers = {
            SeverityLevel.LOW: 1.0,
            SeverityLevel.MEDIUM: 1.3,
            SeverityLevel.HIGH: 1.6,
            SeverityLevel.CRITICAL: 2.0
        }
        
        base_score *= severity_multipliers.get(severity, 1.0)
        
        # Cap at 1.0
        return min(base_score, 1.0)
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        timestamp = str(int(time.time() * 1000000))  # microseconds
        random_data = str(hash(time.time()))
        return hashlib.md5(f"{timestamp}{random_data}".encode()).hexdigest()[:16]
    
    async def _flush_buffer_periodically(self) -> None:
        """Background task to flush buffer periodically."""
        while True:
            try:
                await asyncio.sleep(self.flush_interval)
                await self._flush_buffer()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in periodic buffer flush: {e}")
    
    async def _monitor_security_events(self) -> None:
        """Background task for security monitoring."""
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes
                # Implement additional monitoring logic here
                pass
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in security monitoring: {e}")
    
    async def _initialize_log_files(self) -> None:
        """Initialize audit log files with headers."""
        # Create files if they don't exist
        for log_path in [self.audit_log_path, self.compliance_log_path, self.security_log_path]:
            if not log_path.exists():
                log_path.touch()
    
    async def get_security_metrics(self) -> SecurityMetrics:
        """Get current security metrics."""
        return self.security_metrics
    
    async def shutdown(self) -> None:
        """Shutdown the audit logger gracefully."""
        if self._flush_task:
            self._flush_task.cancel()
        if self._monitoring_task:
            self._monitoring_task.cancel()
        
        # Final buffer flush
        await self._flush_buffer()
        
        self.logger.info("Security Audit Logger shutdown complete")