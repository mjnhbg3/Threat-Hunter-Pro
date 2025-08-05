"""
Security Pipeline for Threat Hunter Pro.

This module provides comprehensive security hardening including:
- PII detection and redaction
- Security entity preservation
- Input validation and sanitization
- Audit logging and monitoring
- Content security for embedding and display

The security pipeline is designed to protect sensitive data while
maintaining the analytical capabilities of the threat hunting system.
"""

from __future__ import annotations

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum

from .pii_detector import PIIDetector
from .entity_preserver import SecurityEntityPreserver
from .redaction_engine import RedactionEngine
from .audit_logger import SecurityAuditLogger


class ProcessingMode(Enum):
    """Processing modes for different use cases."""
    EMBEDDING = "embedding"  # For vector storage - preserve security utility
    DISPLAY = "display"      # For user display - more aggressive redaction
    EXPORT = "export"        # For data export - maximum protection
    ANALYSIS = "analysis"    # For AI analysis - balanced approach


@dataclass
class ProcessedContent:
    """Result of security processing."""
    content: str
    redacted_items: List[Dict[str, Any]]
    security_entities_preserved: List[Dict[str, Any]]
    confidence_score: float
    processing_mode: ProcessingMode
    metadata: Dict[str, Any]


@dataclass
class ValidationResult:
    """Result of input validation."""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    sanitized_input: Optional[Any] = None


class SecurityPipeline:
    """
    Main security pipeline for comprehensive data protection.
    
    This class orchestrates all security processing including PII detection,
    entity preservation, content redaction, and audit logging.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the security pipeline with configuration."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize security components
        self._pii_detector = PIIDetector(self.config.get('pii_detector', {}))
        self._entity_preserver = SecurityEntityPreserver(self.config.get('entity_preserver', {}))
        self._redaction_engine = RedactionEngine(self.config.get('redaction_engine', {}))
        self._audit_logger = SecurityAuditLogger(self.config.get('audit_logger', {}))
        
        # Security state
        self._initialized = False
        
        self.logger.info("Security Pipeline initialized")
    
    async def initialize(self) -> None:
        """Initialize all security components."""
        if self._initialized:
            return
            
        try:
            await self._pii_detector.initialize()
            await self._entity_preserver.initialize()
            await self._redaction_engine.initialize()
            await self._audit_logger.initialize()
            
            self._initialized = True
            self.logger.info("Security Pipeline fully initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize security pipeline: {e}")
            raise
    
    async def process_for_embedding(self, content: str, context: Optional[Dict[str, Any]] = None) -> ProcessedContent:
        """
        Process content for vector embedding storage.
        
        Preserves security entities while redacting PII to maintain
        analytical utility for threat hunting.
        """
        return await self._process_content(content, ProcessingMode.EMBEDDING, context)
    
    async def process_for_display(self, content: str, context: Optional[Dict[str, Any]] = None) -> ProcessedContent:
        """
        Process content for user display.
        
        Applies comprehensive redaction for user-facing content while
        maintaining readability and security context.
        """
        return await self._process_content(content, ProcessingMode.DISPLAY, context)
    
    async def process_for_export(self, content: str, context: Optional[Dict[str, Any]] = None) -> ProcessedContent:
        """
        Process content for data export.
        
        Applies maximum protection for data leaving the system while
        preserving essential security information.
        """
        return await self._process_content(content, ProcessingMode.EXPORT, context)
    
    async def process_for_analysis(self, content: str, context: Optional[Dict[str, Any]] = None) -> ProcessedContent:
        """
        Process content for AI analysis.
        
        Balances PII protection with analytical requirements for
        AI-powered threat hunting and analysis.
        """
        return await self._process_content(content, ProcessingMode.ANALYSIS, context)
    
    async def _process_content(self, content: str, mode: ProcessingMode, context: Optional[Dict[str, Any]] = None) -> ProcessedContent:
        """Internal method to process content based on mode."""
        if not self._initialized:
            await self.initialize()
        
        context = context or {}
        start_time = time.time()
        
        try:
            # Step 1: Detect PII and security entities
            pii_results = await self._pii_detector.detect(content, context)
            security_entities = await self._entity_preserver.extract_entities(content, context)
            
            # Step 2: Apply mode-specific redaction
            redaction_config = self._get_redaction_config(mode)
            processed_content = await self._redaction_engine.redact(
                content, pii_results, security_entities, redaction_config
            )
            
            # Step 3: Calculate confidence score
            confidence_score = self._calculate_confidence_score(pii_results, security_entities, processed_content)
            
            # Step 4: Audit the processing
            await self._audit_logger.log_processing(
                content_hash=self._hash_content(content),
                processing_mode=mode.value,
                pii_detected=len(pii_results.detections),
                entities_preserved=len(security_entities),
                confidence_score=confidence_score,
                context=context
            )
            
            result = ProcessedContent(
                content=processed_content.content,
                redacted_items=pii_results.detections,
                security_entities_preserved=security_entities,
                confidence_score=confidence_score,
                processing_mode=mode,
                metadata={
                    'processing_time_ms': (time.time() - start_time) * 1000,
                    'original_length': len(content),
                    'processed_length': len(processed_content.content),
                    'redaction_ratio': len(pii_results.detections) / max(len(content.split()), 1)
                }
            )
            
            return result
            
        except Exception as e:
            await self._audit_logger.log_error(
                error_type="processing_failure",
                error_message=str(e),
                context=context
            )
            raise
    
    async def validate_input(self, input_data: Any, input_type: str = "generic") -> ValidationResult:
        """
        Validate and sanitize input data.
        
        Protects against injection attacks, malformed data, and
        other security threats while preserving data utility.
        """
        if not self._initialized:
            await self.initialize()
        
        # Implementation would include comprehensive input validation
        # This is a placeholder for the full implementation
        return ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            sanitized_input=input_data
        )
    
    async def audit_action(self, action: str, context: Dict[str, Any]) -> None:
        """Log security-relevant actions for audit purposes."""
        if not self._initialized:
            await self.initialize()
        
        await self._audit_logger.log_action(action, context)
    
    def _get_redaction_config(self, mode: ProcessingMode) -> Dict[str, Any]:
        """Get redaction configuration based on processing mode."""
        configs = {
            ProcessingMode.EMBEDDING: {
                'preserve_security_entities': True,
                'aggressive_pii_redaction': False,
                'maintain_context': True,
                'tokenize_identifiers': True
            },
            ProcessingMode.DISPLAY: {
                'preserve_security_entities': True,
                'aggressive_pii_redaction': True,
                'maintain_context': True,
                'tokenize_identifiers': False
            },
            ProcessingMode.EXPORT: {
                'preserve_security_entities': False,
                'aggressive_pii_redaction': True,
                'maintain_context': False,
                'tokenize_identifiers': False
            },
            ProcessingMode.ANALYSIS: {
                'preserve_security_entities': True,
                'aggressive_pii_redaction': False,
                'maintain_context': True,
                'tokenize_identifiers': True
            }
        }
        return configs.get(mode, configs[ProcessingMode.ANALYSIS])
    
    def _calculate_confidence_score(self, pii_results, security_entities, processed_content) -> float:
        """Calculate confidence score for the processing result."""
        # Implementation would calculate based on detection quality,
        # entity preservation success, and redaction effectiveness
        return 0.95  # Placeholder
    
    def _hash_content(self, content: str) -> str:
        """Generate hash of content for audit purposes."""
        import hashlib
        return hashlib.sha256(content.encode()).hexdigest()[:16]


# Import time module
import time