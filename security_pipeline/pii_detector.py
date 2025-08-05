"""
PII Detection Engine for Threat Hunter Pro.

This module provides comprehensive detection of personally identifiable information
including pattern-based detection, context-aware analysis, and configurable
detection rules for various types of sensitive data.
"""

from __future__ import annotations

import re
import logging
from typing import Dict, Any, List, Optional, Pattern
from dataclasses import dataclass
from enum import Enum
import hashlib


class PIIType(Enum):
    """Types of PII that can be detected."""
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    EMAIL = "email"
    PHONE = "phone"
    NAME = "name"
    ADDRESS = "address"
    DOB = "date_of_birth"
    DL_NUMBER = "drivers_license"
    PASSPORT = "passport"
    CUSTOM = "custom"


@dataclass
class PIIDetection:
    """A detected PII instance."""
    pii_type: PIIType
    value: str
    start_pos: int
    end_pos: int
    confidence: float
    context: str
    metadata: Dict[str, Any]


@dataclass
class PIIResults:
    """Results of PII detection."""
    detections: List[PIIDetection]
    total_count: int
    confidence_score: float
    processing_time_ms: float


class PIIDetector:
    """
    Advanced PII detection system with pattern-based and context-aware detection.
    
    Features:
    - Regex-based pattern matching for common PII types
    - Context-aware detection to reduce false positives
    - Configurable detection rules and sensitivity levels
    - Support for custom PII patterns
    - Confidence scoring for detections
    """
    
    # Pre-compiled regex patterns for performance
    PATTERNS = {
        PIIType.SSN: [
            re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),  # 123-45-6789
            re.compile(r'\b\d{3}\s\d{2}\s\d{4}\b'),  # 123 45 6789
            re.compile(r'\b\d{9}\b'),  # 123456789 (with context validation)
        ],
        PIIType.CREDIT_CARD: [
            re.compile(r'\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),  # Visa
            re.compile(r'\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),  # MasterCard
            re.compile(r'\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b'),  # American Express
            re.compile(r'\b6011[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),  # Discover
        ],
        PIIType.EMAIL: [
            re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        ],
        PIIType.PHONE: [
            re.compile(r'\b\d{3}-\d{3}-\d{4}\b'),  # 123-456-7890
            re.compile(r'\(\d{3}\)\s?\d{3}-\d{4}'),  # (123) 456-7890
            re.compile(r'\b\d{3}\.\d{3}\.\d{4}\b'),  # 123.456.7890
            re.compile(r'\+1[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{4}'),  # +1 123 456 7890
        ],
        PIIType.NAME: [
            # Simple name patterns - would be enhanced with NLP in production
            re.compile(r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b'),  # First Last
            re.compile(r'\b[A-Z][a-z]+\s+[A-Z]\.\s+[A-Z][a-z]+\b'),  # First M. Last
        ],
        PIIType.ADDRESS: [
            re.compile(r'\d+\s+[A-Za-z0-9\s]+\s+(Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd)', re.IGNORECASE),
        ],
        PIIType.DOB: [
            re.compile(r'\b\d{1,2}/\d{1,2}/\d{4}\b'),  # MM/DD/YYYY
            re.compile(r'\b\d{4}-\d{2}-\d{2}\b'),  # YYYY-MM-DD
            re.compile(r'\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b', re.IGNORECASE),
        ]
    }
    
    # Context keywords that may indicate false positives
    FALSE_POSITIVE_CONTEXTS = {
        PIIType.SSN: ['test', 'example', '000-00-0000', '123-45-6789'],
        PIIType.CREDIT_CARD: ['test', 'example', '0000', '1111', '1234'],
        PIIType.EMAIL: ['example.com', 'test.com', 'localhost'],
        PIIType.PHONE: ['555-555-5555', '000-000-0000', '123-456-7890'],
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the PII detector with configuration."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Detection sensitivity (0.0 - 1.0, higher = more sensitive)
        self.sensitivity = self.config.get('sensitivity', 0.8)
        
        # Minimum confidence threshold for reporting
        self.confidence_threshold = self.config.get('confidence_threshold', 0.7)
        
        # Custom patterns from configuration
        self.custom_patterns = self._load_custom_patterns()
        
        # Context window for analysis
        self.context_window = self.config.get('context_window', 50)
        
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the PII detector."""
        if self._initialized:
            return
        
        try:
            # Load any additional resources (models, dictionaries, etc.)
            self._load_resources()
            self._initialized = True
            self.logger.info("PII Detector initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize PII detector: {e}")
            raise
    
    async def detect(self, content: str, context: Optional[Dict[str, Any]] = None) -> PIIResults:
        """
        Detect PII in the given content.
        
        Args:
            content: Text content to scan for PII
            context: Additional context for detection (user, source, etc.)
            
        Returns:
            PIIResults containing all detected PII instances
        """
        if not self._initialized:
            await self.initialize()
        
        import time
        start_time = time.time()
        
        detections = []
        context = context or {}
        
        try:
            # Run pattern-based detection for each PII type
            for pii_type, patterns in self.PATTERNS.items():
                type_detections = await self._detect_pattern_based(content, pii_type, patterns)
                detections.extend(type_detections)
            
            # Run custom pattern detection
            if self.custom_patterns:
                custom_detections = await self._detect_custom_patterns(content)
                detections.extend(custom_detections)
            
            # Apply context-aware filtering
            filtered_detections = await self._filter_false_positives(content, detections)
            
            # Calculate overall confidence score
            confidence_score = self._calculate_overall_confidence(filtered_detections)
            
            processing_time = (time.time() - start_time) * 1000
            
            return PIIResults(
                detections=filtered_detections,
                total_count=len(filtered_detections),
                confidence_score=confidence_score,
                processing_time_ms=processing_time
            )
            
        except Exception as e:
            self.logger.error(f"PII detection failed: {e}")
            raise
    
    async def _detect_pattern_based(self, content: str, pii_type: PIIType, patterns: List[Pattern]) -> List[PIIDetection]:
        """Detect PII using regex patterns."""
        detections = []
        
        for pattern in patterns:
            for match in pattern.finditer(content):
                start_pos = match.start()
                end_pos = match.end()
                value = match.group()
                
                # Extract context around the match
                context_start = max(0, start_pos - self.context_window)
                context_end = min(len(content), end_pos + self.context_window)
                context_text = content[context_start:context_end]
                
                # Calculate confidence based on pattern strength and context
                confidence = self._calculate_confidence(pii_type, value, context_text)
                
                if confidence >= self.confidence_threshold:
                    detection = PIIDetection(
                        pii_type=pii_type,
                        value=value,
                        start_pos=start_pos,
                        end_pos=end_pos,
                        confidence=confidence,
                        context=context_text,
                        metadata={
                            'pattern_used': pattern.pattern,
                            'detection_method': 'regex'
                        }
                    )
                    detections.append(detection)
        
        return detections
    
    async def _detect_custom_patterns(self, content: str) -> List[PIIDetection]:
        """Detect PII using custom patterns."""
        detections = []
        
        for pattern_name, pattern_config in self.custom_patterns.items():
            pattern = pattern_config['pattern']
            pii_type = PIIType.CUSTOM
            
            for match in pattern.finditer(content):
                start_pos = match.start()
                end_pos = match.end()
                value = match.group()
                
                context_start = max(0, start_pos - self.context_window)
                context_end = min(len(content), end_pos + self.context_window)
                context_text = content[context_start:context_end]
                
                confidence = pattern_config.get('confidence', 0.8)
                
                if confidence >= self.confidence_threshold:
                    detection = PIIDetection(
                        pii_type=pii_type,
                        value=value,
                        start_pos=start_pos,
                        end_pos=end_pos,
                        confidence=confidence,
                        context=context_text,
                        metadata={
                            'custom_pattern': pattern_name,
                            'pattern_description': pattern_config.get('description', ''),
                            'detection_method': 'custom'
                        }
                    )
                    detections.append(detection)
        
        return detections
    
    async def _filter_false_positives(self, content: str, detections: List[PIIDetection]) -> List[PIIDetection]:
        """Filter out likely false positives based on context."""
        filtered = []
        
        for detection in detections:
            if self._is_likely_false_positive(detection):
                self.logger.debug(f"Filtering potential false positive: {detection.value}")
                continue
            
            filtered.append(detection)
        
        return filtered
    
    def _is_likely_false_positive(self, detection: PIIDetection) -> bool:
        """Check if a detection is likely a false positive."""
        # Check against known false positive patterns
        fp_contexts = self.FALSE_POSITIVE_CONTEXTS.get(detection.pii_type, [])
        
        for fp_context in fp_contexts:
            if fp_context.lower() in detection.context.lower() or fp_context.lower() in detection.value.lower():
                return True
        
        # Additional context-based checks
        context_lower = detection.context.lower()
        
        # Common false positive indicators
        if any(word in context_lower for word in ['example', 'test', 'sample', 'dummy', 'fake']):
            return True
        
        # SSN specific checks
        if detection.pii_type == PIIType.SSN:
            # Invalid SSN patterns
            if detection.value.replace('-', '').replace(' ', '') in ['000000000', '111111111', '123456789']:
                return True
        
        # Email specific checks
        if detection.pii_type == PIIType.EMAIL:
            # Common test domains
            test_domains = ['example.com', 'test.com', 'localhost', 'domain.com']
            if any(domain in detection.value.lower() for domain in test_domains):
                return True
        
        return False
    
    def _calculate_confidence(self, pii_type: PIIType, value: str, context: str) -> float:
        """Calculate confidence score for a detection."""
        base_confidence = 0.8
        
        # Pattern-specific confidence adjustments
        if pii_type == PIIType.SSN:
            # Check for valid SSN format and range
            clean_ssn = value.replace('-', '').replace(' ', '')
            if len(clean_ssn) == 9 and clean_ssn.isdigit():
                # Basic SSN validation (not comprehensive)
                area = int(clean_ssn[:3])
                if 1 <= area <= 899 and area not in [666]:
                    base_confidence = 0.95
                else:
                    base_confidence = 0.6
        
        elif pii_type == PIIType.CREDIT_CARD:
            # Luhn algorithm check could be added here
            if self._luhn_check(value.replace('-', '').replace(' ', '')):
                base_confidence = 0.95
            else:
                base_confidence = 0.5
        
        elif pii_type == PIIType.EMAIL:
            # Simple email validation
            if '@' in value and '.' in value.split('@')[-1]:
                base_confidence = 0.9
        
        # Context-based adjustments
        context_lower = context.lower()
        
        # Reduce confidence if in a technical/log context
        if any(word in context_lower for word in ['log', 'debug', 'trace', 'error']):
            base_confidence *= 0.9
        
        # Increase confidence if in a personal data context
        if any(word in context_lower for word in ['personal', 'identity', 'private', 'confidential']):
            base_confidence = min(base_confidence * 1.1, 1.0)
        
        return base_confidence
    
    def _luhn_check(self, card_number: str) -> bool:
        """Perform Luhn algorithm check for credit card validation."""
        def luhn_checksum(card_num):
            def digits_of(n):
                return [int(d) for d in str(n)]
            digits = digits_of(card_num)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d*2))
            return checksum % 10
        
        if not card_number.isdigit():
            return False
        
        return luhn_checksum(card_number) == 0
    
    def _calculate_overall_confidence(self, detections: List[PIIDetection]) -> float:
        """Calculate overall confidence score for all detections."""
        if not detections:
            return 1.0  # High confidence in no PII detected
        
        # Average confidence weighted by detection type importance
        total_weight = 0
        weighted_confidence = 0
        
        for detection in detections:
            weight = self._get_detection_weight(detection.pii_type)
            weighted_confidence += detection.confidence * weight
            total_weight += weight
        
        return weighted_confidence / total_weight if total_weight > 0 else 0.5
    
    def _get_detection_weight(self, pii_type: PIIType) -> float:
        """Get importance weight for different PII types."""
        weights = {
            PIIType.SSN: 1.0,
            PIIType.CREDIT_CARD: 1.0,
            PIIType.EMAIL: 0.7,
            PIIType.PHONE: 0.6,
            PIIType.NAME: 0.4,
            PIIType.ADDRESS: 0.8,
            PIIType.DOB: 0.9,
            PIIType.DL_NUMBER: 0.9,
            PIIType.PASSPORT: 1.0,
            PIIType.CUSTOM: 0.8
        }
        return weights.get(pii_type, 0.5)
    
    def _load_custom_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load custom PII patterns from configuration."""
        custom_patterns = {}
        
        patterns_config = self.config.get('custom_patterns', {})
        for name, config in patterns_config.items():
            try:
                pattern = re.compile(config['pattern'], config.get('flags', 0))
                custom_patterns[name] = {
                    'pattern': pattern,
                    'confidence': config.get('confidence', 0.8),
                    'description': config.get('description', '')
                }
            except re.error as e:
                self.logger.warning(f"Invalid custom pattern '{name}': {e}")
        
        return custom_patterns
    
    def _load_resources(self) -> None:
        """Load additional resources for PII detection."""
        # This could load:
        # - ML models for name detection
        # - Dictionaries of common names
        # - Industry-specific PII patterns
        # - External validation services
        pass