"""
Content Redaction Engine for Threat Hunter Pro.

This module provides sophisticated content redaction capabilities that balance
privacy protection with security analysis needs. It supports multiple redaction
strategies and preserves security-relevant context.
"""

from __future__ import annotations

import re
import logging
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from .pii_detector import PIIResults, PIIDetection, PIIType
from .entity_preserver import SecurityEntity, SecurityEntityType


class RedactionStrategy(Enum):
    """Different redaction strategies available."""
    TOKENIZE = "tokenize"          # Replace with consistent tokens
    MASK = "mask"                  # Partial masking (e.g., 555-***-****)
    HASH = "hash"                  # One-way hash for correlation
    REMOVE = "remove"              # Complete removal
    ANONYMIZE = "anonymize"        # Statistical anonymization
    PRESERVE = "preserve"          # Keep original (for security entities)


@dataclass
class RedactionRule:
    """Configuration for how to redact specific PII types."""
    pii_type: PIIType
    strategy: RedactionStrategy
    preserve_format: bool = True
    confidence_threshold: float = 0.7
    context_preservation: int = 0  # Characters to preserve around redacted content


@dataclass
class RedactionResult:
    """Result of content redaction."""
    content: str
    redactions_applied: List[Dict[str, Any]]
    entities_preserved: List[Dict[str, Any]]
    redaction_ratio: float
    metadata: Dict[str, Any]


class RedactionEngine:
    """
    Advanced content redaction engine with configurable strategies.
    
    This engine applies sophisticated redaction techniques that:
    - Preserve security analysis capabilities
    - Maintain content readability and context
    - Provide consistent tokenization for correlation
    - Support multiple redaction modes for different use cases
    """
    
    # Default redaction rules for different PII types
    DEFAULT_REDACTION_RULES = {
        PIIType.SSN: RedactionRule(
            pii_type=PIIType.SSN,
            strategy=RedactionStrategy.TOKENIZE,
            preserve_format=True,
            confidence_threshold=0.8
        ),
        PIIType.CREDIT_CARD: RedactionRule(
            pii_type=PIIType.CREDIT_CARD,
            strategy=RedactionStrategy.MASK,
            preserve_format=True,
            confidence_threshold=0.8
        ),
        PIIType.EMAIL: RedactionRule(
            pii_type=PIIType.EMAIL,
            strategy=RedactionStrategy.TOKENIZE,
            preserve_format=False,
            confidence_threshold=0.7
        ),
        PIIType.PHONE: RedactionRule(
            pii_type=PIIType.PHONE,
            strategy=RedactionStrategy.MASK,
            preserve_format=True,
            confidence_threshold=0.7
        ),
        PIIType.NAME: RedactionRule(
            pii_type=PIIType.NAME,
            strategy=RedactionStrategy.TOKENIZE,
            preserve_format=False,
            confidence_threshold=0.6
        ),
        PIIType.ADDRESS: RedactionRule(
            pii_type=PIIType.ADDRESS,
            strategy=RedactionStrategy.TOKENIZE,
            preserve_format=False,
            confidence_threshold=0.7
        ),
        PIIType.DOB: RedactionRule(
            pii_type=PIIType.DOB,
            strategy=RedactionStrategy.MASK,
            preserve_format=True,
            confidence_threshold=0.8
        )
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the redaction engine."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Load redaction rules
        self.redaction_rules = self._load_redaction_rules()
        
        # Token mappings for consistency
        self.token_mappings = {}
        self.token_counter = 0
        
        # Hash salt for consistent hashing
        self.hash_salt = self.config.get('hash_salt', 'threat_hunter_redaction_salt')
        
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the redaction engine."""
        if self._initialized:
            return
        
        try:
            # Load existing token mappings for consistency
            await self._load_token_mappings()
            
            self._initialized = True
            self.logger.info("Redaction Engine initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize redaction engine: {e}")
            raise
    
    async def redact(
        self,
        content: str,
        pii_results: PIIResults,
        security_entities: List[SecurityEntity],
        config: Dict[str, Any]
    ) -> RedactionResult:
        """
        Apply redaction to content based on PII detections and security entities.
        
        Args:
            content: Original content to redact
            pii_results: Detected PII information
            security_entities: Security entities to preserve
            config: Redaction configuration for this processing mode
            
        Returns:
            RedactionResult with redacted content and metadata
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # Create a list of all redaction/preservation actions
            actions = []
            
            # Process PII detections
            for detection in pii_results.detections:
                rule = self.redaction_rules.get(detection.pii_type, self._get_default_rule(detection.pii_type))
                if detection.confidence >= rule.confidence_threshold:
                    actions.append(self._create_pii_action(detection, rule))
            
            # Process security entities (preserve these)
            for entity in security_entities:
                actions.append(self._create_entity_action(entity, config))
            
            # Sort actions by position (reverse order for stable indexing)
            actions.sort(key=lambda x: x['start_pos'], reverse=True)
            
            # Apply redactions/preservations
            redacted_content = content
            redactions_applied = []
            entities_preserved = []
            
            for action in actions:
                if action['type'] == 'redact':
                    redacted_content, redaction_info = self._apply_redaction(
                        redacted_content, action
                    )
                    redactions_applied.append(redaction_info)
                elif action['type'] == 'preserve':
                    # Entity preservation might involve tokenization
                    redacted_content, preservation_info = self._apply_preservation(
                        redacted_content, action
                    )
                    entities_preserved.append(preservation_info)
            
            # Calculate redaction statistics
            redaction_ratio = len(redactions_applied) / max(len(content.split()), 1)
            
            return RedactionResult(
                content=redacted_content,
                redactions_applied=redactions_applied,
                entities_preserved=entities_preserved,
                redaction_ratio=redaction_ratio,
                metadata={
                    'original_length': len(content),
                    'redacted_length': len(redacted_content),
                    'pii_detections': len(pii_results.detections),
                    'entities_preserved': len(security_entities),
                    'processing_mode': config.get('mode', 'unknown')
                }
            )
            
        except Exception as e:
            self.logger.error(f"Redaction failed: {e}")
            raise
    
    def _create_pii_action(self, detection: PIIDetection, rule: RedactionRule) -> Dict[str, Any]:
        """Create a redaction action for a PII detection."""
        return {
            'type': 'redact',
            'start_pos': detection.start_pos,
            'end_pos': detection.end_pos,
            'original_value': detection.value,
            'pii_type': detection.pii_type,
            'strategy': rule.strategy,
            'rule': rule,
            'confidence': detection.confidence,
            'context': detection.context
        }
    
    def _create_entity_action(self, entity: SecurityEntity, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a preservation action for a security entity."""
        return {
            'type': 'preserve',
            'start_pos': entity.start_pos,
            'end_pos': entity.end_pos,
            'original_value': entity.original_value,
            'processed_value': entity.value,
            'entity_type': entity.entity_type,
            'preserve_original': entity.preserve_original,
            'confidence': entity.confidence,
            'context': entity.context
        }
    
    def _apply_redaction(self, content: str, action: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Apply a redaction action to content."""
        start_pos = action['start_pos']
        end_pos = action['end_pos']
        original_value = action['original_value']
        strategy = action['strategy']
        rule = action['rule']
        
        # Generate replacement based on strategy
        replacement = self._generate_replacement(original_value, strategy, rule, action['pii_type'])
        
        # Apply the redaction
        redacted_content = content[:start_pos] + replacement + content[end_pos:]
        
        # Create redaction info
        redaction_info = {
            'original_value': original_value,
            'redacted_value': replacement,
            'strategy': strategy.value,
            'pii_type': action['pii_type'].value,
            'position': start_pos,
            'confidence': action['confidence']
        }
        
        return redacted_content, redaction_info
    
    def _apply_preservation(self, content: str, action: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Apply a preservation action to content."""
        start_pos = action['start_pos']
        end_pos = action['end_pos']
        original_value = action['original_value']
        processed_value = action['processed_value']
        preserve_original = action['preserve_original']
        
        if preserve_original:
            # Keep original value
            replacement = original_value
        else:
            # Use processed (tokenized) value
            replacement = processed_value
        
        # Apply the preservation (might be no-op if values are the same)
        if replacement != original_value:
            preserved_content = content[:start_pos] + replacement + content[end_pos:]
        else:
            preserved_content = content
        
        # Create preservation info
        preservation_info = {
            'original_value': original_value,
            'preserved_value': replacement,
            'entity_type': action['entity_type'].value,
            'position': start_pos,
            'preserve_original': preserve_original,
            'confidence': action['confidence']
        }
        
        return preserved_content, preservation_info
    
    def _generate_replacement(self, original_value: str, strategy: RedactionStrategy, rule: RedactionRule, pii_type: PIIType) -> str:
        """Generate replacement text based on redaction strategy."""
        if strategy == RedactionStrategy.TOKENIZE:
            return self._tokenize_value(original_value, pii_type)
        
        elif strategy == RedactionStrategy.MASK:
            return self._mask_value(original_value, rule.preserve_format)
        
        elif strategy == RedactionStrategy.HASH:
            return self._hash_value(original_value, pii_type)
        
        elif strategy == RedactionStrategy.REMOVE:
            return "[REDACTED]"
        
        elif strategy == RedactionStrategy.ANONYMIZE:
            return self._anonymize_value(original_value, pii_type)
        
        elif strategy == RedactionStrategy.PRESERVE:
            return original_value
        
        else:
            # Default to tokenization
            return self._tokenize_value(original_value, pii_type)
    
    def _tokenize_value(self, value: str, pii_type: PIIType) -> str:
        """Create a consistent token for a PII value."""
        # Check if we already have a token for this value
        if value in self.token_mappings:
            return self.token_mappings[value]
        
        # Generate new token
        token_prefix = pii_type.value.upper()
        value_hash = hashlib.md5(f"{value}{self.hash_salt}".encode()).hexdigest()[:8]
        token = f"{token_prefix}_TOKEN_{value_hash.upper()}"
        
        # Store mapping for consistency
        self.token_mappings[value] = token
        
        return token
    
    def _mask_value(self, value: str, preserve_format: bool) -> str:
        """Apply masking to a value while optionally preserving format."""
        if not preserve_format:
            return "*" * min(len(value), 8)
        
        # Format-preserving masking based on value type
        if re.match(r'\d{3}-\d{2}-\d{4}', value):  # SSN format
            return "***-**-****"
        
        elif re.match(r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}', value):  # Credit card
            # Show first 4 and last 4 digits
            cleaned = re.sub(r'[\s-]', '', value)
            if len(cleaned) >= 8:
                return f"{cleaned[:4]}-****-****-{cleaned[-4:]}"
            else:
                return "*" * len(cleaned)
        
        elif re.match(r'\d{3}-\d{3}-\d{4}', value):  # Phone format
            return "***-***-****"
        
        elif re.match(r'\(\d{3}\)\s?\d{3}-\d{4}', value):  # (123) 456-7890
            return "(***) ***-****"
        
        elif '@' in value:  # Email
            local, domain = value.split('@', 1)
            if len(local) > 2:
                masked_local = local[0] + '*' * (len(local) - 2) + local[-1]
            else:
                masked_local = '*' * len(local)
            return f"{masked_local}@{domain}"
        
        else:
            # Generic masking - show first and last character if long enough
            if len(value) <= 2:
                return "*" * len(value)
            elif len(value) <= 4:
                return value[0] + "*" * (len(value) - 2) + value[-1]
            else:
                return value[:2] + "*" * (len(value) - 4) + value[-2:]
    
    def _hash_value(self, value: str, pii_type: PIIType) -> str:
        """Create a one-way hash of the value for correlation."""
        hash_input = f"{value}{self.hash_salt}{pii_type.value}"
        hash_value = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
        return f"{pii_type.value.upper()}_HASH_{hash_value.upper()}"
    
    def _anonymize_value(self, value: str, pii_type: PIIType) -> str:
        """Apply statistical anonymization to the value."""
        # This would implement more sophisticated anonymization
        # For now, return a generic anonymized representation
        return f"[ANONYMIZED_{pii_type.value.upper()}]"
    
    def _get_default_rule(self, pii_type: PIIType) -> RedactionRule:
        """Get default redaction rule for a PII type."""
        return RedactionRule(
            pii_type=pii_type,
            strategy=RedactionStrategy.TOKENIZE,
            preserve_format=False,
            confidence_threshold=0.7
        )
    
    def _load_redaction_rules(self) -> Dict[PIIType, RedactionRule]:
        """Load redaction rules from configuration."""
        rules = self.DEFAULT_REDACTION_RULES.copy()
        
        # Override with configuration if provided
        config_rules = self.config.get('redaction_rules', {})
        for pii_type_str, rule_config in config_rules.items():
            try:
                pii_type = PIIType(pii_type_str)
                strategy = RedactionStrategy(rule_config.get('strategy', 'tokenize'))
                
                rule = RedactionRule(
                    pii_type=pii_type,
                    strategy=strategy,
                    preserve_format=rule_config.get('preserve_format', True),
                    confidence_threshold=rule_config.get('confidence_threshold', 0.7),
                    context_preservation=rule_config.get('context_preservation', 0)
                )
                
                rules[pii_type] = rule
                
            except (ValueError, KeyError) as e:
                self.logger.warning(f"Invalid redaction rule configuration for {pii_type_str}: {e}")
        
        return rules
    
    async def _load_token_mappings(self) -> None:
        """Load existing token mappings for consistency."""
        # This would load from persistent storage
        # For now, start with empty mappings
        self.token_mappings = {}
        self.token_counter = 0
    
    async def save_token_mappings(self) -> None:
        """Save token mappings for persistence across restarts."""
        # This would save to persistent storage
        # Implementation would depend on storage backend
        pass