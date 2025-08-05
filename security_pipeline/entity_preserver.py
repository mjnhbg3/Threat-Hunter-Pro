"""
Security Entity Preservation Engine for Threat Hunter Pro.

This module identifies and preserves security-relevant entities that are
critical for threat hunting and analysis while protecting PII. It ensures
that threat intelligence data remains intact for effective security analysis.
"""

from __future__ import annotations

import re
import logging
import ipaddress
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum
import hashlib


class SecurityEntityType(Enum):
    """Types of security entities to preserve."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"
    PORT = "port"
    PROTOCOL = "protocol"
    PROCESS_NAME = "process_name"
    SERVICE_NAME = "service_name"
    SYSTEM_ID = "system_id"
    USER_ROLE = "user_role"
    THREAT_INDICATOR = "threat_indicator"
    CVE = "cve"
    SIGNATURE_ID = "signature_id"
    EVENT_ID = "event_id"


@dataclass
class SecurityEntity:
    """A detected security entity."""
    entity_type: SecurityEntityType
    value: str
    original_value: str
    start_pos: int
    end_pos: int
    confidence: float
    context: str
    preserve_original: bool
    metadata: Dict[str, Any]


class SecurityEntityPreserver:
    """
    Advanced security entity preservation system.
    
    This system identifies security-relevant entities in log data and determines
    how to preserve them during PII redaction. It balances security analysis
    needs with privacy protection requirements.
    
    Features:
    - Pattern-based security entity detection
    - Context-aware entity classification
    - Threat intelligence integration
    - Configurable preservation policies
    - Entity relationship mapping
    """
    
    # Pre-compiled patterns for security entities
    ENTITY_PATTERNS = {
        SecurityEntityType.IP_ADDRESS: [
            re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),  # IPv4
            re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),  # IPv6
        ],
        SecurityEntityType.DOMAIN: [
            re.compile(r'\b[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}\b'),
        ],
        SecurityEntityType.FILE_HASH: [
            re.compile(r'\b[a-fA-F0-9]{32}\b'),   # MD5
            re.compile(r'\b[a-fA-F0-9]{40}\b'),   # SHA1
            re.compile(r'\b[a-fA-F0-9]{64}\b'),   # SHA256
            re.compile(r'\b[a-fA-F0-9]{128}\b'),  # SHA512
        ],
        SecurityEntityType.PORT: [
            re.compile(r'(?:port|Port|PORT)[\s:=]+(\d{1,5})\b'),
            re.compile(r':(\d{1,5})\b'),  # Common :port pattern
        ],
        SecurityEntityType.PROTOCOL: [
            re.compile(r'\b(HTTP|HTTPS|FTP|FTPS|SSH|TELNET|SMTP|POP3|IMAP|DNS|DHCP|SNMP|TCP|UDP|ICMP)\b', re.IGNORECASE),
        ],
        SecurityEntityType.PROCESS_NAME: [
            re.compile(r'\b\w+\.exe\b', re.IGNORECASE),
            re.compile(r'\b\w+\.dll\b', re.IGNORECASE),
            re.compile(r'/usr/bin/\w+\b'),
            re.compile(r'/sbin/\w+\b'),
        ],
        SecurityEntityType.CVE: [
            re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE),
        ],
        SecurityEntityType.SIGNATURE_ID: [
            re.compile(r'\bSID[\s:=]+(\d+)\b', re.IGNORECASE),
            re.compile(r'\bRule[\s:=]+(\d+)\b', re.IGNORECASE),
        ],
        SecurityEntityType.EVENT_ID: [
            re.compile(r'\bEvent[\s:=]+ID[\s:=]+(\d+)\b', re.IGNORECASE),
            re.compile(r'\bEventID[\s:=]+(\d+)\b', re.IGNORECASE),
        ]
    }
    
    # Known threat intelligence domains/IPs to always preserve
    THREAT_INDICATORS = {
        'malicious_domains': {
            # Would be loaded from threat intel feeds
            'known_malware_domains.txt',
            'phishing_domains.txt'
        },
        'malicious_ips': {
            # Would be loaded from threat intel feeds
            'botnet_ips.txt',
            'attack_sources.txt'
        }
    }
    
    # Private IP ranges for special handling
    PRIVATE_IP_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),  # Loopback
        ipaddress.ip_network('169.254.0.0/16'),  # Link-local
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the security entity preserver."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Preservation policies
        self.preservation_policies = self._load_preservation_policies()
        
        # Threat intelligence data
        self.threat_intel = self._load_threat_intelligence()
        
        # Entity tokenization mappings
        self.entity_tokens = {}
        self.token_counter = 0
        
        # Context window for entity analysis
        self.context_window = self.config.get('context_window', 30)
        
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the security entity preserver."""
        if self._initialized:
            return
        
        try:
            # Load threat intelligence feeds
            await self._load_threat_intel_feeds()
            
            # Initialize entity tokenization
            self._initialize_tokenization()
            
            self._initialized = True
            self.logger.info("Security Entity Preserver initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize security entity preserver: {e}")
            raise
    
    async def extract_entities(self, content: str, context: Optional[Dict[str, Any]] = None) -> List[SecurityEntity]:
        """
        Extract security entities from content.
        
        Args:
            content: Text content to analyze
            context: Additional context for entity extraction
            
        Returns:
            List of SecurityEntity objects representing detected entities
        """
        if not self._initialized:
            await self.initialize()
        
        entities = []
        context = context or {}
        
        try:
            # Extract entities using pattern matching
            for entity_type, patterns in self.ENTITY_PATTERNS.items():
                type_entities = await self._extract_pattern_entities(content, entity_type, patterns)
                entities.extend(type_entities)
            
            # Apply context-aware enhancements
            enhanced_entities = await self._enhance_with_context(content, entities, context)
            
            # Apply preservation policies
            final_entities = await self._apply_preservation_policies(enhanced_entities)
            
            return final_entities
            
        except Exception as e:
            self.logger.error(f"Entity extraction failed: {e}")
            raise
    
    async def _extract_pattern_entities(self, content: str, entity_type: SecurityEntityType, patterns: List[re.Pattern]) -> List[SecurityEntity]:
        """Extract entities using regex patterns."""
        entities = []
        
        for pattern in patterns:
            for match in pattern.finditer(content):
                start_pos = match.start()
                end_pos = match.end()
                value = match.group()
                
                # Skip if this looks like PII context
                if self._is_pii_context(content, start_pos, end_pos):
                    continue
                
                # Extract context around the match
                context_start = max(0, start_pos - self.context_window)
                context_end = min(len(content), end_pos + self.context_window)
                context_text = content[context_start:context_end]
                
                # Calculate confidence and determine preservation strategy
                confidence = self._calculate_entity_confidence(entity_type, value, context_text)
                preserve_original = self._should_preserve_original(entity_type, value, context_text)
                
                # Create processed value (tokenized if needed)
                processed_value = await self._process_entity_value(entity_type, value, preserve_original)
                
                entity = SecurityEntity(
                    entity_type=entity_type,
                    value=processed_value,
                    original_value=value,
                    start_pos=start_pos,
                    end_pos=end_pos,
                    confidence=confidence,
                    context=context_text,
                    preserve_original=preserve_original,
                    metadata={
                        'pattern_used': pattern.pattern,
                        'detection_method': 'regex'
                    }
                )
                entities.append(entity)
        
        return entities
    
    async def _enhance_with_context(self, content: str, entities: List[SecurityEntity], context: Dict[str, Any]) -> List[SecurityEntity]:
        """Enhance entity detection with contextual analysis."""
        enhanced = []
        
        for entity in entities:
            # Enhance based on entity type
            if entity.entity_type == SecurityEntityType.IP_ADDRESS:
                entity = await self._enhance_ip_entity(entity, content, context)
            elif entity.entity_type == SecurityEntityType.DOMAIN:
                entity = await self._enhance_domain_entity(entity, content, context)
            elif entity.entity_type == SecurityEntityType.FILE_HASH:
                entity = await self._enhance_hash_entity(entity, content, context)
            
            enhanced.append(entity)
        
        return enhanced
    
    async def _enhance_ip_entity(self, entity: SecurityEntity, content: str, context: Dict[str, Any]) -> SecurityEntity:
        """Enhance IP address entity with additional context."""
        ip_str = entity.original_value
        
        try:
            ip = ipaddress.ip_address(ip_str)
            
            # Determine if it's a private IP
            is_private = any(ip in private_range for private_range in self.PRIVATE_IP_RANGES)
            
            # Check against threat intelligence
            is_threat = self._is_threat_indicator(ip_str, 'ip')
            
            # Update metadata
            entity.metadata.update({
                'is_private': is_private,
                'is_threat_indicator': is_threat,
                'ip_version': ip.version
            })
            
            # Adjust preservation policy based on threat status
            if is_threat:
                entity.preserve_original = True
                entity.confidence = min(entity.confidence * 1.2, 1.0)
            elif is_private:
                # Private IPs might need tokenization
                entity.preserve_original = False
                if not entity.value.startswith('PRIVATE_IP_'):
                    entity.value = self._get_entity_token('PRIVATE_IP', ip_str)
            
        except ValueError:
            # Invalid IP address
            entity.confidence *= 0.5
        
        return entity
    
    async def _enhance_domain_entity(self, entity: SecurityEntity, content: str, context: Dict[str, Any]) -> SecurityEntity:
        """Enhance domain entity with additional context."""
        domain = entity.original_value.lower()
        
        # Check against threat intelligence
        is_threat = self._is_threat_indicator(domain, 'domain')
        
        # Check if it's a common corporate/legitimate domain
        is_legitimate = self._is_legitimate_domain(domain)
        
        # Update metadata
        entity.metadata.update({
            'is_threat_indicator': is_threat,
            'is_legitimate': is_legitimate,
            'tld': domain.split('.')[-1] if '.' in domain else ''
        })
        
        # Adjust preservation based on threat/legitimacy status
        if is_threat:
            entity.preserve_original = True
            entity.confidence = min(entity.confidence * 1.3, 1.0)
        elif is_legitimate:
            entity.preserve_original = True
        else:
            # Unknown domain - apply tokenization for privacy
            entity.preserve_original = False
            entity.value = self._get_entity_token('DOMAIN', domain)
        
        return entity
    
    async def _enhance_hash_entity(self, entity: SecurityEntity, content: str, context: Dict[str, Any]) -> SecurityEntity:
        """Enhance file hash entity with additional context."""
        file_hash = entity.original_value.lower()
        
        # File hashes are always preserved - critical for threat hunting
        entity.preserve_original = True
        
        # Determine hash type
        hash_type = self._determine_hash_type(file_hash)
        
        # Check against threat intelligence
        is_malware = self._is_threat_indicator(file_hash, 'hash')
        
        entity.metadata.update({
            'hash_type': hash_type,
            'is_malware_hash': is_malware
        })
        
        if is_malware:
            entity.confidence = min(entity.confidence * 1.5, 1.0)
        
        return entity
    
    async def _apply_preservation_policies(self, entities: List[SecurityEntity]) -> List[SecurityEntity]:
        """Apply preservation policies to entities."""
        preserved = []
        
        for entity in entities:
            policy = self.preservation_policies.get(entity.entity_type.value, {})
            
            # Apply policy rules
            if policy.get('always_preserve', False):
                entity.preserve_original = True
            elif policy.get('never_preserve', False):
                entity.preserve_original = False
            
            # Apply confidence threshold
            min_confidence = policy.get('min_confidence', 0.7)
            if entity.confidence < min_confidence:
                continue
            
            preserved.append(entity)
        
        return preserved
    
    async def _process_entity_value(self, entity_type: SecurityEntityType, value: str, preserve_original: bool) -> str:
        """Process entity value based on preservation policy."""
        if preserve_original:
            return value
        else:
            # Return tokenized value
            return self._get_entity_token(entity_type.value.upper(), value)
    
    def _get_entity_token(self, entity_prefix: str, original_value: str) -> str:
        """Get or create a consistent token for an entity."""
        # Create hash-based token for consistency
        value_hash = hashlib.md5(original_value.encode()).hexdigest()[:8]
        
        # Check if we already have a token for this value
        if original_value in self.entity_tokens:
            return self.entity_tokens[original_value]
        
        # Create new token
        token = f"{entity_prefix}_{value_hash.upper()}"
        self.entity_tokens[original_value] = token
        
        return token
    
    def _is_pii_context(self, content: str, start_pos: int, end_pos: int) -> bool:
        """Check if the entity appears in a PII context."""
        # Extract wider context
        context_start = max(0, start_pos - 50)
        context_end = min(len(content), end_pos + 50)
        context = content[context_start:context_end].lower()
        
        # PII context indicators
        pii_indicators = [
            'personal', 'private', 'confidential', 'name', 'address',
            'phone', 'email', 'ssn', 'social security', 'credit card',
            'employee id', 'customer id', 'account number'
        ]
        
        return any(indicator in context for indicator in pii_indicators)
    
    def _calculate_entity_confidence(self, entity_type: SecurityEntityType, value: str, context: str) -> float:
        """Calculate confidence score for an entity detection."""
        base_confidence = 0.8
        
        # Entity-specific confidence adjustments
        if entity_type == SecurityEntityType.IP_ADDRESS:
            try:
                ip = ipaddress.ip_address(value)
                if ip.is_loopback or ip.is_link_local:
                    base_confidence = 0.9  # High confidence for system IPs
                elif ip.is_private:
                    base_confidence = 0.85
            except ValueError:
                base_confidence = 0.3  # Invalid IP
        
        elif entity_type == SecurityEntityType.FILE_HASH:
            # File hashes are very reliable
            hash_len = len(value)
            if hash_len in [32, 40, 64, 128]:  # Valid hash lengths
                base_confidence = 0.95
            else:
                base_confidence = 0.6
        
        elif entity_type == SecurityEntityType.CVE:
            # CVE format is very specific
            base_confidence = 0.95
        
        # Context-based adjustments
        context_lower = context.lower()
        
        # Increase confidence in security contexts
        security_contexts = ['alert', 'warning', 'error', 'threat', 'attack', 'malware', 'virus']
        if any(ctx in context_lower for ctx in security_contexts):
            base_confidence = min(base_confidence * 1.1, 1.0)
        
        # Decrease confidence in obvious false positive contexts
        fp_contexts = ['example', 'test', 'sample', 'placeholder']
        if any(ctx in context_lower for ctx in fp_contexts):
            base_confidence *= 0.7
        
        return base_confidence
    
    def _should_preserve_original(self, entity_type: SecurityEntityType, value: str, context: str) -> bool:
        """Determine if original value should be preserved."""
        # Always preserve threat indicators
        if self._is_threat_indicator(value, entity_type.value):
            return True
        
        # Entity-specific rules
        preserve_rules = {
            SecurityEntityType.FILE_HASH: True,  # Always preserve hashes
            SecurityEntityType.CVE: True,       # Always preserve CVEs
            SecurityEntityType.PROTOCOL: True,   # Always preserve protocols
            SecurityEntityType.PORT: True,      # Always preserve ports
            SecurityEntityType.EVENT_ID: True,  # Always preserve event IDs
            SecurityEntityType.SIGNATURE_ID: True,  # Always preserve signature IDs
        }
        
        return preserve_rules.get(entity_type, False)
    
    def _is_threat_indicator(self, value: str, indicator_type: str) -> bool:
        """Check if value is a known threat indicator."""
        # This would check against threat intelligence feeds
        # Placeholder implementation
        return value.lower() in self.threat_intel.get(indicator_type, set())
    
    def _is_legitimate_domain(self, domain: str) -> bool:
        """Check if domain is a known legitimate domain."""
        # Common legitimate domains
        legitimate_domains = {
            'microsoft.com', 'google.com', 'amazon.com', 'apple.com',
            'github.com', 'stackoverflow.com', 'cloudflare.com'
        }
        
        return any(domain.endswith(legit) for legit in legitimate_domains)
    
    def _determine_hash_type(self, hash_value: str) -> str:
        """Determine the type of hash based on length."""
        hash_types = {
            32: 'MD5',
            40: 'SHA1',
            64: 'SHA256',
            128: 'SHA512'
        }
        return hash_types.get(len(hash_value), 'Unknown')
    
    def _load_preservation_policies(self) -> Dict[str, Dict[str, Any]]:
        """Load entity preservation policies from configuration."""
        default_policies = {
            'ip_address': {
                'always_preserve': False,
                'min_confidence': 0.7,
                'tokenize_private': True
            },
            'domain': {
                'always_preserve': False,
                'min_confidence': 0.7,
                'preserve_threats': True
            },
            'file_hash': {
                'always_preserve': True,
                'min_confidence': 0.8
            },
            'cve': {
                'always_preserve': True,
                'min_confidence': 0.9
            },
            'protocol': {
                'always_preserve': True,
                'min_confidence': 0.8
            },
            'port': {
                'always_preserve': True,
                'min_confidence': 0.8
            }
        }
        
        # Merge with configuration
        policies = default_policies.copy()
        policies.update(self.config.get('preservation_policies', {}))
        
        return policies
    
    def _load_threat_intelligence(self) -> Dict[str, Set[str]]:
        """Load threat intelligence data."""
        # This would load from external threat intel feeds
        # Placeholder implementation
        return {
            'ip': set(),
            'domain': set(),
            'hash': set()
        }
    
    async def _load_threat_intel_feeds(self) -> None:
        """Load threat intelligence feeds from external sources."""
        # This would implement loading from:
        # - MISP feeds
        # - Commercial threat intel
        # - Open source feeds
        # - Internal threat data
        pass
    
    def _initialize_tokenization(self) -> None:
        """Initialize entity tokenization system."""
        # Load existing token mappings if available
        # This ensures consistency across restarts
        pass