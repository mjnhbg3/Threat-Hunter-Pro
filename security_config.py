"""
Security Configuration System for Threat Hunter Pro.

This module provides secure configuration management with encryption,
validation, and environment-based overrides for all security settings.
"""

from __future__ import annotations

import os
import json
import logging
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field, asdict
from pathlib import Path
from datetime import timedelta

from .secrets import SecretsManager, SecretType
from .security_pipeline import ProcessingMode


@dataclass
class PIIDetectionConfig:
    """PII detection configuration."""
    enabled: bool = True
    sensitivity: float = 0.8
    confidence_threshold: float = 0.7
    context_window: int = 50
    custom_patterns: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    def __post_init__(self):
        # Validate sensitivity and confidence values
        if not 0.0 <= self.sensitivity <= 1.0:
            raise ValueError("Sensitivity must be between 0.0 and 1.0")
        if not 0.0 <= self.confidence_threshold <= 1.0:
            raise ValueError("Confidence threshold must be between 0.0 and 1.0")


@dataclass
class EntityPreservationConfig:
    """Entity preservation configuration."""
    enabled: bool = True
    preserve_ip_addresses: bool = True
    preserve_file_hashes: bool = True
    preserve_domain_names: bool = True
    preserve_ports_protocols: bool = True
    preserve_cves: bool = True
    tokenize_private_ips: bool = True
    threat_intel_integration: bool = True
    custom_preservation_rules: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RedactionConfig:
    """Content redaction configuration."""
    enabled: bool = True
    default_strategy: str = "tokenize"  # tokenize, mask, hash, remove
    preserve_format: bool = True
    hash_salt: str = "default_salt"
    tokenization_salt: str = "default_tokenization_salt"
    mode_specific_configs: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    def __post_init__(self):
        # Set default mode-specific configurations
        if not self.mode_specific_configs:
            self.mode_specific_configs = {
                ProcessingMode.EMBEDDING.value: {
                    'preserve_security_entities': True,
                    'aggressive_pii_redaction': False,
                    'maintain_context': True,
                    'tokenize_identifiers': True
                },
                ProcessingMode.DISPLAY.value: {
                    'preserve_security_entities': True,
                    'aggressive_pii_redaction': True,
                    'maintain_context': True,
                    'tokenize_identifiers': False
                },
                ProcessingMode.EXPORT.value: {
                    'preserve_security_entities': False,
                    'aggressive_pii_redaction': True,
                    'maintain_context': False,
                    'tokenize_identifiers': False
                },
                ProcessingMode.ANALYSIS.value: {
                    'preserve_security_entities': True,
                    'aggressive_pii_redaction': False,
                    'maintain_context': True,
                    'tokenize_identifiers': True
                }
            }


@dataclass
class AuditLoggingConfig:
    """Audit logging configuration."""
    enabled: bool = True
    audit_log_path: str = "/var/log/threat_hunter/audit.log"
    compliance_log_path: str = "/var/log/threat_hunter/compliance.log"
    security_log_path: str = "/var/log/threat_hunter/security.log"
    buffer_size: int = 100
    flush_interval: int = 60
    retention_days: int = 2555  # 7 years for compliance
    log_sensitive_data: bool = False
    anonymize_logs: bool = True
    compliance_tags: List[str] = field(default_factory=lambda: ['GDPR', 'HIPAA', 'SOC2'])


@dataclass
class AuthenticationConfig:
    """Authentication configuration."""
    enabled: bool = True
    require_mfa: bool = True
    mfa_issuer_name: str = "Threat Hunter Pro"
    mfa_window_size: int = 1
    backup_code_count: int = 8
    device_trust_days: int = 30
    max_trusted_devices: int = 5
    session_timeout_minutes: int = 60
    absolute_session_timeout_hours: int = 8
    max_concurrent_sessions: int = 5
    password_hash_rounds: int = 12


@dataclass
class RateLimitingConfig:
    """Rate limiting configuration."""
    enabled: bool = True
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    requests_per_day: int = 10000
    burst_limit: int = 10
    whitelist_ips: List[str] = field(default_factory=list)
    blacklist_ips: List[str] = field(default_factory=list)


@dataclass
class SecurityHeadersConfig:
    """Security headers configuration."""
    enabled: bool = True
    content_security_policy: str = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'"
    strict_transport_security: str = "max-age=31536000; includeSubDomains"
    x_content_type_options: str = "nosniff"
    x_frame_options: str = "DENY"
    x_xss_protection: str = "1; mode=block"
    referrer_policy: str = "strict-origin-when-cross-origin"
    permissions_policy: str = "geolocation=(), microphone=(), camera=()"


@dataclass
class InputValidationConfig:
    """Input validation configuration."""
    enabled: bool = True
    strict_mode: bool = True
    max_string_length: int = 10000
    max_json_depth: int = 10
    max_request_size: int = 10 * 1024 * 1024  # 10MB
    security_checks_enabled: bool = True
    custom_validation_rules: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecretsManagementConfig:
    """Secrets management configuration."""
    enabled: bool = True
    encryption_key_source: str = "env"  # env, file, generated
    key_env_var: str = "SECRETS_ENCRYPTION_KEY"
    secrets_dir: str = "/var/ossec/integrations/threat_hunter_secrets"
    auto_load_env: bool = True
    backup_enabled: bool = True
    max_versions: int = 5
    rotation_enabled: bool = False
    vault_integration: Optional[Dict[str, Any]] = None


@dataclass
class ComplianceConfig:
    """Compliance configuration."""
    gdpr_mode: bool = True
    hipaa_mode: bool = False
    pci_dss_mode: bool = False
    sox_mode: bool = False
    data_retention_days: int = 90
    right_to_erasure: bool = True
    data_portability: bool = True
    consent_management: bool = True


@dataclass
class SecurityConfiguration:
    """Main security configuration container."""
    # Core security components
    pii_detection: PIIDetectionConfig = field(default_factory=PIIDetectionConfig)
    entity_preservation: EntityPreservationConfig = field(default_factory=EntityPreservationConfig)
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    audit_logging: AuditLoggingConfig = field(default_factory=AuditLoggingConfig)
    
    # Authentication and authorization
    authentication: AuthenticationConfig = field(default_factory=AuthenticationConfig)
    
    # Request security
    rate_limiting: RateLimitingConfig = field(default_factory=RateLimitingConfig)
    security_headers: SecurityHeadersConfig = field(default_factory=SecurityHeadersConfig)
    input_validation: InputValidationConfig = field(default_factory=InputValidationConfig)
    
    # Secrets and configuration management
    secrets_management: SecretsManagementConfig = field(default_factory=SecretsManagementConfig)
    
    # Compliance
    compliance: ComplianceConfig = field(default_factory=ComplianceConfig)
    
    # Global settings
    security_enabled: bool = True
    debug_mode: bool = False
    environment: str = "production"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityConfiguration':
        """Create from dictionary."""
        # Create nested dataclass instances
        config = cls()
        
        for field_name, field_value in data.items():
            if hasattr(config, field_name):
                if field_name == 'pii_detection':
                    config.pii_detection = PIIDetectionConfig(**field_value)
                elif field_name == 'entity_preservation':
                    config.entity_preservation = EntityPreservationConfig(**field_value)
                elif field_name == 'redaction':
                    config.redaction = RedactionConfig(**field_value)
                elif field_name == 'audit_logging':
                    config.audit_logging = AuditLoggingConfig(**field_value)
                elif field_name == 'authentication':
                    config.authentication = AuthenticationConfig(**field_value)
                elif field_name == 'rate_limiting':
                    config.rate_limiting = RateLimitingConfig(**field_value)
                elif field_name == 'security_headers':
                    config.security_headers = SecurityHeadersConfig(**field_value)
                elif field_name == 'input_validation':
                    config.input_validation = InputValidationConfig(**field_value)
                elif field_name == 'secrets_management':
                    config.secrets_management = SecretsManagementConfig(**field_value)
                elif field_name == 'compliance':
                    config.compliance = ComplianceConfig(**field_value)
                else:
                    setattr(config, field_name, field_value)
        
        return config


class SecurityConfigManager:
    """
    Secure configuration management system.
    
    Features:
    - Encrypted configuration storage
    - Environment variable overrides
    - Configuration validation
    - Hot configuration reloading
    - Configuration versioning
    - Audit logging of configuration changes
    """
    
    def __init__(self, config_path: Optional[str] = None, secrets_manager: Optional[SecretsManager] = None):
        """Initialize the security configuration manager."""
        self.logger = logging.getLogger(__name__)
        
        # Configuration file path
        self.config_path = Path(config_path or "/etc/threat_hunter/security_config.json")
        self.encrypted_config_path = Path(str(self.config_path) + ".encrypted")
        
        # Secrets manager for encrypting sensitive config
        self.secrets_manager = secrets_manager
        
        # Current configuration
        self._config: Optional[SecurityConfiguration] = None
        self._config_version = 0
        
        # Configuration change callbacks
        self._change_callbacks: List[callable] = []
    
    async def initialize(self) -> None:
        """Initialize the configuration manager."""
        try:
            # Load configuration
            await self.load_configuration()
            
            # Apply environment variable overrides
            await self._apply_environment_overrides()
            
            # Validate configuration
            await self._validate_configuration()
            
            self.logger.info("Security Configuration Manager initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize security configuration manager: {e}")
            raise
    
    async def load_configuration(self) -> SecurityConfiguration:
        """Load security configuration from file."""
        try:
            # Try to load encrypted configuration first
            if self.encrypted_config_path.exists() and self.secrets_manager:
                config_data = await self._load_encrypted_config()
            # Fall back to plain text configuration
            elif self.config_path.exists():
                config_data = await self._load_plain_config()
                self.logger.warning("Loading plain text configuration - consider encrypting")
            else:
                # Create default configuration
                config_data = SecurityConfiguration().to_dict()
                await self.save_configuration(SecurityConfiguration())
                self.logger.info("Created default security configuration")
            
            self._config = SecurityConfiguration.from_dict(config_data)
            self._config_version += 1
            
            self.logger.info("Security configuration loaded successfully")
            return self._config
            
        except Exception as e:
            self.logger.error(f"Failed to load security configuration: {e}")
            # Return default configuration on error
            self._config = SecurityConfiguration()
            return self._config
    
    async def save_configuration(self, config: SecurityConfiguration, encrypt: bool = True) -> None:
        """Save security configuration to file."""
        try:
            config_data = config.to_dict()
            
            # Create directory if it doesn't exist
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            if encrypt and self.secrets_manager:
                await self._save_encrypted_config(config_data)
            else:
                await self._save_plain_config(config_data)
            
            self._config = config
            self._config_version += 1
            
            # Notify change callbacks
            await self._notify_config_change()
            
            self.logger.info("Security configuration saved successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to save security configuration: {e}")
            raise
    
    def get_configuration(self) -> SecurityConfiguration:
        """Get current security configuration."""
        if self._config is None:
            raise RuntimeError("Configuration not loaded - call initialize() first")
        return self._config
    
    async def update_configuration(self, updates: Dict[str, Any]) -> None:
        """Update configuration with partial changes."""
        if self._config is None:
            raise RuntimeError("Configuration not loaded")
        
        try:
            # Apply updates to current configuration
            current_dict = self._config.to_dict()
            current_dict.update(updates)
            
            # Create new configuration instance
            new_config = SecurityConfiguration.from_dict(current_dict)
            
            # Validate new configuration
            await self._validate_configuration_dict(current_dict)
            
            # Save updated configuration
            await self.save_configuration(new_config)
            
            self.logger.info("Security configuration updated successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to update security configuration: {e}")
            raise
    
    def add_change_callback(self, callback: callable) -> None:
        """Add callback to be notified of configuration changes."""
        self._change_callbacks.append(callback)
    
    def remove_change_callback(self, callback: callable) -> None:
        """Remove configuration change callback."""
        if callback in self._change_callbacks:
            self._change_callbacks.remove(callback)
    
    async def _load_encrypted_config(self) -> Dict[str, Any]:
        """Load encrypted configuration file."""
        try:
            with open(self.encrypted_config_path, 'r') as f:
                encrypted_data = f.read()
            
            # Decrypt using secrets manager
            decrypted_data = await self.secrets_manager.encryption.decrypt(encrypted_data)
            
            return json.loads(decrypted_data)
            
        except Exception as e:
            self.logger.error(f"Failed to load encrypted configuration: {e}")
            raise
    
    async def _save_encrypted_config(self, config_data: Dict[str, Any]) -> None:
        """Save encrypted configuration file."""
        try:
            # Convert to JSON
            json_data = json.dumps(config_data, indent=2)
            
            # Encrypt using secrets manager
            encrypted_data = await self.secrets_manager.encryption.encrypt(json_data)
            
            # Save encrypted file
            with open(self.encrypted_config_path, 'w') as f:
                f.write(encrypted_data)
            
            # Set restrictive permissions
            os.chmod(self.encrypted_config_path, 0o600)
            
        except Exception as e:
            self.logger.error(f"Failed to save encrypted configuration: {e}")
            raise
    
    async def _load_plain_config(self) -> Dict[str, Any]:
        """Load plain text configuration file."""
        with open(self.config_path, 'r') as f:
            return json.load(f)
    
    async def _save_plain_config(self, config_data: Dict[str, Any]) -> None:
        """Save plain text configuration file."""
        with open(self.config_path, 'w') as f:
            json.dump(config_data, f, indent=2)
        
        # Set restrictive permissions
        os.chmod(self.config_path, 0o600)
    
    async def _apply_environment_overrides(self) -> None:
        """Apply environment variable overrides to configuration."""
        if self._config is None:
            return
        
        # Map environment variables to configuration paths
        env_mappings = {
            'SECURITY_ENABLED': 'security_enabled',
            'DEBUG_MODE': 'debug_mode',
            'ENVIRONMENT': 'environment',
            
            # PII Detection
            'PII_DETECTION_ENABLED': 'pii_detection.enabled',
            'PII_DETECTION_SENSITIVITY': 'pii_detection.sensitivity',
            'PII_CONFIDENCE_THRESHOLD': 'pii_detection.confidence_threshold',
            
            # Authentication
            'REQUIRE_MFA': 'authentication.require_mfa',
            'SESSION_TIMEOUT_MINUTES': 'authentication.session_timeout_minutes',
            'MAX_CONCURRENT_SESSIONS': 'authentication.max_concurrent_sessions',
            
            # Rate Limiting
            'RATE_LIMIT_ENABLED': 'rate_limiting.enabled',
            'RATE_LIMIT_REQUESTS_PER_MINUTE': 'rate_limiting.requests_per_minute',
            'RATE_LIMIT_BURST_LIMIT': 'rate_limiting.burst_limit',
            
            # Security Headers
            'SECURITY_HEADERS_ENABLED': 'security_headers.enabled',
            'CSP_POLICY': 'security_headers.content_security_policy',
            'HSTS_MAX_AGE': 'security_headers.strict_transport_security',
            
            # Compliance
            'GDPR_COMPLIANCE_MODE': 'compliance.gdpr_mode',
            'HIPAA_COMPLIANCE_MODE': 'compliance.hipaa_mode',
            'DATA_RETENTION_DAYS': 'compliance.data_retention_days'
        }
        
        try:
            config_dict = self._config.to_dict()
            
            for env_var, config_path in env_mappings.items():
                env_value = os.getenv(env_var)
                if env_value is not None:
                    # Convert string values to appropriate types
                    processed_value = self._process_env_value(env_value)
                    
                    # Set nested configuration value
                    self._set_nested_config_value(config_dict, config_path, processed_value)
            
            # Update configuration
            self._config = SecurityConfiguration.from_dict(config_dict)
            
        except Exception as e:
            self.logger.warning(f"Failed to apply environment overrides: {e}")
    
    def _process_env_value(self, value: str) -> Union[str, int, float, bool]:
        """Process environment variable value to appropriate type."""
        # Boolean values
        if value.lower() in ('true', '1', 'yes', 'on'):
            return True
        elif value.lower() in ('false', '0', 'no', 'off'):
            return False
        
        # Try integer
        try:
            return int(value)
        except ValueError:
            pass
        
        # Try float
        try:
            return float(value)
        except ValueError:
            pass
        
        # Return as string
        return value
    
    def _set_nested_config_value(self, config_dict: Dict[str, Any], path: str, value: Any) -> None:
        """Set nested configuration value using dot notation path."""
        keys = path.split('.')
        current = config_dict
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    async def _validate_configuration(self) -> None:
        """Validate current configuration."""
        if self._config is not None:
            await self._validate_configuration_dict(self._config.to_dict())
    
    async def _validate_configuration_dict(self, config_data: Dict[str, Any]) -> None:
        """Validate configuration dictionary."""
        # Validate PII detection settings
        pii_config = config_data.get('pii_detection', {})
        if 'sensitivity' in pii_config:
            sensitivity = pii_config['sensitivity']
            if not 0.0 <= sensitivity <= 1.0:
                raise ValueError("PII detection sensitivity must be between 0.0 and 1.0")
        
        # Validate rate limiting settings
        rate_limit_config = config_data.get('rate_limiting', {})
        if 'requests_per_minute' in rate_limit_config:
            rpm = rate_limit_config['requests_per_minute']
            if rpm <= 0:
                raise ValueError("Requests per minute must be positive")
        
        # Validate session timeout settings
        auth_config = config_data.get('authentication', {})
        if 'session_timeout_minutes' in auth_config:
            timeout = auth_config['session_timeout_minutes']
            if timeout <= 0:
                raise ValueError("Session timeout must be positive")
        
        # Add more validation rules as needed
        self.logger.debug("Configuration validation passed")
    
    async def _notify_config_change(self) -> None:
        """Notify all callbacks of configuration change."""
        for callback in self._change_callbacks:
            try:
                if callable(callback):
                    await callback(self._config)
            except Exception as e:
                self.logger.warning(f"Configuration change callback failed: {e}")
    
    def get_config_version(self) -> int:
        """Get current configuration version."""
        return self._config_version