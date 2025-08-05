"""
Input Validation System for Threat Hunter Pro.

This module provides comprehensive input validation to protect against
injection attacks, malformed data, and other security threats.
"""

from __future__ import annotations

import re
import json
import logging
from typing import Dict, Any, Optional, List, Union, Callable
from dataclasses import dataclass
from enum import Enum
import html
import urllib.parse


class ValidationType(Enum):
    """Types of validation rules."""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    EMAIL = "email"
    URL = "url"
    IP_ADDRESS = "ip_address"
    UUID = "uuid"
    JSON = "json"
    SQL_SAFE = "sql_safe"
    FILENAME = "filename"
    REGEX = "regex"
    CUSTOM = "custom"


@dataclass
class ValidationRule:
    """Validation rule configuration."""
    field_name: str
    validation_type: ValidationType
    required: bool = False
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None
    allowed_values: Optional[List[Any]] = None
    regex_pattern: Optional[str] = None
    custom_validator: Optional[Callable[[Any], bool]] = None
    sanitize: bool = True
    error_message: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of input validation."""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    sanitized_data: Dict[str, Any]
    original_data: Dict[str, Any]


class InputValidator:
    """
    Comprehensive input validation system.
    
    Features:
    - Multiple validation types
    - SQL injection prevention
    - XSS prevention
    - Path traversal prevention
    - Custom validation rules
    - Automatic sanitization
    - Detailed error reporting
    """
    
    # Pre-compiled regex patterns for performance
    PATTERNS = {
        'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
        'url': re.compile(r'^https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:\w*))?)?$'),
        'ipv4': re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'),
        'ipv6': re.compile(r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'),
        'uuid': re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.IGNORECASE),
        'filename': re.compile(r'^[a-zA-Z0-9._-]+$'),
        'sql_injection': re.compile(r'''
            (?i)                                    # Case insensitive
            (?:
                (?:union\s+select)|                 # UNION SELECT
                (?:select\s+.*\s+from)|             # SELECT ... FROM
                (?:insert\s+into)|                  # INSERT INTO
                (?:update\s+.*\s+set)|              # UPDATE ... SET
                (?:delete\s+from)|                  # DELETE FROM
                (?:drop\s+(?:table|database))|      # DROP TABLE/DATABASE
                (?:create\s+(?:table|database))|    # CREATE TABLE/DATABASE
                (?:alter\s+table)|                  # ALTER TABLE
                (?:exec(?:ute)?)|                   # EXEC/EXECUTE
                (?:sp_)|                            # Stored procedures
                (?:xp_)|                            # Extended stored procedures
                (?:--)|                             # SQL comments
                (?:/\*.*?\*/)                       # SQL block comments
            )
        ''', re.VERBOSE),
        'xss': re.compile(r'''
            (?i)                                    # Case insensitive
            (?:
                (?:<script[^>]*>)|                  # <script> tags
                (?:</script>)|                      # </script> tags
                (?:javascript:)|                    # javascript: protocol
                (?:vbscript:)|                      # vbscript: protocol
                (?:on\w+\s*=)|                      # Event handlers (onclick, onload, etc.)
                (?:<iframe[^>]*>)|                  # <iframe> tags
                (?:<object[^>]*>)|                  # <object> tags
                (?:<embed[^>]*>)|                   # <embed> tags
                (?:<link[^>]*>)|                    # <link> tags
                (?:<meta[^>]*>)|                    # <meta> tags
                (?:expression\s*\()|                # CSS expression()
                (?:@import)|                        # CSS @import
                (?:data:text/html)                  # data: URLs with HTML
            )
        ''', re.VERBOSE),
        'path_traversal': re.compile(r'(?:\.\.[\\/]|[\\/]\.\.[\\/]|[\\/]\.\.$)'),
        'command_injection': re.compile(r'''
            (?:
                (?:[;&|`])|                         # Command separators
                (?:\$\(.*?\))|                      # Command substitution
                (?:`.*?`)|                          # Backtick command substitution
                (?:\|\s*\w+)|                       # Pipe to command
                (?:>\s*[\w/.-]+)|                   # Output redirection
                (?:<\s*[\w/.-]+)                    # Input redirection
            )
        ''', re.VERBOSE)
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the input validator."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Validation configuration
        self.strict_mode = self.config.get('strict_mode', True)
        self.auto_sanitize = self.config.get('auto_sanitize', True)
        self.max_string_length = self.config.get('max_string_length', 10000)
        self.max_json_depth = self.config.get('max_json_depth', 10)
        
        # Custom validation rules
        self.custom_rules: Dict[str, ValidationRule] = {}
        
        # Security patterns
        self.security_checks_enabled = self.config.get('security_checks_enabled', True)
        
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the input validator."""
        if self._initialized:
            return
        
        try:
            # Load custom validation rules if configured
            await self._load_custom_rules()
            
            self._initialized = True
            self.logger.info("Input Validator initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize input validator: {e}")
            raise
    
    async def validate(
        self,
        data: Dict[str, Any],
        rules: List[ValidationRule],
        context: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """
        Validate input data against a set of rules.
        
        Args:
            data: Input data to validate
            rules: List of validation rules to apply
            context: Additional context for validation
            
        Returns:
            ValidationResult with validation outcome and sanitized data
        """
        if not self._initialized:
            await self.initialize()
        
        errors = []
        warnings = []
        sanitized_data = {}
        original_data = data.copy()
        
        try:
            # Perform security checks first
            if self.security_checks_enabled:
                security_errors = await self._perform_security_checks(data)
                errors.extend(security_errors)
            
            # Validate each field according to rules
            for rule in rules:
                field_name = rule.field_name
                field_value = data.get(field_name)
                
                try:
                    # Check if required field is present
                    if rule.required and (field_value is None or field_value == ""):
                        errors.append(f"Required field '{field_name}' is missing")
                        continue
                    
                    # Skip validation if field is not present and not required
                    if field_value is None:
                        continue
                    
                    # Validate and sanitize the field
                    validation_result = await self._validate_field(field_value, rule)
                    
                    if validation_result['is_valid']:
                        sanitized_data[field_name] = validation_result['sanitized_value']
                        if validation_result.get('warnings'):
                            warnings.extend(validation_result['warnings'])
                    else:
                        errors.extend(validation_result['errors'])
                        # Include original value in sanitized data for error context
                        sanitized_data[field_name] = field_value
                        
                except Exception as e:
                    errors.append(f"Validation error for field '{field_name}': {e}")
            
            # Add any fields not covered by rules (if not in strict mode)
            if not self.strict_mode:
                for field_name, field_value in data.items():
                    if field_name not in sanitized_data:
                        # Apply basic sanitization
                        sanitized_data[field_name] = await self._basic_sanitize(field_value)
            
            is_valid = len(errors) == 0
            
            return ValidationResult(
                is_valid=is_valid,
                errors=errors,
                warnings=warnings,
                sanitized_data=sanitized_data,
                original_data=original_data
            )
            
        except Exception as e:
            self.logger.error(f"Validation failed: {e}")
            return ValidationResult(
                is_valid=False,
                errors=[f"Validation system error: {e}"],
                warnings=[],
                sanitized_data={},
                original_data=original_data
            )
    
    async def _validate_field(self, value: Any, rule: ValidationRule) -> Dict[str, Any]:
        """Validate a single field according to its rule."""
        errors = []
        warnings = []
        sanitized_value = value
        
        try:
            # Type-specific validation
            if rule.validation_type == ValidationType.STRING:
                result = await self._validate_string(value, rule)
            elif rule.validation_type == ValidationType.INTEGER:
                result = await self._validate_integer(value, rule)
            elif rule.validation_type == ValidationType.FLOAT:
                result = await self._validate_float(value, rule)
            elif rule.validation_type == ValidationType.BOOLEAN:
                result = await self._validate_boolean(value, rule)
            elif rule.validation_type == ValidationType.EMAIL:
                result = await self._validate_email(value, rule)
            elif rule.validation_type == ValidationType.URL:
                result = await self._validate_url(value, rule)
            elif rule.validation_type == ValidationType.IP_ADDRESS:
                result = await self._validate_ip_address(value, rule)
            elif rule.validation_type == ValidationType.UUID:
                result = await self._validate_uuid(value, rule)
            elif rule.validation_type == ValidationType.JSON:
                result = await self._validate_json(value, rule)
            elif rule.validation_type == ValidationType.SQL_SAFE:
                result = await self._validate_sql_safe(value, rule)
            elif rule.validation_type == ValidationType.FILENAME:
                result = await self._validate_filename(value, rule)
            elif rule.validation_type == ValidationType.REGEX:
                result = await self._validate_regex(value, rule)
            elif rule.validation_type == ValidationType.CUSTOM:
                result = await self._validate_custom(value, rule)
            else:
                result = {
                    'is_valid': False,
                    'errors': [f"Unknown validation type: {rule.validation_type}"],
                    'sanitized_value': value
                }
            
            return result
            
        except Exception as e:
            return {
                'is_valid': False,
                'errors': [f"Field validation error: {e}"],
                'sanitized_value': value
            }
    
    async def _validate_string(self, value: Any, rule: ValidationRule) -> Dict[str, Any]:
        """Validate string field."""
        errors = []
        warnings = []
        
        # Convert to string
        try:
            str_value = str(value)
        except Exception:
            return {'is_valid': False, 'errors': ['Value cannot be converted to string'], 'sanitized_value': value}
        
        # Length checks
        if rule.min_length is not None and len(str_value) < rule.min_length:
            errors.append(f"String too short (minimum {rule.min_length} characters)")
        
        if rule.max_length is not None and len(str_value) > rule.max_length:
            errors.append(f"String too long (maximum {rule.max_length} characters)")
        
        # Check against maximum system limit
        if len(str_value) > self.max_string_length:
            errors.append(f"String exceeds system limit ({self.max_string_length} characters)")
        
        # Allowed values check
        if rule.allowed_values and str_value not in rule.allowed_values:
            errors.append(f"Value not in allowed list: {rule.allowed_values}")
        
        # Sanitize if requested
        sanitized_value = str_value
        if rule.sanitize and self.auto_sanitize:
            sanitized_value = html.escape(str_value)
            if sanitized_value != str_value:
                warnings.append("String was HTML-escaped")
        
        return {
            'is_valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'sanitized_value': sanitized_value
        }
    
    async def _validate_integer(self, value: Any, rule: ValidationRule) -> Dict[str, Any]:
        """Validate integer field."""
        errors = []
        
        # Convert to integer
        try:
            if isinstance(value, str):
                int_value = int(value.strip())
            else:
                int_value = int(value)
        except (ValueError, TypeError):
            return {'is_valid': False, 'errors': ['Value is not a valid integer'], 'sanitized_value': value}
        
        # Range checks
        if rule.min_value is not None and int_value < rule.min_value:
            errors.append(f"Value too small (minimum {rule.min_value})")
        
        if rule.max_value is not None and int_value > rule.max_value:
            errors.append(f"Value too large (maximum {rule.max_value})")
        
        # Allowed values check
        if rule.allowed_values and int_value not in rule.allowed_values:
            errors.append(f"Value not in allowed list: {rule.allowed_values}")
        
        return {
            'is_valid': len(errors) == 0,
            'errors': errors,
            'sanitized_value': int_value
        }
    
    async def _validate_float(self, value: Any, rule: ValidationRule) -> Dict[str, Any]:
        """Validate float field."""
        errors = []
        
        # Convert to float
        try:
            if isinstance(value, str):
                float_value = float(value.strip())
            else:
                float_value = float(value)
        except (ValueError, TypeError):
            return {'is_valid': False, 'errors': ['Value is not a valid number'], 'sanitized_value': value}
        
        # Range checks
        if rule.min_value is not None and float_value < rule.min_value:
            errors.append(f"Value too small (minimum {rule.min_value})")
        
        if rule.max_value is not None and float_value > rule.max_value:
            errors.append(f"Value too large (maximum {rule.max_value})")
        
        return {
            'is_valid': len(errors) == 0,
            'errors': errors,
            'sanitized_value': float_value
        }
    
    async def _validate_boolean(self, value: Any, rule: ValidationRule) -> Dict[str, Any]:
        """Validate boolean field."""
        if isinstance(value, bool):
            bool_value = value
        elif isinstance(value, str):
            lower_value = value.lower().strip()
            if lower_value in ('true', '1', 'yes', 'on'):
                bool_value = True
            elif lower_value in ('false', '0', 'no', 'off'):
                bool_value = False
            else:
                return {'is_valid': False, 'errors': ['Value is not a valid boolean'], 'sanitized_value': value}
        elif isinstance(value, (int, float)):
            bool_value = bool(value)
        else:
            return {'is_valid': False, 'errors': ['Value is not a valid boolean'], 'sanitized_value': value}
        
        return {
            'is_valid': True,
            'errors': [],
            'sanitized_value': bool_value
        }
    
    async def _validate_email(self, value: Any, rule: ValidationRule) -> Dict[str, Any]:
        """Validate email field."""
        str_value = str(value).strip().lower()
        
        if not self.PATTERNS['email'].match(str_value):
            return {'is_valid': False, 'errors': ['Invalid email format'], 'sanitized_value': value}
        
        return {
            'is_valid': True,
            'errors': [],
            'sanitized_value': str_value
        }
    
    async def _validate_url(self, value: Any, rule: ValidationRule) -> Dict[str, Any]:
        """Validate URL field."""
        str_value = str(value).strip()
        
        if not self.PATTERNS['url'].match(str_value):
            return {'is_valid': False, 'errors': ['Invalid URL format'], 'sanitized_value': value}
        
        # Additional security check for URL
        parsed_url = urllib.parse.urlparse(str_value)
        if parsed_url.scheme not in ('http', 'https'):
            return {'is_valid': False, 'errors': ['Only HTTP/HTTPS URLs allowed'], 'sanitized_value': value}
        
        return {
            'is_valid': True,
            'errors': [],
            'sanitized_value': str_value
        }
    
    async def _validate_ip_address(self, value: Any, rule: ValidationRule) -> Dict[str, Any]:
        """Validate IP address field."""
        str_value = str(value).strip()
        
        # Check IPv4
        if self.PATTERNS['ipv4'].match(str_value):
            return {'is_valid': True, 'errors': [], 'sanitized_value': str_value}
        
        # Check IPv6
        if self.PATTERNS['ipv6'].match(str_value):
            return {'is_valid': True, 'errors': [], 'sanitized_value': str_value}
        
        return {'is_valid': False, 'errors': ['Invalid IP address format'], 'sanitized_value': value}
    
    async def _validate_uuid(self, value: Any, rule: ValidationRule) -> Dict[str, Any]:
        """Validate UUID field."""
        str_value = str(value).strip()
        
        if not self.PATTERNS['uuid'].match(str_value):
            return {'is_valid': False, 'errors': ['Invalid UUID format'], 'sanitized_value': value}
        
        return {
            'is_valid': True,
            'errors': [],
            'sanitized_value': str_value.lower()
        }
    
    async def _validate_json(self, value: Any, rule: ValidationRule) -> Dict[str, Any]:
        """Validate JSON field."""
        if isinstance(value, (dict, list)):
            # Already parsed JSON
            json_value = value
        else:
            # Try to parse as JSON string
            try:
                json_value = json.loads(str(value))
            except json.JSONDecodeError as e:
                return {'is_valid': False, 'errors': [f'Invalid JSON: {e}'], 'sanitized_value': value}
        
        # Check JSON depth to prevent DoS
        if self._get_json_depth(json_value) > self.max_json_depth:
            return {'is_valid': False, 'errors': ['JSON too deeply nested'], 'sanitized_value': value}
        
        return {
            'is_valid': True,
            'errors': [],
            'sanitized_value': json_value
        }
    
    async def _validate_sql_safe(self, value: Any, rule: ValidationRule) -> Dict[str, Any]:
        """Validate that value is safe from SQL injection."""
        str_value = str(value)
        
        if self.PATTERNS['sql_injection'].search(str_value):
            return {'is_valid': False, 'errors': ['Potential SQL injection detected'], 'sanitized_value': value}
        
        return {
            'is_valid': True,
            'errors': [],
            'sanitized_value': str_value
        }
    
    async def _validate_filename(self, value: Any, rule: ValidationRule) -> Dict[str, Any]:
        """Validate filename field."""
        str_value = str(value).strip()
        
        # Check for path traversal
        if self.PATTERNS['path_traversal'].search(str_value):
            return {'is_valid': False, 'errors': ['Path traversal detected in filename'], 'sanitized_value': value}
        
        # Check filename pattern
        if not self.PATTERNS['filename'].match(str_value):
            return {'is_valid': False, 'errors': ['Invalid filename format'], 'sanitized_value': value}
        
        return {
            'is_valid': True,
            'errors': [],
            'sanitized_value': str_value
        }
    
    async def _validate_regex(self, value: Any, rule: ValidationRule) -> Dict[str, Any]:
        """Validate against custom regex pattern."""
        if not rule.regex_pattern:
            return {'is_valid': False, 'errors': ['No regex pattern specified'], 'sanitized_value': value}
        
        str_value = str(value)
        
        try:
            pattern = re.compile(rule.regex_pattern)
            if not pattern.match(str_value):
                error_msg = rule.error_message or f'Value does not match required pattern'
                return {'is_valid': False, 'errors': [error_msg], 'sanitized_value': value}
        except re.error as e:
            return {'is_valid': False, 'errors': [f'Invalid regex pattern: {e}'], 'sanitized_value': value}
        
        return {
            'is_valid': True,
            'errors': [],
            'sanitized_value': str_value
        }
    
    async def _validate_custom(self, value: Any, rule: ValidationRule) -> Dict[str, Any]:
        """Validate using custom validator function."""
        if not rule.custom_validator:
            return {'is_valid': False, 'errors': ['No custom validator specified'], 'sanitized_value': value}
        
        try:
            is_valid = rule.custom_validator(value)
            if not is_valid:
                error_msg = rule.error_message or 'Custom validation failed'
                return {'is_valid': False, 'errors': [error_msg], 'sanitized_value': value}
        except Exception as e:
            return {'is_valid': False, 'errors': [f'Custom validator error: {e}'], 'sanitized_value': value}
        
        return {
            'is_valid': True,
            'errors': [],
            'sanitized_value': value
        }
    
    async def _perform_security_checks(self, data: Dict[str, Any]) -> List[str]:
        """Perform security checks on all input data."""
        errors = []
        
        try:
            # Convert data to string for security scanning
            data_str = json.dumps(data, default=str)
            
            # Check for XSS
            if self.PATTERNS['xss'].search(data_str):
                errors.append('Potential XSS attack detected')
            
            # Check for command injection
            if self.PATTERNS['command_injection'].search(data_str):
                errors.append('Potential command injection detected')
            
            # Check for path traversal
            if self.PATTERNS['path_traversal'].search(data_str):
                errors.append('Path traversal detected')
            
        except Exception as e:
            self.logger.warning(f"Security check failed: {e}")
        
        return errors
    
    async def _basic_sanitize(self, value: Any) -> Any:
        """Apply basic sanitization to a value."""
        if isinstance(value, str):
            # HTML escape
            sanitized = html.escape(value)
            # URL encode special characters
            sanitized = urllib.parse.quote(sanitized, safe='')
            return urllib.parse.unquote(sanitized)
        
        return value
    
    def _get_json_depth(self, obj: Any, depth: int = 0) -> int:
        """Calculate the depth of a JSON object."""
        if depth > self.max_json_depth:
            return depth
        
        if isinstance(obj, dict):
            return max([self._get_json_depth(v, depth + 1) for v in obj.values()] + [depth])
        elif isinstance(obj, list):
            return max([self._get_json_depth(item, depth + 1) for item in obj] + [depth])
        else:
            return depth
    
    def add_custom_rule(self, rule: ValidationRule) -> None:
        """Add a custom validation rule."""
        self.custom_rules[rule.field_name] = rule
        self.logger.info(f"Added custom validation rule: {rule.field_name}")
    
    async def _load_custom_rules(self) -> None:
        """Load custom validation rules from configuration."""
        # This would load custom rules from configuration
        # Placeholder implementation
        pass