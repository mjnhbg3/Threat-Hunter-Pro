"""
Multi-Factor Authentication (MFA) System for Threat Hunter Pro.

This module provides comprehensive MFA capabilities including TOTP,
backup codes, and device trust management for enhanced security.
"""

from __future__ import annotations

import secrets
import base64
import hashlib
import hmac
import struct
import time
import qrcode
import io
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timezone, timedelta


class MFAMethod(Enum):
    """Available MFA methods."""
    TOTP = "totp"
    BACKUP_CODES = "backup_codes"
    SMS = "sms"
    EMAIL = "email"


@dataclass
class MFADevice:
    """Represents an MFA device/method for a user."""
    device_id: str
    user_id: str
    method: MFAMethod
    name: str
    secret: Optional[str] = None  # For TOTP
    phone_number: Optional[str] = None  # For SMS
    email: Optional[str] = None  # For Email
    backup_codes: Optional[List[str]] = None
    is_verified: bool = False
    created_at: datetime = None
    last_used: Optional[datetime] = None
    use_count: int = 0
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)
    
    def to_dict(self, include_secrets: bool = False) -> Dict[str, Any]:
        """Convert to dictionary, optionally including secrets."""
        data = asdict(self)
        if not include_secrets:
            data['secret'] = None
            data['backup_codes'] = None
        data['method'] = self.method.value
        data['created_at'] = self.created_at.isoformat() if self.created_at else None
        data['last_used'] = self.last_used.isoformat() if self.last_used else None
        return data


@dataclass
class TrustedDevice:
    """Represents a trusted device that can bypass MFA."""
    device_id: str
    user_id: str
    device_fingerprint: str
    device_name: str
    trust_expires: datetime
    created_at: datetime
    last_used: Optional[datetime] = None
    
    def is_valid(self) -> bool:
        """Check if device trust is still valid."""
        return datetime.now(timezone.utc) < self.trust_expires
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'device_id': self.device_id,
            'user_id': self.user_id,
            'device_fingerprint': self.device_fingerprint,
            'device_name': self.device_name,
            'trust_expires': self.trust_expires.isoformat(),
            'created_at': self.created_at.isoformat(),
            'last_used': self.last_used.isoformat() if self.last_used else None
        }


class MFAManager:
    """
    Multi-Factor Authentication Manager.
    
    Features:
    - TOTP (Time-based One-Time Password) support
    - Backup codes for account recovery
    - Device trust management
    - Multiple MFA methods per user
    - Rate limiting and security monitoring
    - QR code generation for easy setup
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the MFA manager."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # MFA configuration
        self.issuer_name = self.config.get('issuer_name', 'Threat Hunter Pro')
        self.totp_window = self.config.get('totp_window', 1)  # Allow 1 step before/after
        self.backup_code_count = self.config.get('backup_code_count', 8)
        self.device_trust_days = self.config.get('device_trust_days', 30)
        
        # Storage
        self.mfa_devices: Dict[str, List[MFADevice]] = {}  # user_id -> devices
        self.trusted_devices: Dict[str, List[TrustedDevice]] = {}  # user_id -> devices
        
        # Rate limiting
        self.failed_attempts: Dict[str, List[datetime]] = {}  # user_id -> attempt times
        self.max_failed_attempts = self.config.get('max_failed_attempts', 5)
        self.lockout_duration = timedelta(minutes=self.config.get('lockout_minutes', 15))
        
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the MFA manager."""
        if self._initialized:
            return
        
        try:
            # Load MFA devices and trusted devices from storage
            await self._load_mfa_devices()
            await self._load_trusted_devices()
            
            self._initialized = True
            self.logger.info("MFA Manager initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize MFA manager: {e}")
            raise
    
    async def setup_totp(self, user_id: str, device_name: str) -> Tuple[str, str, bytes]:
        """
        Set up TOTP MFA for a user.
        
        Returns:
            Tuple of (device_id, secret, qr_code_image)
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # Generate secret
            secret = base64.b32encode(secrets.token_bytes(20)).decode('utf-8')
            
            # Generate device ID
            device_id = self._generate_device_id()
            
            # Create MFA device
            device = MFADevice(
                device_id=device_id,
                user_id=user_id,
                method=MFAMethod.TOTP,
                name=device_name,
                secret=secret,
                is_verified=False
            )
            
            # Add to user's devices
            if user_id not in self.mfa_devices:
                self.mfa_devices[user_id] = []
            self.mfa_devices[user_id].append(device)
            
            # Generate QR code
            totp_uri = self._generate_totp_uri(user_id, secret)
            qr_code = self._generate_qr_code(totp_uri)
            
            # Save to storage
            await self._save_mfa_devices()
            
            self.logger.info(f"TOTP setup initiated for user {user_id}")
            return device_id, secret, qr_code
            
        except Exception as e:
            self.logger.error(f"TOTP setup failed for user {user_id}: {e}")
            raise
    
    async def verify_totp_setup(self, user_id: str, device_id: str, token: str) -> bool:
        """Verify TOTP setup with initial token."""
        if not self._initialized:
            await self.initialize()
        
        try:
            device = self._get_device(user_id, device_id)
            if not device or device.method != MFAMethod.TOTP:
                return False
            
            # Verify token
            if self._verify_totp_token(device.secret, token):
                device.is_verified = True
                device.last_used = datetime.now(timezone.utc)
                device.use_count += 1
                
                await self._save_mfa_devices()
                
                self.logger.info(f"TOTP setup completed for user {user_id}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"TOTP verification failed: {e}")
            return False
    
    async def generate_backup_codes(self, user_id: str) -> List[str]:
        """Generate backup codes for a user."""
        if not self._initialized:
            await self.initialize()
        
        try:
            # Generate backup codes
            backup_codes = [self._generate_backup_code() for _ in range(self.backup_code_count)]
            
            # Hash codes for storage
            hashed_codes = [self._hash_backup_code(code) for code in backup_codes]
            
            # Create or update backup codes device
            device_id = self._generate_device_id()
            device = MFADevice(
                device_id=device_id,
                user_id=user_id,
                method=MFAMethod.BACKUP_CODES,
                name="Backup Codes",
                backup_codes=hashed_codes,
                is_verified=True
            )
            
            # Remove existing backup codes and add new ones
            if user_id in self.mfa_devices:
                self.mfa_devices[user_id] = [
                    d for d in self.mfa_devices[user_id] 
                    if d.method != MFAMethod.BACKUP_CODES
                ]
            else:
                self.mfa_devices[user_id] = []
            
            self.mfa_devices[user_id].append(device)
            
            await self._save_mfa_devices()
            
            self.logger.info(f"Backup codes generated for user {user_id}")
            return backup_codes
            
        except Exception as e:
            self.logger.error(f"Backup code generation failed: {e}")
            raise
    
    async def verify_mfa(self, user_id: str, token: str, device_id: Optional[str] = None) -> bool:
        """
        Verify MFA token for a user.
        
        Args:
            user_id: User identifier
            token: MFA token to verify
            device_id: Specific device to verify against (optional)
            
        Returns:
            True if token is valid, False otherwise
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # Check if user is locked out
            if await self._is_user_locked_out(user_id):
                self.logger.warning(f"MFA verification blocked - user {user_id} is locked out")
                return False
            
            user_devices = self.mfa_devices.get(user_id, [])
            if not user_devices:
                return False
            
            # Filter devices if device_id specified
            if device_id:
                user_devices = [d for d in user_devices if d.device_id == device_id]
            
            # Try each verified device
            for device in user_devices:
                if not device.is_verified:
                    continue
                
                verified = False
                
                if device.method == MFAMethod.TOTP:
                    verified = self._verify_totp_token(device.secret, token)
                elif device.method == MFAMethod.BACKUP_CODES:
                    verified = await self._verify_backup_code(device, token)
                
                if verified:
                    # Update device usage
                    device.last_used = datetime.now(timezone.utc)
                    device.use_count += 1
                    
                    await self._save_mfa_devices()
                    
                    # Clear failed attempts
                    if user_id in self.failed_attempts:
                        del self.failed_attempts[user_id]
                    
                    self.logger.info(f"MFA verification successful for user {user_id}")
                    return True
            
            # Record failed attempt
            await self._record_failed_attempt(user_id)
            
            self.logger.warning(f"MFA verification failed for user {user_id}")
            return False
            
        except Exception as e:
            self.logger.error(f"MFA verification error: {e}")
            return False
    
    async def is_mfa_required(self, user_id: str, device_fingerprint: Optional[str] = None) -> bool:
        """Check if MFA is required for a user."""
        if not self._initialized:
            await self.initialize()
        
        # Check if user has MFA devices
        user_devices = self.mfa_devices.get(user_id, [])
        verified_devices = [d for d in user_devices if d.is_verified]
        
        if not verified_devices:
            return False  # No MFA set up
        
        # Check trusted devices
        if device_fingerprint:
            trusted_devices = self.trusted_devices.get(user_id, [])
            for device in trusted_devices:
                if (device.device_fingerprint == device_fingerprint and 
                    device.is_valid()):
                    # Update last used
                    device.last_used = datetime.now(timezone.utc)
                    await self._save_trusted_devices()
                    return False  # Trusted device, skip MFA
        
        return True  # MFA required
    
    async def trust_device(
        self,
        user_id: str,
        device_fingerprint: str,
        device_name: str,
        trust_days: Optional[int] = None
    ) -> str:
        """Add a device to the trusted devices list."""
        if not self._initialized:
            await self.initialize()
        
        try:
            trust_days = trust_days or self.device_trust_days
            device_id = self._generate_device_id()
            
            trusted_device = TrustedDevice(
                device_id=device_id,
                user_id=user_id,
                device_fingerprint=device_fingerprint,
                device_name=device_name,
                trust_expires=datetime.now(timezone.utc) + timedelta(days=trust_days),
                created_at=datetime.now(timezone.utc)
            )
            
            if user_id not in self.trusted_devices:
                self.trusted_devices[user_id] = []
            
            self.trusted_devices[user_id].append(trusted_device)
            
            await self._save_trusted_devices()
            
            self.logger.info(f"Device trusted for user {user_id}: {device_name}")
            return device_id
            
        except Exception as e:
            self.logger.error(f"Device trust failed: {e}")
            raise
    
    async def revoke_device_trust(self, user_id: str, device_id: str) -> bool:
        """Revoke trust for a specific device."""
        if not self._initialized:
            await self.initialize()
        
        try:
            if user_id not in self.trusted_devices:
                return False
            
            original_count = len(self.trusted_devices[user_id])
            self.trusted_devices[user_id] = [
                d for d in self.trusted_devices[user_id]
                if d.device_id != device_id
            ]
            
            if len(self.trusted_devices[user_id]) < original_count:
                await self._save_trusted_devices()
                self.logger.info(f"Device trust revoked for user {user_id}: {device_id}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Device trust revocation failed: {e}")
            return False
    
    async def remove_mfa_device(self, user_id: str, device_id: str) -> bool:
        """Remove an MFA device for a user."""
        if not self._initialized:
            await self.initialize()
        
        try:
            if user_id not in self.mfa_devices:
                return False
            
            original_count = len(self.mfa_devices[user_id])
            self.mfa_devices[user_id] = [
                d for d in self.mfa_devices[user_id]
                if d.device_id != device_id
            ]
            
            if len(self.mfa_devices[user_id]) < original_count:
                await self._save_mfa_devices()
                self.logger.info(f"MFA device removed for user {user_id}: {device_id}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"MFA device removal failed: {e}")
            return False
    
    async def get_user_mfa_devices(self, user_id: str) -> List[MFADevice]:
        """Get all MFA devices for a user."""
        if not self._initialized:
            await self.initialize()
        
        return self.mfa_devices.get(user_id, [])
    
    async def get_user_trusted_devices(self, user_id: str) -> List[TrustedDevice]:
        """Get all trusted devices for a user."""
        if not self._initialized:
            await self.initialize()
        
        # Filter out expired devices
        trusted_devices = self.trusted_devices.get(user_id, [])
        valid_devices = [d for d in trusted_devices if d.is_valid()]
        
        # Update storage if we filtered out expired devices
        if len(valid_devices) < len(trusted_devices):
            self.trusted_devices[user_id] = valid_devices
            await self._save_trusted_devices()
        
        return valid_devices
    
    def _verify_totp_token(self, secret: str, token: str) -> bool:
        """Verify a TOTP token against the secret."""
        if not secret or not token:
            return False
        
        try:
            # Convert token to integer
            token_int = int(token)
            
            # Get current time step
            current_time_step = int(time.time()) // 30
            
            # Check current and adjacent time steps
            for i in range(-self.totp_window, self.totp_window + 1):
                time_step = current_time_step + i
                expected_token = self._generate_totp(secret, time_step)
                
                if expected_token == token_int:
                    return True
            
            return False
            
        except ValueError:
            return False
    
    def _generate_totp(self, secret: str, time_step: int) -> int:
        """Generate TOTP token for given secret and time step."""
        # Convert secret from base32
        key = base64.b32decode(secret)
        
        # Pack time step as big-endian 64-bit integer
        time_bytes = struct.pack('>Q', time_step)
        
        # Calculate HMAC
        hmac_digest = hmac.new(key, time_bytes, hashlib.sha1).digest()
        
        # Dynamic truncation
        offset = hmac_digest[-1] & 0x0f
        truncated = struct.unpack('>I', hmac_digest[offset:offset + 4])[0]
        truncated &= 0x7fffffff
        
        # Generate 6-digit code
        return truncated % 1000000
    
    async def _verify_backup_code(self, device: MFADevice, code: str) -> bool:
        """Verify a backup code and mark it as used."""
        if not device.backup_codes:
            return False
        
        hashed_code = self._hash_backup_code(code)
        
        if hashed_code in device.backup_codes:
            # Remove used backup code
            device.backup_codes.remove(hashed_code)
            return True
        
        return False
    
    def _generate_backup_code(self) -> str:
        """Generate a single backup code."""
        return '-'.join([
            ''.join(secrets.choice('0123456789') for _ in range(4))
            for _ in range(2)
        ])
    
    def _hash_backup_code(self, code: str) -> str:
        """Hash a backup code for secure storage."""
        return hashlib.sha256(code.encode()).hexdigest()
    
    def _generate_totp_uri(self, user_id: str, secret: str) -> str:
        """Generate TOTP URI for QR code."""
        return (f"otpauth://totp/{self.issuer_name}:{user_id}"
                f"?secret={secret}&issuer={self.issuer_name}")
    
    def _generate_qr_code(self, uri: str) -> bytes:
        """Generate QR code image for TOTP setup."""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to bytes
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        return img_buffer.getvalue()
    
    def _generate_device_id(self) -> str:
        """Generate unique device ID."""
        return secrets.token_urlsafe(16)
    
    def _get_device(self, user_id: str, device_id: str) -> Optional[MFADevice]:
        """Get specific MFA device for user."""
        user_devices = self.mfa_devices.get(user_id, [])
        return next((d for d in user_devices if d.device_id == device_id), None)
    
    async def _is_user_locked_out(self, user_id: str) -> bool:
        """Check if user is locked out due to failed attempts."""
        if user_id not in self.failed_attempts:
            return False
        
        # Clean old attempts
        cutoff_time = datetime.now(timezone.utc) - self.lockout_duration
        self.failed_attempts[user_id] = [
            attempt for attempt in self.failed_attempts[user_id]
            if attempt > cutoff_time
        ]
        
        return len(self.failed_attempts[user_id]) >= self.max_failed_attempts
    
    async def _record_failed_attempt(self, user_id: str) -> None:
        """Record a failed MFA attempt."""
        if user_id not in self.failed_attempts:
            self.failed_attempts[user_id] = []
        
        self.failed_attempts[user_id].append(datetime.now(timezone.utc))
    
    async def _load_mfa_devices(self) -> None:
        """Load MFA devices from storage."""
        # This would load from database or secure file
        # Placeholder implementation
        pass
    
    async def _save_mfa_devices(self) -> None:
        """Save MFA devices to storage."""
        # This would save to database or secure file
        # Placeholder implementation
        pass
    
    async def _load_trusted_devices(self) -> None:
        """Load trusted devices from storage."""
        # This would load from database or file
        # Placeholder implementation
        pass
    
    async def _save_trusted_devices(self) -> None:
        """Save trusted devices to storage."""
        # This would save to database or file
        # Placeholder implementation
        pass