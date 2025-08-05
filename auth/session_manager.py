"""
Secure Session Management for Threat Hunter Pro.

This module provides comprehensive session management with security features
including session validation, timeout handling, and concurrent session control.
"""

from __future__ import annotations

import secrets
import hashlib
import json
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum


class SessionState(Enum):
    """Session states."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    LOCKED = "locked"


@dataclass
class SessionInfo:
    """Session information."""
    session_id: str
    user_id: str
    user_agent: Optional[str]
    source_ip: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    state: SessionState
    mfa_verified: bool = False
    permissions: List[str] = None
    device_fingerprint: Optional[str] = None
    
    def __post_init__(self):
        if self.permissions is None:
            self.permissions = []
    
    def is_valid(self) -> bool:
        """Check if session is valid."""
        now = datetime.now(timezone.utc)
        return (self.state == SessionState.ACTIVE and 
                self.expires_at > now)
    
    def is_expired(self) -> bool:
        """Check if session is expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data['state'] = self.state.value
        data['created_at'] = self.created_at.isoformat()
        data['last_activity'] = self.last_activity.isoformat()
        data['expires_at'] = self.expires_at.isoformat()
        return data


class SessionManager:
    """
    Secure session management system.
    
    Features:
    - Secure session token generation
    - Session timeout and renewal
    - Concurrent session limiting
    - Session hijacking protection
    - Activity tracking and monitoring
    - Automatic cleanup of expired sessions
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the session manager."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Session configuration
        self.session_timeout = timedelta(minutes=self.config.get('session_timeout_minutes', 60))
        self.absolute_timeout = timedelta(hours=self.config.get('absolute_timeout_hours', 8))
        self.max_concurrent_sessions = self.config.get('max_concurrent_sessions', 5)
        self.session_renewal_threshold = timedelta(minutes=self.config.get('renewal_threshold_minutes', 15))
        
        # Security settings
        self.require_ip_consistency = self.config.get('require_ip_consistency', True)
        self.require_user_agent_consistency = self.config.get('require_user_agent_consistency', True)
        self.track_device_fingerprint = self.config.get('track_device_fingerprint', True)
        
        # Session storage
        self.sessions: Dict[str, SessionInfo] = {}
        self.user_sessions: Dict[str, List[str]] = {}  # user_id -> session_ids
        
        # Activity tracking
        self.session_activity: Dict[str, List[datetime]] = {}
        
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the session manager."""
        if self._initialized:
            return
        
        try:
            # Load existing sessions from storage
            await self._load_sessions()
            
            # Clean up expired sessions
            await self.cleanup_expired_sessions()
            
            self._initialized = True
            self.logger.info("Session Manager initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize session manager: {e}")
            raise
    
    async def create_session(
        self,
        user_id: str,
        source_ip: str,
        user_agent: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
        mfa_verified: bool = False,
        permissions: Optional[List[str]] = None
    ) -> str:
        """
        Create a new session for a user.
        
        Args:
            user_id: User identifier
            source_ip: Source IP address
            user_agent: User agent string
            device_fingerprint: Device fingerprint for tracking
            mfa_verified: Whether MFA was verified
            permissions: User permissions for this session
            
        Returns:
            Session ID
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # Check concurrent session limit
            await self._enforce_session_limit(user_id)
            
            # Generate secure session ID
            session_id = self._generate_session_id()
            
            # Calculate expiration times
            now = datetime.now(timezone.utc)
            session_expires = now + self.session_timeout
            absolute_expires = now + self.absolute_timeout
            expires_at = min(session_expires, absolute_expires)
            
            # Create session info
            session_info = SessionInfo(
                session_id=session_id,
                user_id=user_id,
                user_agent=user_agent,
                source_ip=source_ip,
                created_at=now,
                last_activity=now,
                expires_at=expires_at,
                state=SessionState.ACTIVE,
                mfa_verified=mfa_verified,
                permissions=permissions or [],
                device_fingerprint=device_fingerprint
            )
            
            # Store session
            self.sessions[session_id] = session_info
            
            # Add to user sessions
            if user_id not in self.user_sessions:
                self.user_sessions[user_id] = []
            self.user_sessions[user_id].append(session_id)
            
            # Initialize activity tracking
            self.session_activity[session_id] = [now]
            
            # Save to storage
            await self._save_sessions()
            
            self.logger.info(f"Session created for user {user_id}: {session_id}")
            return session_id
            
        except Exception as e:
            self.logger.error(f"Session creation failed: {e}")
            raise
    
    async def validate_session(
        self,
        session_id: str,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Optional[SessionInfo]:
        """
        Validate a session and return session info if valid.
        
        Args:
            session_id: Session identifier
            source_ip: Source IP address for validation
            user_agent: User agent for validation
            
        Returns:
            SessionInfo if valid, None otherwise
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            session_info = self.sessions.get(session_id)
            if not session_info:
                return None
            
            # Check if session is valid
            if not session_info.is_valid():
                if session_info.is_expired():
                    session_info.state = SessionState.EXPIRED
                    await self._save_sessions()
                return None
            
            # Validate IP consistency if required
            if (self.require_ip_consistency and source_ip and 
                source_ip != session_info.source_ip):
                self.logger.warning(f"IP mismatch for session {session_id}: {source_ip} != {session_info.source_ip}")
                await self.revoke_session(session_id, "ip_mismatch")
                return None
            
            # Validate user agent consistency if required
            if (self.require_user_agent_consistency and user_agent and 
                user_agent != session_info.user_agent):
                self.logger.warning(f"User agent mismatch for session {session_id}")
                await self.revoke_session(session_id, "user_agent_mismatch")
                return None
            
            # Update last activity
            await self._update_session_activity(session_id)
            
            return session_info
            
        except Exception as e:
            self.logger.error(f"Session validation failed: {e}")
            return None
    
    async def renew_session(self, session_id: str) -> bool:
        """
        Renew a session if it's close to expiring.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if renewed, False otherwise
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            session_info = self.sessions.get(session_id)
            if not session_info or not session_info.is_valid():
                return False
            
            now = datetime.now(timezone.utc)
            time_until_expiry = session_info.expires_at - now
            
            # Check if renewal is needed
            if time_until_expiry <= self.session_renewal_threshold:
                # Calculate new expiration (but not beyond absolute timeout)
                new_expires = now + self.session_timeout
                absolute_expires = session_info.created_at + self.absolute_timeout
                session_info.expires_at = min(new_expires, absolute_expires)
                
                await self._save_sessions()
                
                self.logger.info(f"Session renewed: {session_id}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Session renewal failed: {e}")
            return False
    
    async def revoke_session(self, session_id: str, reason: str = "manual") -> bool:
        """
        Revoke a session.
        
        Args:
            session_id: Session identifier
            reason: Reason for revocation
            
        Returns:
            True if revoked, False if session not found
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            session_info = self.sessions.get(session_id)
            if not session_info:
                return False
            
            session_info.state = SessionState.REVOKED
            
            # Remove from user sessions
            user_id = session_info.user_id
            if user_id in self.user_sessions:
                self.user_sessions[user_id] = [
                    sid for sid in self.user_sessions[user_id] 
                    if sid != session_id
                ]
            
            # Clean up activity tracking
            if session_id in self.session_activity:
                del self.session_activity[session_id]
            
            await self._save_sessions()
            
            self.logger.info(f"Session revoked: {session_id} (reason: {reason})")
            return True
            
        except Exception as e:
            self.logger.error(f"Session revocation failed: {e}")
            return False
    
    async def revoke_user_sessions(self, user_id: str, except_session: Optional[str] = None) -> int:
        """
        Revoke all sessions for a user.
        
        Args:
            user_id: User identifier
            except_session: Session to exclude from revocation
            
        Returns:
            Number of sessions revoked
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            user_session_ids = self.user_sessions.get(user_id, []).copy()
            revoked_count = 0
            
            for session_id in user_session_ids:
                if session_id != except_session:
                    if await self.revoke_session(session_id, "user_logout"):
                        revoked_count += 1
            
            self.logger.info(f"Revoked {revoked_count} sessions for user {user_id}")
            return revoked_count
            
        except Exception as e:
            self.logger.error(f"User session revocation failed: {e}")
            return 0
    
    async def get_user_sessions(self, user_id: str) -> List[SessionInfo]:
        """Get all active sessions for a user."""
        if not self._initialized:
            await self.initialize()
        
        user_session_ids = self.user_sessions.get(user_id, [])
        sessions = []
        
        for session_id in user_session_ids:
            session_info = self.sessions.get(session_id)
            if session_info and session_info.is_valid():
                sessions.append(session_info)
        
        return sessions
    
    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired and revoked sessions."""
        if not self._initialized:
            await self.initialize()
        
        try:
            expired_session_ids = []
            
            for session_id, session_info in self.sessions.items():
                if (session_info.state != SessionState.ACTIVE or 
                    session_info.is_expired()):
                    expired_session_ids.append(session_id)
            
            # Remove expired sessions
            for session_id in expired_session_ids:
                session_info = self.sessions[session_id]
                user_id = session_info.user_id
                
                # Remove from sessions
                del self.sessions[session_id]
                
                # Remove from user sessions
                if user_id in self.user_sessions:
                    self.user_sessions[user_id] = [
                        sid for sid in self.user_sessions[user_id] 
                        if sid != session_id
                    ]
                
                # Clean up activity tracking
                if session_id in self.session_activity:
                    del self.session_activity[session_id]
            
            if expired_session_ids:
                await self._save_sessions()
            
            self.logger.info(f"Cleaned up {len(expired_session_ids)} expired sessions")
            return len(expired_session_ids)
            
        except Exception as e:
            self.logger.error(f"Session cleanup failed: {e}")
            return 0
    
    async def get_session_stats(self) -> Dict[str, Any]:
        """Get session statistics."""
        if not self._initialized:
            await self.initialize()
        
        active_sessions = sum(1 for s in self.sessions.values() if s.is_valid())
        expired_sessions = sum(1 for s in self.sessions.values() if s.is_expired())
        revoked_sessions = sum(1 for s in self.sessions.values() if s.state == SessionState.REVOKED)
        
        return {
            'total_sessions': len(self.sessions),
            'active_sessions': active_sessions,
            'expired_sessions': expired_sessions,
            'revoked_sessions': revoked_sessions,
            'unique_users': len(self.user_sessions),
            'avg_sessions_per_user': active_sessions / max(len(self.user_sessions), 1)
        }
    
    async def _enforce_session_limit(self, user_id: str) -> None:
        """Enforce concurrent session limit for user."""
        user_sessions = await self.get_user_sessions(user_id)
        
        if len(user_sessions) >= self.max_concurrent_sessions:
            # Revoke oldest session
            oldest_session = min(user_sessions, key=lambda s: s.created_at)
            await self.revoke_session(oldest_session.session_id, "session_limit")
    
    async def _update_session_activity(self, session_id: str) -> None:
        """Update session activity timestamp."""
        session_info = self.sessions.get(session_id)
        if session_info:
            now = datetime.now(timezone.utc)
            session_info.last_activity = now
            
            # Track activity for monitoring
            if session_id not in self.session_activity:
                self.session_activity[session_id] = []
            self.session_activity[session_id].append(now)
            
            # Keep only recent activity (last hour)
            cutoff_time = now - timedelta(hours=1)
            self.session_activity[session_id] = [
                activity for activity in self.session_activity[session_id]
                if activity > cutoff_time
            ]
            
            # Save periodically (not on every activity update for performance)
            # This would be done on a timer or after certain number of updates
    
    def _generate_session_id(self) -> str:
        """Generate a cryptographically secure session ID."""
        # Generate 32 bytes of random data
        random_bytes = secrets.token_bytes(32)
        
        # Create session ID using URL-safe base64 encoding
        session_id = secrets.token_urlsafe(32)
        
        return session_id
    
    def _hash_session_data(self, session_info: SessionInfo) -> str:
        """Generate hash of session data for integrity checking."""
        session_data = f"{session_info.session_id}{session_info.user_id}{session_info.created_at}"
        return hashlib.sha256(session_data.encode()).hexdigest()
    
    async def _load_sessions(self) -> None:
        """Load sessions from persistent storage."""
        # This would load from database or secure file
        # Placeholder implementation
        pass
    
    async def _save_sessions(self) -> None:
        """Save sessions to persistent storage."""
        # This would save to database or secure file
        # Implementation would be asynchronous and handle encryption
        pass