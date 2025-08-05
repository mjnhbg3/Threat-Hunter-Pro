"""
Authentication Backend for Threat Hunter Pro.

This module provides a unified authentication backend that integrates
basic auth, MFA, RBAC, and session management into a cohesive system.
"""

from __future__ import annotations

import logging
import hashlib
import secrets
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime, timezone
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials

from .rbac import RBACManager, ResourceType, PermissionType
from .mfa import MFAManager
from .session_manager import SessionManager, SessionInfo


@dataclass
class AuthenticatedUser:
    """Represents an authenticated user."""
    user_id: str
    username: str
    roles: List[str]
    permissions: List[str]
    session_id: Optional[str] = None
    mfa_verified: bool = False
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None


class AuthenticationBackend:
    """
    Unified authentication backend.
    
    This class provides a comprehensive authentication system that integrates:
    - Basic HTTP authentication
    - Multi-factor authentication
    - Role-based access control
    - Secure session management
    - JWT token support
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the authentication backend."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize sub-systems
        self.rbac = RBACManager(self.config.get('rbac', {}))
        self.mfa = MFAManager(self.config.get('mfa', {}))
        self.session_manager = SessionManager(self.config.get('sessions', {}))
        
        # Authentication settings
        self.require_mfa = self.config.get('require_mfa', True)
        self.password_hash_rounds = self.config.get('password_hash_rounds', 12)
        
        # User storage (in production, this would be a proper database)
        self.users: Dict[str, Dict[str, Any]] = {}
        
        # FastAPI security schemes
        self.basic_auth = HTTPBasic()
        self.bearer_auth = HTTPBearer(optional=True)
        
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the authentication backend."""
        if self._initialized:
            return
        
        try:
            # Initialize sub-systems
            await self.rbac.initialize()
            await self.mfa.initialize()
            await self.session_manager.initialize()
            
            # Load users
            await self._load_users()
            
            # Create default admin user if none exists
            await self._ensure_admin_user()
            
            self._initialized = True
            self.logger.info("Authentication Backend initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize authentication backend: {e}")
            raise
    
    async def authenticate_basic(
        self,
        credentials: HTTPBasicCredentials,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_fingerprint: Optional[str] = None
    ) -> AuthenticatedUser:
        """
        Authenticate using HTTP Basic authentication.
        
        Args:
            credentials: HTTP Basic credentials
            source_ip: Source IP address
            user_agent: User agent string
            device_fingerprint: Device fingerprint
            
        Returns:
            AuthenticatedUser object
            
        Raises:
            HTTPException: If authentication fails
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # Validate credentials
            user_info = await self._validate_credentials(credentials.username, credentials.password)
            if not user_info:
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            user_id = user_info['user_id']
            
            # Check if MFA is required
            mfa_required = await self.mfa.is_mfa_required(user_id, device_fingerprint)
            
            if self.require_mfa and mfa_required:
                # Return user but mark as requiring MFA
                return AuthenticatedUser(
                    user_id=user_id,
                    username=credentials.username,
                    roles=[],
                    permissions=[],
                    mfa_verified=False,
                    source_ip=source_ip,
                    user_agent=user_agent
                )
            
            # Get user roles and permissions
            user_roles = await self.rbac.get_user_roles(user_id)
            user_permissions = await self.rbac.get_user_permissions(user_id)
            
            # Create session
            session_id = await self.session_manager.create_session(
                user_id=user_id,
                source_ip=source_ip or "",
                user_agent=user_agent,
                device_fingerprint=device_fingerprint,
                mfa_verified=not mfa_required,
                permissions=[str(p) for p in user_permissions]
            )
            
            return AuthenticatedUser(
                user_id=user_id,
                username=credentials.username,
                roles=[role.role_name for role in user_roles],
                permissions=[str(p) for p in user_permissions],
                session_id=session_id,
                mfa_verified=not mfa_required,
                source_ip=source_ip,
                user_agent=user_agent
            )
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Basic authentication failed: {e}")
            raise HTTPException(status_code=500, detail="Authentication error")
    
    async def complete_mfa_authentication(
        self,
        user_id: str,
        mfa_token: str,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
        trust_device: bool = False
    ) -> AuthenticatedUser:
        """
        Complete MFA authentication process.
        
        Args:
            user_id: User identifier
            mfa_token: MFA token/code
            source_ip: Source IP address
            user_agent: User agent string
            device_fingerprint: Device fingerprint
            trust_device: Whether to trust this device
            
        Returns:
            AuthenticatedUser object
            
        Raises:
            HTTPException: If MFA verification fails
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # Verify MFA token
            if not await self.mfa.verify_mfa(user_id, mfa_token):
                raise HTTPException(status_code=401, detail="Invalid MFA token")
            
            # Trust device if requested
            if trust_device and device_fingerprint:
                await self.mfa.trust_device(
                    user_id=user_id,
                    device_fingerprint=device_fingerprint,
                    device_name=f"Device from {source_ip}"
                )
            
            # Get user info
            user_info = self.users.get(user_id)
            if not user_info:
                raise HTTPException(status_code=401, detail="User not found")
            
            # Get user roles and permissions
            user_roles = await self.rbac.get_user_roles(user_id)
            user_permissions = await self.rbac.get_user_permissions(user_id)
            
            # Create session
            session_id = await self.session_manager.create_session(
                user_id=user_id,
                source_ip=source_ip or "",
                user_agent=user_agent,
                device_fingerprint=device_fingerprint,
                mfa_verified=True,
                permissions=[str(p) for p in user_permissions]
            )
            
            return AuthenticatedUser(
                user_id=user_id,
                username=user_info['username'],
                roles=[role.role_name for role in user_roles],
                permissions=[str(p) for p in user_permissions],
                session_id=session_id,
                mfa_verified=True,
                source_ip=source_ip,
                user_agent=user_agent
            )
            
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"MFA authentication completion failed: {e}")
            raise HTTPException(status_code=500, detail="Authentication error")
    
    async def authenticate_session(
        self,
        session_id: str,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Optional[AuthenticatedUser]:
        """
        Authenticate using session ID.
        
        Args:
            session_id: Session identifier
            source_ip: Source IP address
            user_agent: User agent string
            
        Returns:
            AuthenticatedUser object if valid session, None otherwise
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # Validate session
            session_info = await self.session_manager.validate_session(
                session_id=session_id,
                source_ip=source_ip,
                user_agent=user_agent
            )
            
            if not session_info:
                return None
            
            # Get user info
            user_info = self.users.get(session_info.user_id)
            if not user_info:
                await self.session_manager.revoke_session(session_id, "user_not_found")
                return None
            
            # Renew session if needed
            await self.session_manager.renew_session(session_id)
            
            return AuthenticatedUser(
                user_id=session_info.user_id,
                username=user_info['username'],
                roles=[],  # Would need to fetch current roles
                permissions=session_info.permissions,
                session_id=session_id,
                mfa_verified=session_info.mfa_verified,
                source_ip=source_ip,
                user_agent=user_agent
            )
            
        except Exception as e:
            self.logger.error(f"Session authentication failed: {e}")
            return None
    
    async def check_permission(
        self,
        user: AuthenticatedUser,
        resource_type: ResourceType,
        permission_type: PermissionType,
        resource_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Check if user has required permission.
        
        Args:
            user: Authenticated user
            resource_type: Type of resource
            permission_type: Type of permission
            resource_id: Specific resource ID
            context: Additional context
            
        Returns:
            True if user has permission, False otherwise
        """
        if not self._initialized:
            await self.initialize()
        
        # Enhance context with user information
        enhanced_context = context or {}
        enhanced_context.update({
            'user_id': user.user_id,
            'source_ip': user.source_ip,
            'mfa_verified': user.mfa_verified,
            'session_id': user.session_id
        })
        
        return await self.rbac.check_permission(
            user_id=user.user_id,
            resource_type=resource_type,
            permission_type=permission_type,
            resource_id=resource_id,
            context=enhanced_context
        )
    
    async def logout(self, user: AuthenticatedUser, revoke_all_sessions: bool = False) -> bool:
        """
        Log out a user.
        
        Args:
            user: Authenticated user
            revoke_all_sessions: Whether to revoke all user sessions
            
        Returns:
            True if successful, False otherwise
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            if revoke_all_sessions:
                await self.session_manager.revoke_user_sessions(user.user_id)
            elif user.session_id:
                await self.session_manager.revoke_session(user.session_id, "logout")
            
            self.logger.info(f"User logged out: {user.username}")
            return True
            
        except Exception as e:
            self.logger.error(f"Logout failed: {e}")
            return False
    
    async def create_user(
        self,
        username: str,
        password: str,
        email: Optional[str] = None,
        roles: Optional[List[str]] = None,
        created_by: str = "system"
    ) -> str:
        """
        Create a new user.
        
        Args:
            username: Username
            password: Password
            email: Email address
            roles: Initial roles
            created_by: Who created the user
            
        Returns:
            User ID
        """
        if not self._initialized:
            await self.initialize()
        
        try:
            # Check if user already exists
            for user_info in self.users.values():
                if user_info['username'] == username:
                    raise ValueError("User already exists")
            
            # Generate user ID
            user_id = self._generate_user_id()
            
            # Hash password
            password_hash = self._hash_password(password)
            
            # Create user
            user_info = {
                'user_id': user_id,
                'username': username,
                'password_hash': password_hash,
                'email': email,
                'created_at': datetime.now(timezone.utc),
                'created_by': created_by,
                'is_active': True
            }
            
            self.users[user_id] = user_info
            
            # Assign roles
            if roles:
                for role_name in roles:
                    await self.rbac.assign_role(
                        user_id=user_id,
                        role_name=role_name,
                        assigned_by=created_by
                    )
            
            # Save users
            await self._save_users()
            
            self.logger.info(f"User created: {username} ({user_id})")
            return user_id
            
        except Exception as e:
            self.logger.error(f"User creation failed: {e}")
            raise
    
    async def _validate_credentials(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Validate username and password."""
        for user_info in self.users.values():
            if (user_info['username'] == username and 
                user_info.get('is_active', True) and
                self._verify_password(password, user_info['password_hash'])):
                return user_info
        return None
    
    def _hash_password(self, password: str) -> str:
        """Hash a password using PBKDF2."""
        salt = secrets.token_bytes(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt.hex() + ':' + password_hash.hex()
    
    def _verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify a password against stored hash."""
        try:
            salt_hex, hash_hex = stored_hash.split(':')
            salt = bytes.fromhex(salt_hex)
            stored_password_hash = bytes.fromhex(hash_hex)
            
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
            return password_hash == stored_password_hash
            
        except (ValueError, TypeError):
            return False
    
    def _generate_user_id(self) -> str:
        """Generate unique user ID."""
        return secrets.token_urlsafe(16)
    
    async def _ensure_admin_user(self) -> None:
        """Ensure default admin user exists."""
        # Check if any admin user exists
        has_admin = False
        for user_info in self.users.values():
            user_roles = await self.rbac.get_user_roles(user_info['user_id'])
            if any(role.role_name in ['super_admin', 'admin'] for role in user_roles):
                has_admin = True
                break
        
        if not has_admin:
            # Create default admin user
            from ..config import BASIC_AUTH_USER, BASIC_AUTH_PASS
            if BASIC_AUTH_USER and BASIC_AUTH_PASS:
                try:
                    user_id = await self.create_user(
                        username=BASIC_AUTH_USER,
                        password=BASIC_AUTH_PASS,
                        roles=['admin'],
                        created_by='system'
                    )
                    self.logger.info(f"Created default admin user: {BASIC_AUTH_USER}")
                except Exception as e:
                    self.logger.error(f"Failed to create default admin user: {e}")
    
    async def _load_users(self) -> None:
        """Load users from storage."""
        # This would load from database or secure file
        # Placeholder implementation
        pass
    
    async def _save_users(self) -> None:
        """Save users to storage."""
        # This would save to database or secure file
        # Placeholder implementation
        pass