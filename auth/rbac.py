"""
Role-Based Access Control (RBAC) System for Threat Hunter Pro.

This module implements a comprehensive RBAC system with hierarchical roles,
granular permissions, and dynamic access control policies.
"""

from __future__ import annotations

import json
import logging
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timezone, timedelta
import hashlib


class PermissionType(Enum):
    """Types of permissions in the system."""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"


class ResourceType(Enum):
    """Types of resources that can be protected."""
    DASHBOARD = "dashboard"
    LOGS = "logs"
    ISSUES = "issues"
    SETTINGS = "settings"
    USERS = "users"
    API = "api"
    SYSTEM = "system"
    REPORTS = "reports"
    EXPORT = "export"


@dataclass
class Permission:
    """Represents a specific permission."""
    resource_type: ResourceType
    permission_type: PermissionType
    resource_id: Optional[str] = None  # For resource-specific permissions
    conditions: Optional[Dict[str, Any]] = None  # Additional conditions
    
    def __str__(self) -> str:
        """String representation of permission."""
        if self.resource_id:
            return f"{self.permission_type.value}:{self.resource_type.value}:{self.resource_id}"
        else:
            return f"{self.permission_type.value}:{self.resource_type.value}"
    
    def matches(self, required_permission: Permission) -> bool:
        """Check if this permission satisfies the required permission."""
        # Resource type must match
        if self.resource_type != required_permission.resource_type:
            return False
        
        # Permission type must be sufficient
        if not self._permission_covers(required_permission.permission_type):
            return False
        
        # Resource ID must match if specified
        if required_permission.resource_id and self.resource_id != required_permission.resource_id:
            return False
        
        # Check conditions if specified
        if required_permission.conditions and self.conditions:
            for key, value in required_permission.conditions.items():
                if key not in self.conditions or self.conditions[key] != value:
                    return False
        
        return True
    
    def _permission_covers(self, required_type: PermissionType) -> bool:
        """Check if this permission type covers the required type."""
        # Admin permission covers everything
        if self.permission_type == PermissionType.ADMIN:
            return True
        
        # Write permission covers read
        if self.permission_type == PermissionType.WRITE and required_type == PermissionType.READ:
            return True
        
        # Exact match
        return self.permission_type == required_type


@dataclass
class Role:
    """Represents a role with associated permissions."""
    name: str
    description: str
    permissions: List[Permission]
    parent_roles: List[str] = None  # Inherits permissions from parent roles
    is_system_role: bool = False
    created_at: datetime = None
    updated_at: datetime = None
    
    def __post_init__(self):
        if self.parent_roles is None:
            self.parent_roles = []
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)
        if self.updated_at is None:
            self.updated_at = datetime.now(timezone.utc)
    
    def has_permission(self, required_permission: Permission, inherited_permissions: List[Permission] = None) -> bool:
        """Check if role has the required permission."""
        all_permissions = self.permissions.copy()
        if inherited_permissions:
            all_permissions.extend(inherited_permissions)
        
        return any(perm.matches(required_permission) for perm in all_permissions)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert role to dictionary."""
        data = asdict(self)
        data['permissions'] = [asdict(p) for p in self.permissions]
        data['created_at'] = self.created_at.isoformat() if self.created_at else None
        data['updated_at'] = self.updated_at.isoformat() if self.updated_at else None
        return data


@dataclass
class UserRole:
    """Represents a user's role assignment."""
    user_id: str
    role_name: str
    assigned_by: str
    assigned_at: datetime
    expires_at: Optional[datetime] = None
    conditions: Optional[Dict[str, Any]] = None
    
    def is_active(self) -> bool:
        """Check if role assignment is currently active."""
        now = datetime.now(timezone.utc)
        return self.expires_at is None or self.expires_at > now
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'user_id': self.user_id,
            'role_name': self.role_name,
            'assigned_by': self.assigned_by,
            'assigned_at': self.assigned_at.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'conditions': self.conditions
        }


class RBACManager:
    """
    Comprehensive Role-Based Access Control Manager.
    
    Features:
    - Hierarchical role inheritance
    - Granular permission management
    - Time-based role assignments
    - Condition-based access control
    - Audit logging integration
    - Dynamic permission evaluation
    """
    
    # System roles that cannot be deleted or modified
    SYSTEM_ROLES = {
        'super_admin': Role(
            name='super_admin',
            description='Full system administrator with all permissions',
            permissions=[
                Permission(ResourceType.SYSTEM, PermissionType.ADMIN),
                Permission(ResourceType.USERS, PermissionType.ADMIN),
                Permission(ResourceType.SETTINGS, PermissionType.ADMIN),
                Permission(ResourceType.DASHBOARD, PermissionType.ADMIN),
                Permission(ResourceType.LOGS, PermissionType.ADMIN),
                Permission(ResourceType.ISSUES, PermissionType.ADMIN),
                Permission(ResourceType.API, PermissionType.ADMIN),
                Permission(ResourceType.REPORTS, PermissionType.ADMIN),
                Permission(ResourceType.EXPORT, PermissionType.ADMIN),
            ],
            is_system_role=True
        ),
        'admin': Role(
            name='admin',
            description='System administrator with most permissions',
            permissions=[
                Permission(ResourceType.DASHBOARD, PermissionType.ADMIN),
                Permission(ResourceType.LOGS, PermissionType.ADMIN),
                Permission(ResourceType.ISSUES, PermissionType.ADMIN),
                Permission(ResourceType.SETTINGS, PermissionType.WRITE),
                Permission(ResourceType.API, PermissionType.EXECUTE),
                Permission(ResourceType.REPORTS, PermissionType.ADMIN),
                Permission(ResourceType.EXPORT, PermissionType.WRITE),
            ],
            is_system_role=True
        ),
        'analyst': Role(
            name='analyst',
            description='Security analyst with analysis and investigation permissions',
            permissions=[
                Permission(ResourceType.DASHBOARD, PermissionType.READ),
                Permission(ResourceType.LOGS, PermissionType.READ),
                Permission(ResourceType.ISSUES, PermissionType.WRITE),
                Permission(ResourceType.API, PermissionType.EXECUTE),
                Permission(ResourceType.REPORTS, PermissionType.WRITE),
                Permission(ResourceType.EXPORT, PermissionType.READ),
            ],
            is_system_role=True
        ),
        'viewer': Role(
            name='viewer',
            description='Read-only access to dashboards and reports',
            permissions=[
                Permission(ResourceType.DASHBOARD, PermissionType.READ),
                Permission(ResourceType.LOGS, PermissionType.READ),
                Permission(ResourceType.ISSUES, PermissionType.READ),
                Permission(ResourceType.REPORTS, PermissionType.READ),
            ],
            is_system_role=True
        ),
        'service': Role(
            name='service',
            description='Service account for automated systems',
            permissions=[
                Permission(ResourceType.API, PermissionType.EXECUTE),
                Permission(ResourceType.LOGS, PermissionType.READ),
                Permission(ResourceType.ISSUES, PermissionType.READ),
            ],
            is_system_role=True
        )
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the RBAC manager."""
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Role storage
        self.roles: Dict[str, Role] = self.SYSTEM_ROLES.copy()
        self.user_roles: Dict[str, List[UserRole]] = {}
        
        # Permission cache
        self.permission_cache: Dict[str, Dict[str, bool]] = {}
        self.cache_ttl = timedelta(minutes=self.config.get('cache_ttl_minutes', 15))
        self.cache_timestamps: Dict[str, datetime] = {}
        
        # Access control policies
        self.access_policies = self._load_access_policies()
        
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the RBAC manager."""
        if self._initialized:
            return
        
        try:
            # Load custom roles and user assignments
            await self._load_roles()
            await self._load_user_roles()
            
            self._initialized = True
            self.logger.info("RBAC Manager initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize RBAC manager: {e}")
            raise
    
    async def check_permission(
        self,
        user_id: str,
        resource_type: ResourceType,
        permission_type: PermissionType,
        resource_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Check if user has the required permission.
        
        Args:
            user_id: User identifier
            resource_type: Type of resource being accessed
            permission_type: Type of permission required
            resource_id: Specific resource identifier (optional)
            context: Additional context for permission evaluation
            
        Returns:
            True if user has permission, False otherwise
        """
        if not self._initialized:
            await self.initialize()
        
        # Check cache first
        cache_key = self._get_cache_key(user_id, resource_type, permission_type, resource_id)
        if self._is_cache_valid(cache_key):
            return self.permission_cache[cache_key]['result']
        
        try:
            # Get user's roles
            user_roles = await self._get_active_user_roles(user_id)
            if not user_roles:
                result = False
            else:
                # Create required permission
                required_permission = Permission(
                    resource_type=resource_type,
                    permission_type=permission_type,
                    resource_id=resource_id,
                    conditions=context.get('conditions') if context else None
                )
                
                # Check each role
                result = await self._evaluate_permission(user_roles, required_permission, context)
            
            # Cache result
            self.permission_cache[cache_key] = {
                'result': result,
                'timestamp': datetime.now(timezone.utc)
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Permission check failed for user {user_id}: {e}")
            return False  # Fail secure
    
    async def assign_role(
        self,
        user_id: str,
        role_name: str,
        assigned_by: str,
        expires_at: Optional[datetime] = None,
        conditions: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Assign a role to a user."""
        if not self._initialized:
            await self.initialize()
        
        try:
            # Validate role exists
            if role_name not in self.roles:
                self.logger.warning(f"Attempted to assign non-existent role: {role_name}")
                return False
            
            # Create role assignment
            role_assignment = UserRole(
                user_id=user_id,
                role_name=role_name,
                assigned_by=assigned_by,
                assigned_at=datetime.now(timezone.utc),
                expires_at=expires_at,
                conditions=conditions
            )
            
            # Add to user roles
            if user_id not in self.user_roles:
                self.user_roles[user_id] = []
            
            self.user_roles[user_id].append(role_assignment)
            
            # Clear user's permission cache
            self._clear_user_cache(user_id)
            
            # Save to storage
            await self._save_user_roles()
            
            self.logger.info(f"Role '{role_name}' assigned to user '{user_id}' by '{assigned_by}'")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to assign role: {e}")
            return False
    
    async def revoke_role(self, user_id: str, role_name: str, revoked_by: str) -> bool:
        """Revoke a role from a user."""
        if not self._initialized:
            await self.initialize()
        
        try:
            if user_id not in self.user_roles:
                return False
            
            # Remove role assignments
            original_count = len(self.user_roles[user_id])
            self.user_roles[user_id] = [
                role for role in self.user_roles[user_id]
                if role.role_name != role_name
            ]
            
            if len(self.user_roles[user_id]) < original_count:
                # Clear user's permission cache
                self._clear_user_cache(user_id)
                
                # Save to storage
                await self._save_user_roles()
                
                self.logger.info(f"Role '{role_name}' revoked from user '{user_id}' by '{revoked_by}'")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to revoke role: {e}")
            return False
    
    async def create_role(self, role: Role, created_by: str) -> bool:
        """Create a new custom role."""
        if not self._initialized:
            await self.initialize()
        
        try:
            # Prevent overwriting system roles
            if role.name in self.SYSTEM_ROLES:
                self.logger.warning(f"Attempted to create system role: {role.name}")
                return False
            
            # Validate role
            if not self._validate_role(role):
                return False
            
            # Add to roles
            self.roles[role.name] = role
            
            # Save to storage
            await self._save_roles()
            
            self.logger.info(f"Role '{role.name}' created by '{created_by}'")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create role: {e}")
            return False
    
    async def delete_role(self, role_name: str, deleted_by: str) -> bool:
        """Delete a custom role."""
        if not self._initialized:
            await self.initialize()
        
        try:
            # Prevent deleting system roles
            if role_name in self.SYSTEM_ROLES:
                self.logger.warning(f"Attempted to delete system role: {role_name}")
                return False
            
            if role_name not in self.roles:
                return False
            
            # Remove role assignments from all users
            for user_id in list(self.user_roles.keys()):
                await self.revoke_role(user_id, role_name, deleted_by)
            
            # Remove role
            del self.roles[role_name]
            
            # Save to storage
            await self._save_roles()
            
            self.logger.info(f"Role '{role_name}' deleted by '{deleted_by}'")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to delete role: {e}")
            return False
    
    async def get_user_roles(self, user_id: str) -> List[UserRole]:
        """Get all roles assigned to a user."""
        if not self._initialized:
            await self.initialize()
        
        return self.user_roles.get(user_id, [])
    
    async def get_user_permissions(self, user_id: str) -> List[Permission]:
        """Get all effective permissions for a user."""
        if not self._initialized:
            await self.initialize()
        
        user_roles = await self._get_active_user_roles(user_id)
        permissions = []
        
        for role_assignment in user_roles:
            role = self.roles.get(role_assignment.role_name)
            if role:
                permissions.extend(role.permissions)
                # Add inherited permissions
                inherited = await self._get_inherited_permissions(role)
                permissions.extend(inherited)
        
        # Remove duplicates
        unique_permissions = []
        seen = set()
        for perm in permissions:
            perm_str = str(perm)
            if perm_str not in seen:
                unique_permissions.append(perm)
                seen.add(perm_str)
        
        return unique_permissions
    
    async def _get_active_user_roles(self, user_id: str) -> List[UserRole]:
        """Get active role assignments for a user."""
        all_roles = self.user_roles.get(user_id, [])
        return [role for role in all_roles if role.is_active()]
    
    async def _evaluate_permission(
        self,
        user_roles: List[UserRole],
        required_permission: Permission,
        context: Optional[Dict[str, Any]]
    ) -> bool:
        """Evaluate if user roles provide the required permission."""
        for role_assignment in user_roles:
            role = self.roles.get(role_assignment.role_name)
            if not role:
                continue
            
            # Get all permissions including inherited
            all_permissions = role.permissions.copy()
            inherited = await self._get_inherited_permissions(role)
            all_permissions.extend(inherited)
            
            # Check if role has permission
            if role.has_permission(required_permission, inherited):
                # Apply additional access policies
                if await self._apply_access_policies(role_assignment, required_permission, context):
                    return True
        
        return False
    
    async def _get_inherited_permissions(self, role: Role) -> List[Permission]:
        """Get permissions inherited from parent roles."""
        inherited = []
        
        for parent_role_name in role.parent_roles:
            parent_role = self.roles.get(parent_role_name)
            if parent_role:
                inherited.extend(parent_role.permissions)
                # Recursively get inherited permissions
                parent_inherited = await self._get_inherited_permissions(parent_role)
                inherited.extend(parent_inherited)
        
        return inherited
    
    async def _apply_access_policies(
        self,
        role_assignment: UserRole,
        required_permission: Permission,
        context: Optional[Dict[str, Any]]
    ) -> bool:
        """Apply additional access control policies."""
        # Time-based access control
        if role_assignment.conditions:
            time_restrictions = role_assignment.conditions.get('time_restrictions')
            if time_restrictions and not self._check_time_restrictions(time_restrictions):
                return False
            
            # IP-based access control
            ip_restrictions = role_assignment.conditions.get('ip_restrictions')
            if ip_restrictions and context:
                source_ip = context.get('source_ip')
                if source_ip and not self._check_ip_restrictions(source_ip, ip_restrictions):
                    return False
        
        return True
    
    def _check_time_restrictions(self, time_restrictions: Dict[str, Any]) -> bool:
        """Check if current time falls within allowed time restrictions."""
        # Implementation would check business hours, days of week, etc.
        return True  # Placeholder
    
    def _check_ip_restrictions(self, source_ip: str, ip_restrictions: Dict[str, Any]) -> bool:
        """Check if source IP is allowed."""
        # Implementation would check IP allowlists/blocklists
        return True  # Placeholder
    
    def _validate_role(self, role: Role) -> bool:
        """Validate role configuration."""
        if not role.name or not role.description:
            return False
        
        # Validate permissions
        for permission in role.permissions:
            if not isinstance(permission, Permission):
                return False
        
        return True
    
    def _get_cache_key(
        self,
        user_id: str,
        resource_type: ResourceType,
        permission_type: PermissionType,
        resource_id: Optional[str]
    ) -> str:
        """Generate cache key for permission check."""
        key_data = f"{user_id}:{resource_type.value}:{permission_type.value}:{resource_id or 'none'}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached permission result is still valid."""
        if cache_key not in self.permission_cache:
            return False
        
        cached_time = self.permission_cache[cache_key]['timestamp']
        return datetime.now(timezone.utc) - cached_time < self.cache_ttl
    
    def _clear_user_cache(self, user_id: str) -> None:
        """Clear permission cache for a specific user."""
        keys_to_remove = []
        for cache_key in self.permission_cache:
            if cache_key.startswith(hashlib.md5(user_id.encode()).hexdigest()[:8]):
                keys_to_remove.append(cache_key)
        
        for key in keys_to_remove:
            del self.permission_cache[key]
    
    def _load_access_policies(self) -> Dict[str, Any]:
        """Load access control policies from configuration."""
        return self.config.get('access_policies', {})
    
    async def _load_roles(self) -> None:
        """Load custom roles from storage."""
        # This would load from database or file
        # Placeholder implementation
        pass
    
    async def _save_roles(self) -> None:
        """Save custom roles to storage."""
        # This would save to database or file
        # Placeholder implementation
        pass
    
    async def _load_user_roles(self) -> None:
        """Load user role assignments from storage."""
        # This would load from database or file
        # Placeholder implementation
        pass
    
    async def _save_user_roles(self) -> None:
        """Save user role assignments to storage."""
        # This would save to database or file
        # Placeholder implementation
        pass