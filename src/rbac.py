"""
Role-Based Access Control (RBAC)

Implements:
- Role hierarchy: viewer < operator < admin
- Permission checks with audit logging
- MFA requirement for admin actions
- Role change logging
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any

from src.logger import get_logger

logger = get_logger(__name__)


class Permission(Enum):
    """Granular permissions for security operations."""
    VIEW_SCANS = auto()
    VIEW_REPORTS = auto()
    RUN_SCAN = auto()
    RUN_VALIDATION = auto()  # Check mode only
    EXPORT_DATA = auto()
    APPROVE_EXPLOIT = auto()  # Requires admin
    ADMIN_ACTIONS = auto()  # Kill switch, role changes


class Role(Enum):
    """User roles with hierarchical permissions."""
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


# Role → Permission mapping
ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.VIEWER: {
        Permission.VIEW_SCANS,
        Permission.VIEW_REPORTS,
    },
    Role.OPERATOR: {
        Permission.VIEW_SCANS,
        Permission.VIEW_REPORTS,
        Permission.RUN_SCAN,
        Permission.RUN_VALIDATION,
        Permission.EXPORT_DATA,
    },
    Role.ADMIN: {
        Permission.VIEW_SCANS,
        Permission.VIEW_REPORTS,
        Permission.RUN_SCAN,
        Permission.RUN_VALIDATION,
        Permission.EXPORT_DATA,
        Permission.APPROVE_EXPLOIT,
        Permission.ADMIN_ACTIONS,
    },
}


@dataclass
class User:
    """User with role and MFA status."""
    id: str
    username: str
    role: Role
    mfa_enabled: bool = False
    mfa_verified_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def has_valid_mfa(self, max_age_seconds: int = 3600) -> bool:
        """Check if MFA was verified within the time window."""
        if not self.mfa_enabled or not self.mfa_verified_at:
            return False
        age = (datetime.now(timezone.utc) - self.mfa_verified_at).total_seconds()
        return age <= max_age_seconds


class RBACManager:
    """
    Manages role-based access control.
    
    All permission checks are logged for audit purposes.
    """
    
    def __init__(self, admin_mfa_required: bool = True):
        self._users: dict[str, User] = {}
        self._admin_mfa_required = admin_mfa_required
    
    def add_user(self, user: User) -> None:
        """Add user to RBAC system."""
        self._users[user.id] = user
        logger.info("user_added", user_id=user.id, role=user.role.value)
    
    def get_user(self, user_id: str) -> User | None:
        """Get user by ID."""
        return self._users.get(user_id)
    
    def set_role(self, user_id: str, new_role: Role, changed_by: str) -> None:
        """
        Change user's role. Requires admin permission from changed_by.
        
        Role changes are always logged.
        """
        if not self.has_permission(changed_by, Permission.ADMIN_ACTIONS):
            logger.warning(
                "role_change_denied",
                user_id=user_id,
                changed_by=changed_by,
                reason="insufficient_permission"
            )
            raise PermissionError(f"User {changed_by} cannot change roles")
        
        user = self._users.get(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")
        
        old_role = user.role
        user.role = new_role
        
        logger.warning(
            "role_changed",
            user_id=user_id,
            old_role=old_role.value,
            new_role=new_role.value,
            changed_by=changed_by
        )
    
    def has_permission(self, user_id: str, permission: Permission) -> bool:
        """
        Check if user has specific permission.
        
        For admin actions, MFA verification is required if configured.
        """
        user = self._users.get(user_id)
        if not user:
            logger.debug("permission_check_failed", user_id=user_id, reason="user_not_found")
            return False
        
        # Check if permission is in user's role
        if permission not in ROLE_PERMISSIONS.get(user.role, set()):
            logger.debug(
                "permission_check_failed",
                user_id=user_id,
                permission=permission.name,
                role=user.role.value
            )
            return False
        
        # Admin actions require MFA
        if permission in (Permission.APPROVE_EXPLOIT, Permission.ADMIN_ACTIONS):
            if self._admin_mfa_required and not user.has_valid_mfa():
                logger.warning(
                    "permission_check_failed",
                    user_id=user_id,
                    permission=permission.name,
                    reason="mfa_required"
                )
                return False
        
        return True
    
    def check_permission(
        self,
        user_id: str,
        permission: Permission,
        resource: str | None = None
    ) -> None:
        """
        Check permission and raise if denied.
        
        Use this for explicit permission gates in code.
        """
        if not self.has_permission(user_id, permission):
            logger.warning(
                "permission_denied",
                user_id=user_id,
                permission=permission.name,
                resource=resource
            )
            raise PermissionError(
                f"User {user_id} lacks permission {permission.name}"
                + (f" for {resource}" if resource else "")
            )
    
    def verify_mfa(self, user_id: str, otp_code: str) -> bool:
        """
        Verify MFA code for user.
        
        Updates mfa_verified_at on success.
        """
        user = self._users.get(user_id)
        if not user or not user.mfa_enabled:
            return False
        
        # TODO: Integrate with actual OTP verification (pyotp)
        # For now, placeholder that would call TOTP verify
        verified = self._verify_totp(user_id, otp_code)
        
        if verified:
            user.mfa_verified_at = datetime.now(timezone.utc)
            logger.info("mfa_verified", user_id=user_id)
        else:
            logger.warning("mfa_verification_failed", user_id=user_id)
        
        return verified
    
    def _verify_totp(self, user_id: str, otp_code: str) -> bool:
        """Verify TOTP code. Override in production."""
        # Placeholder - integrate with pyotp and user's secret from Vault
        return len(otp_code) == 6 and otp_code.isdigit()
    
    def get_permissions(self, user_id: str) -> set[Permission]:
        """Get all permissions for user."""
        user = self._users.get(user_id)
        if not user:
            return set()
        return ROLE_PERMISSIONS.get(user.role, set())
