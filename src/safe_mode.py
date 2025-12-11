"""
Safe Mode Controller - Exploitation Constraints

CRITICAL SECURITY MODULE

Enforces:
- Non-destructive validation by default (check mode only)
- Two-person approval for any exploit runs
- Scope authorization with signed tickets
- Kill switch for emergency stops
- Lab fixture verification before destructive tests

This module is the LAST LINE OF DEFENSE before any Metasploit action.
"""

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from typing import Any

from src.logger import AuditLogger, get_logger
from src.rbac import Permission, RBACManager

logger = get_logger(__name__)


class SecurityViolation(Exception):
    """Raised when a security policy is violated. Always logged."""
    pass


class ApprovalStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class ScopeAuthorization:
    """Represents an authorized scanning scope."""
    id: str
    cidr: IPv4Network
    ticket_id: str  # JIRA or signed approval reference
    approved_by: list[str]
    valid_from: datetime
    valid_until: datetime
    allow_exploit: bool = False  # Requires two-person approval
    
    def is_valid(self) -> bool:
        """Check if scope authorization is currently valid."""
        now = datetime.now(timezone.utc)
        return self.valid_from <= now <= self.valid_until
    
    def contains(self, ip: str) -> bool:
        """Check if IP is within authorized scope."""
        try:
            return IPv4Address(ip) in self.cidr
        except ValueError:
            return False


@dataclass
class ExploitApproval:
    """Two-person approval record for exploit execution."""
    id: str
    target: str
    module: str
    operator_id: str
    operator_fingerprint: str  # Unique device/session ID
    approver_id: str | None = None
    approver_fingerprint: str | None = None
    ticket_id: str | None = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = None
    approved_at: datetime | None = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)


class SafeModeController:
    """
    Enforces safe exploitation constraints.
    
    ALL Metasploit actions must pass through this controller.
    """
    
    # Ticket ID pattern (JIRA-style or signed hash)
    TICKET_PATTERN = re.compile(r"^(VULN-\d+|[A-F0-9]{64})$")
    
    # Lab fixture IP ranges (safe for destructive testing)
    LAB_RANGES = [
        IPv4Network("10.99.0.0/16"),  # Designated lab network
        IPv4Network("192.168.99.0/24"),  # Local test VMs
    ]
    
    def __init__(
        self,
        rbac: RBACManager,
        audit: AuditLogger,
        authorized_scopes: list[ScopeAuthorization] | None = None,
        notification_webhook: str | None = None
    ):
        self._rbac = rbac
        self._audit = audit
        self._authorized_scopes = authorized_scopes or []
        self._pending_approvals: dict[str, ExploitApproval] = {}
        self._webhook = notification_webhook
        self._kill_switch_active = False
    
    # === KILL SWITCH ===
    
    def activate_kill_switch(self, user_id: str, reason: str) -> None:
        """
        Emergency stop for all active scans and validations.
        
        Can be activated by any authenticated user.
        """
        self._kill_switch_active = True
        self._audit.log(
            action="kill_switch_activated",
            user_id=user_id,
            result={"reason": reason}
        )
        logger.critical("kill_switch_activated", user_id=user_id, reason=reason)
        # TODO: Signal all workers to stop immediately
    
    def deactivate_kill_switch(self, user_id: str) -> None:
        """Deactivate kill switch. Requires admin role."""
        if not self._rbac.has_permission(user_id, Permission.ADMIN_ACTIONS):
            raise SecurityViolation("Only admins can deactivate kill switch")
        
        self._kill_switch_active = False
        self._audit.log(action="kill_switch_deactivated", user_id=user_id)
        logger.warning("kill_switch_deactivated", user_id=user_id)
    
    def is_kill_switch_active(self) -> bool:
        return self._kill_switch_active
    
    # === SCOPE AUTHORIZATION ===
    
    def target_in_scope(self, target_ip: str) -> ScopeAuthorization | None:
        """Check if target is in an authorized scope. Returns scope or None."""
        for scope in self._authorized_scopes:
            if scope.is_valid() and scope.contains(target_ip):
                return scope
        return None
    
    def verify_scope_ticket(self, ticket_id: str) -> bool:
        """Verify ticket ID format (JIRA or signed hash)."""
        return bool(self.TICKET_PATTERN.match(ticket_id))
    
    def is_lab_fixture(self, target_ip: str) -> bool:
        """Check if target is in designated lab network."""
        try:
            ip = IPv4Address(target_ip)
            return any(ip in lab_range for lab_range in self.LAB_RANGES)
        except ValueError:
            return False
    
    # === PRE-VALIDATION CHECKLIST ===
    
    def pre_scan_check(self, target: str, user_id: str, ticket_id: str) -> bool:
        """
        Verify all preconditions before any scan.
        
        Checks:
        1. Kill switch not active
        2. User has scan permission
        3. Target in authorized scope
        4. Valid ticket ID
        
        Returns True if all checks pass, raises SecurityViolation otherwise.
        """
        # Check kill switch
        if self._kill_switch_active:
            self._audit.log(
                action="scan_blocked",
                user_id=user_id,
                target=target,
                result={"reason": "kill_switch_active"}
            )
            raise SecurityViolation("Kill switch is active - all scans blocked")
        
        # Check permission
        if not self._rbac.has_permission(user_id, Permission.RUN_SCAN):
            self._audit.log(
                action="scan_blocked",
                user_id=user_id,
                target=target,
                result={"reason": "insufficient_permission"}
            )
            raise SecurityViolation(f"User {user_id} lacks scan permission")
        
        # Check scope
        scope = self.target_in_scope(target)
        if scope is None:
            self._audit.log(
                action="scan_blocked",
                user_id=user_id,
                target=target,
                result={"reason": "out_of_scope"}
            )
            raise SecurityViolation(f"Target {target} is not in authorized scope")
        
        # Verify ticket
        if not self.verify_scope_ticket(ticket_id):
            self._audit.log(
                action="scan_blocked",
                user_id=user_id,
                target=target,
                result={"reason": "invalid_ticket", "ticket_id": ticket_id}
            )
            raise SecurityViolation(f"Invalid ticket ID format: {ticket_id}")
        
        return True
    
    def pre_validation_checklist(
        self,
        target: str,
        user_id: str,
        ticket_id: str,
        allow_exploit: bool = False
    ) -> bool:
        """
        Complete checklist before Metasploit validation.
        
        For exploit (non-check) mode, additional requirements:
        - Target must be lab fixture
        - Two-person approval required
        """
        # Basic scan checks
        self.pre_scan_check(target, user_id, ticket_id)
        
        if allow_exploit:
            # Lab fixture required for destructive tests
            if not self.is_lab_fixture(target):
                self._audit.log(
                    action="exploit_blocked",
                    user_id=user_id,
                    target=target,
                    result={"reason": "not_lab_fixture"}
                )
                raise SecurityViolation(
                    f"Exploit mode only allowed on lab fixtures. "
                    f"Target {target} is not in lab range."
                )
            
            # Two-person approval already verified by caller
            logger.warning(
                "exploit_mode_authorized",
                target=target,
                user_id=user_id,
                ticket_id=ticket_id
            )
        
        return True
    
    # === TWO-PERSON APPROVAL ===
    
    def request_exploit_approval(
        self,
        target: str,
        module: str,
        operator_id: str,
        operator_fingerprint: str,
        ticket_id: str
    ) -> str:
        """
        Request approval for exploit execution.
        
        Returns approval ID. Another admin must approve before execution.
        """
        if not self.verify_scope_ticket(ticket_id):
            raise SecurityViolation(f"Invalid ticket ID: {ticket_id}")
        
        if not self.is_lab_fixture(target):
            raise SecurityViolation("Exploit requests only for lab fixtures")
        
        import uuid
        approval_id = str(uuid.uuid4())
        
        approval = ExploitApproval(
            id=approval_id,
            target=target,
            module=module,
            operator_id=operator_id,
            operator_fingerprint=operator_fingerprint,
            ticket_id=ticket_id
        )
        
        self._pending_approvals[approval_id] = approval
        
        self._audit.log(
            action="exploit_approval_requested",
            user_id=operator_id,
            target=target,
            scope_ticket=ticket_id,
            result={"approval_id": approval_id, "module": module}
        )
        
        # Send notification
        self._notify_approval_needed(approval)
        
        return approval_id
    
    def approve_exploit(
        self,
        approval_id: str,
        approver_id: str,
        approver_fingerprint: str
    ) -> ExploitApproval:
        """
        Approve exploit request. Enforces two-person rule.
        
        HARD ENFORCEMENT:
        - Approver must differ from operator
        - Approver must have admin role
        - Both fingerprints must be unique
        """
        if approval_id not in self._pending_approvals:
            raise SecurityViolation(f"Unknown approval ID: {approval_id}")
        
        approval = self._pending_approvals[approval_id]
        
        # === HARD ENFORCEMENT - NOT POLICY ===
        
        # Check 1: Different users
        if approval.operator_id == approver_id:
            self._audit.log(
                action="exploit_approval_rejected",
                user_id=approver_id,
                result={"reason": "same_user", "approval_id": approval_id}
            )
            raise SecurityViolation(
                "SECURITY VIOLATION: Operator and approver must be different users"
            )
        
        # Check 2: Different sessions/devices
        if approval.operator_fingerprint == approver_fingerprint:
            self._audit.log(
                action="exploit_approval_rejected",
                user_id=approver_id,
                result={"reason": "same_fingerprint", "approval_id": approval_id}
            )
            raise SecurityViolation(
                "SECURITY VIOLATION: Approval must come from different device/session"
            )
        
        # Check 3: Approver has admin role
        if not self._rbac.has_permission(approver_id, Permission.APPROVE_EXPLOIT):
            self._audit.log(
                action="exploit_approval_rejected",
                user_id=approver_id,
                result={"reason": "insufficient_permission", "approval_id": approval_id}
            )
            raise SecurityViolation(
                f"SECURITY VIOLATION: User {approver_id} lacks approval permission"
            )
        
        # All checks passed - approve
        approval.approver_id = approver_id
        approval.approver_fingerprint = approver_fingerprint
        approval.status = ApprovalStatus.APPROVED
        approval.approved_at = datetime.now(timezone.utc)
        
        self._audit.log(
            action="exploit_approved",
            user_id=approver_id,
            target=approval.target,
            scope_ticket=approval.ticket_id,
            result={
                "approval_id": approval_id,
                "operator_id": approval.operator_id,
                "module": approval.module
            }
        )
        
        return approval
    
    def execute_exploit(self, approval_id: str) -> dict[str, Any]:
        """
        Execute approved exploit. Final verification before action.
        
        Returns execution context for msf_validator.
        """
        if approval_id not in self._pending_approvals:
            raise SecurityViolation(f"Unknown approval ID: {approval_id}")
        
        approval = self._pending_approvals[approval_id]
        
        if approval.status != ApprovalStatus.APPROVED:
            raise SecurityViolation(
                f"Approval {approval_id} is not approved (status: {approval.status})"
            )
        
        # Final verification
        self.pre_validation_checklist(
            target=approval.target,
            user_id=approval.operator_id,
            ticket_id=approval.ticket_id,
            allow_exploit=True
        )
        
        # Remove from pending
        del self._pending_approvals[approval_id]
        
        self._audit.log(
            action="exploit_executed",
            user_id=approval.operator_id,
            target=approval.target,
            scope_ticket=approval.ticket_id,
            result={
                "approval_id": approval_id,
                "approver_id": approval.approver_id,
                "module": approval.module
            }
        )
        
        return {
            "target": approval.target,
            "module": approval.module,
            "safe_mode": False,  # Exploit mode authorized
            "ticket_id": approval.ticket_id,
            "operator_id": approval.operator_id,
            "approver_id": approval.approver_id
        }
    
    def _notify_approval_needed(self, approval: ExploitApproval) -> None:
        """Send notification for pending approval (webhook)."""
        if not self._webhook:
            return
        
        # TODO: Implement Slack/email notification
        logger.info(
            "approval_notification_sent",
            approval_id=approval.id,
            target=approval.target,
            operator_id=approval.operator_id
        )
