"""
Tests for Safe Mode Controller

Verifies security controls including:
- Two-person approval enforcement
- Scope authorization
- Kill switch functionality
"""

import pytest
from datetime import datetime, timezone

from src.safe_mode import (
    SecurityViolation,
    ApprovalStatus,
)


class TestSafeMode:
    """Tests for SafeModeController."""
    
    def test_target_in_scope(self, safe_mode_controller):
        """Test scope checking."""
        # In scope
        scope = safe_mode_controller.target_in_scope("10.0.0.1")
        assert scope is not None
        assert scope.id == "test-scope"
        
        # Out of scope
        scope = safe_mode_controller.target_in_scope("192.168.1.1")
        assert scope is None
    
    def test_pre_scan_check_success(self, safe_mode_controller):
        """Test pre-scan check passes for authorized targets."""
        result = safe_mode_controller.pre_scan_check(
            target="10.0.0.1",
            user_id="operator1",
            ticket_id="VULN-001"
        )
        assert result is True
    
    def test_pre_scan_check_out_of_scope(self, safe_mode_controller):
        """Test pre-scan check fails for out-of-scope targets."""
        with pytest.raises(SecurityViolation) as exc:
            safe_mode_controller.pre_scan_check(
                target="192.168.1.1",  # Not authorized
                user_id="operator1",
                ticket_id="VULN-001"
            )
        assert "not in authorized scope" in str(exc.value)
    
    def test_pre_scan_check_invalid_ticket(self, safe_mode_controller):
        """Test pre-scan check fails for invalid ticket format."""
        with pytest.raises(SecurityViolation) as exc:
            safe_mode_controller.pre_scan_check(
                target="10.0.0.1",
                user_id="operator1",
                ticket_id="invalid-format"
            )
        assert "Invalid ticket" in str(exc.value)
    
    def test_pre_scan_check_insufficient_permission(self, safe_mode_controller):
        """Test pre-scan check fails for viewer role."""
        with pytest.raises(SecurityViolation) as exc:
            safe_mode_controller.pre_scan_check(
                target="10.0.0.1",
                user_id="viewer1",  # Viewer cannot scan
                ticket_id="VULN-001"
            )
        assert "lacks scan permission" in str(exc.value)


class TestTwoPersonApproval:
    """Tests for two-person approval enforcement."""
    
    def test_request_approval(self, safe_mode_controller):
        """Test exploit approval request."""
        approval_id = safe_mode_controller.request_exploit_approval(
            target="192.168.99.10",  # Lab fixture
            module="exploit/test",
            operator_id="operator1",
            operator_fingerprint="device-1",
            ticket_id="VULN-002"
        )
        assert approval_id is not None
    
    def test_approve_different_user(self, safe_mode_controller, rbac_manager):
        """Test approval works with different users."""
        # Enable MFA for admin
        admin = rbac_manager.get_user("admin1")
        admin.mfa_verified_at = datetime.now(timezone.utc)
        
        # Request
        approval_id = safe_mode_controller.request_exploit_approval(
            target="192.168.99.10",
            module="exploit/test",
            operator_id="operator1",
            operator_fingerprint="device-1",
            ticket_id="VULN-002"
        )
        
        # Approve with different user
        approval = safe_mode_controller.approve_exploit(
            approval_id=approval_id,
            approver_id="admin1",
            approver_fingerprint="device-2"
        )
        
        assert approval.status == ApprovalStatus.APPROVED
        assert approval.approver_id == "admin1"
    
    def test_approve_same_user_rejected(self, safe_mode_controller):
        """Test approval fails when operator == approver."""
        approval_id = safe_mode_controller.request_exploit_approval(
            target="192.168.99.10",
            module="exploit/test",
            operator_id="operator1",
            operator_fingerprint="device-1",
            ticket_id="VULN-002"
        )
        
        with pytest.raises(SecurityViolation) as exc:
            safe_mode_controller.approve_exploit(
                approval_id=approval_id,
                approver_id="operator1",  # Same as operator
                approver_fingerprint="device-2"
            )
        assert "different users" in str(exc.value)
    
    def test_approve_same_device_rejected(self, safe_mode_controller, rbac_manager):
        """Test approval fails when same device/fingerprint."""
        admin = rbac_manager.get_user("admin1")
        admin.mfa_verified_at = datetime.now(timezone.utc)
        
        approval_id = safe_mode_controller.request_exploit_approval(
            target="192.168.99.10",
            module="exploit/test",
            operator_id="operator1",
            operator_fingerprint="device-1",
            ticket_id="VULN-002"
        )
        
        with pytest.raises(SecurityViolation) as exc:
            safe_mode_controller.approve_exploit(
                approval_id=approval_id,
                approver_id="admin1",
                approver_fingerprint="device-1"  # Same device
            )
        assert "different device" in str(exc.value)


class TestKillSwitch:
    """Tests for kill switch functionality."""
    
    def test_kill_switch_blocks_scans(self, safe_mode_controller):
        """Test kill switch blocks all scans."""
        safe_mode_controller.activate_kill_switch(
            user_id="responder",
            reason="Test incident"
        )
        
        assert safe_mode_controller.is_kill_switch_active() is True
        
        with pytest.raises(SecurityViolation) as exc:
            safe_mode_controller.pre_scan_check(
                target="10.0.0.1",
                user_id="operator1",
                ticket_id="VULN-TEST"
            )
        assert "kill switch" in str(exc.value).lower()
    
    def test_kill_switch_deactivation_requires_admin(
        self, safe_mode_controller
    ):
        """Test only admin can deactivate kill switch."""
        safe_mode_controller.activate_kill_switch("responder", "Test")
        
        with pytest.raises(SecurityViolation):
            safe_mode_controller.deactivate_kill_switch("operator1")
