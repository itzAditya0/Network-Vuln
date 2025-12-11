"""
Test Configuration and Fixtures

Provides mock msfrpcd, test endpoints, and database fixtures.
"""

import pytest
from datetime import datetime, timezone, timedelta
from ipaddress import IPv4Network
from unittest.mock import MagicMock, AsyncMock

from src.endpoint_manager import Endpoint, EndpointManager
from src.rbac import RBACManager, Role, User
from src.safe_mode import SafeModeController, ScopeAuthorization
from src.logger import AuditLogger
from src.scoring_engine import ScoringEngine
from src.msf_validator import ValidationResult


@pytest.fixture
def mock_audit_logger():
    """Audit logger with test key."""
    return AuditLogger(hmac_key=b"test-key-do-not-use-in-production")


@pytest.fixture
def rbac_manager():
    """RBAC manager with test users."""
    rbac = RBACManager(admin_mfa_required=False)
    rbac.add_user(User(id="operator1", username="operator1", role=Role.OPERATOR))
    rbac.add_user(User(id="admin1", username="admin1", role=Role.ADMIN, mfa_enabled=True))
    rbac.add_user(User(id="viewer1", username="viewer1", role=Role.VIEWER))
    return rbac


@pytest.fixture
def safe_mode_controller(rbac_manager, mock_audit_logger):
    """Safe mode controller with test scopes."""
    scopes = [
        ScopeAuthorization(
            id="test-scope",
            cidr=IPv4Network("10.0.0.0/24"),
            ticket_id="VULN-TEST",
            approved_by=["admin1"],
            valid_from=datetime.now(timezone.utc) - timedelta(hours=1),
            valid_until=datetime.now(timezone.utc) + timedelta(hours=24),
        ),
        ScopeAuthorization(
            id="lab-scope",
            cidr=IPv4Network("192.168.99.0/24"),
            ticket_id="VULN-LAB",
            approved_by=["admin1"],
            valid_from=datetime.now(timezone.utc) - timedelta(hours=1),
            valid_until=datetime.now(timezone.utc) + timedelta(hours=24),
            allow_exploit=True,
        ),
    ]
    return SafeModeController(
        rbac=rbac_manager,
        audit=mock_audit_logger,
        authorized_scopes=scopes,
    )


@pytest.fixture
def test_endpoints():
    """Sample endpoints for testing."""
    return [
        Endpoint(ip="10.0.0.1", hostname="server1", asset_criticality=2.0),
        Endpoint(ip="10.0.0.2", hostname="server2", asset_criticality=1.0),
        Endpoint(ip="192.168.99.10", hostname="lab-vm", environment="lab"),
    ]


@pytest.fixture
def mock_msf_validator():
    """Mock Metasploit validator."""
    from src.msf_validator import MetasploitValidator, ValidationReport
    
    validator = MagicMock(spec=MetasploitValidator)
    validator.validate.return_value = ValidationReport(
        target="10.0.0.1",
        module="exploit/test",
        result=ValidationResult.VULNERABLE,
        output="The target is vulnerable",
        duration_seconds=5.0,
        check_mode=True,
    )
    return validator


@pytest.fixture
def scoring_engine():
    """Scoring engine with test CVSS scores."""
    return ScoringEngine(
        cvss_scores={
            "CVE-2021-44228": 10.0,
            "CVE-2017-0143": 8.1,
            "CVE-TEST-001": 7.5,
        }
    )


@pytest.fixture
def sample_vulnerabilities():
    """Sample vulnerabilities for scoring tests."""
    return [
        {
            "target": "10.0.0.1",
            "port": 445,
            "service": "smb",
            "cves": ["CVE-2017-0143"],
            "validation_result": "vulnerable",
        },
        {
            "target": "10.0.0.2",
            "port": 80,
            "service": "http",
            "cves": ["CVE-2021-44228"],
            "validation_result": "not_vulnerable",
        },
        {
            "target": "10.0.0.3",
            "port": 22,
            "service": "ssh",
            "cves": [],
            "validation_result": None,
        },
    ]
