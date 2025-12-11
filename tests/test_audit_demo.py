"""
Audit Chain Tests

Unit tests for the HMAC audit chain functionality:
- Chain creation with multiple records
- Verification passes for valid chains
- Verification fails for tampered records
- Verification fails for broken prev_hmac links

Run: pytest tests/test_audit_demo.py -v
"""

import copy
import pytest

from src.logger import AuditLogger


class TestAuditChainCreation:
    """Tests for audit chain creation."""
    
    @pytest.fixture
    def audit_logger(self):
        """Create audit logger with test key."""
        return AuditLogger(hmac_key=b"test-audit-key")
    
    def test_single_record_has_hmac(self, audit_logger):
        """Single record contains valid HMAC."""
        record = audit_logger.log(
            action="test_action",
            user_id="operator1",
        )
        
        assert "hmac" in record
        assert len(record["hmac"]) == 64  # SHA256 hex
        assert record["prev_hmac"] is None  # First record
    
    def test_chained_records_link_correctly(self, audit_logger):
        """Multiple records form a proper chain."""
        record1 = audit_logger.log(action="action1", user_id="user1")
        record2 = audit_logger.log(action="action2", user_id="user2")
        record3 = audit_logger.log(action="action3", user_id="user3")
        
        # Chain links
        assert record1["prev_hmac"] is None
        assert record2["prev_hmac"] == record1["hmac"]
        assert record3["prev_hmac"] == record2["hmac"]
        
        # All HMACs are different
        assert record1["hmac"] != record2["hmac"]
        assert record2["hmac"] != record3["hmac"]
    
    def test_hmac_deterministic(self):
        """Same payload + prev_hmac produces same HMAC."""
        key = b"deterministic-key"
        logger1 = AuditLogger(hmac_key=key)
        logger2 = AuditLogger(hmac_key=key)
        
        # Create identical payloads (mock timestamp)
        payload = {
            "timestamp": "2024-01-01T00:00:00+00:00",
            "action": "test",
            "user_id": "user1",
            "target": None,
            "scope_ticket": None,
            "result": {},
            "trace_id": "abc123",
        }
        
        hmac1 = logger1.compute_hmac(payload)
        hmac2 = logger2.compute_hmac(payload)
        
        assert hmac1 == hmac2


class TestAuditChainVerification:
    """Tests for audit chain verification."""
    
    @pytest.fixture
    def sample_chain(self):
        """Create a sample valid chain for testing."""
        key = b"verification-test-key"
        logger = AuditLogger(hmac_key=key)
        
        records = []
        for i in range(5):
            record = logger.log(
                action=f"action_{i}",
                user_id=f"user_{i}",
                target=f"10.0.0.{i}",
            )
            records.append(record)
        
        return records, key
    
    def test_valid_chain_verifies(self, sample_chain):
        """Valid chain passes verification."""
        records, key = sample_chain
        
        assert AuditLogger.verify_chain(records, key) is True
    
    def test_empty_chain_verifies(self):
        """Empty chain is considered valid."""
        assert AuditLogger.verify_chain([], b"any-key") is True
    
    def test_single_record_chain_verifies(self):
        """Single record chain verifies."""
        key = b"single-record-key"
        logger = AuditLogger(hmac_key=key)
        
        record = logger.log(action="test", user_id="user1")
        
        assert AuditLogger.verify_chain([record], key) is True


class TestAuditChainTamperDetection:
    """Tests for tamper detection in audit chains."""
    
    @pytest.fixture
    def sample_chain(self):
        """Create a sample valid chain for testing."""
        key = b"tamper-test-key"
        logger = AuditLogger(hmac_key=key)
        
        records = []
        for i in range(5):
            record = logger.log(
                action=f"action_{i}",
                user_id=f"user_{i}",
                target=f"10.0.0.{i}",
            )
            records.append(record)
        
        return records, key
    
    def test_tampered_action_detected(self, sample_chain):
        """Modifying action field is detected."""
        records, key = sample_chain
        tampered = copy.deepcopy(records)
        
        tampered[2]["action"] = "malicious_action"
        
        assert AuditLogger.verify_chain(tampered, key) is False
    
    def test_tampered_user_id_detected(self, sample_chain):
        """Modifying user_id field is detected."""
        records, key = sample_chain
        tampered = copy.deepcopy(records)
        
        tampered[1]["user_id"] = "attacker"
        
        assert AuditLogger.verify_chain(tampered, key) is False
    
    def test_tampered_target_detected(self, sample_chain):
        """Modifying target field is detected."""
        records, key = sample_chain
        tampered = copy.deepcopy(records)
        
        tampered[3]["target"] = "192.168.1.1"  # Different target
        
        assert AuditLogger.verify_chain(tampered, key) is False
    
    def test_tampered_timestamp_detected(self, sample_chain):
        """Modifying timestamp field is detected."""
        records, key = sample_chain
        tampered = copy.deepcopy(records)
        
        tampered[0]["timestamp"] = "1999-01-01T00:00:00+00:00"
        
        assert AuditLogger.verify_chain(tampered, key) is False
    
    def test_broken_chain_link_detected(self, sample_chain):
        """Breaking prev_hmac link is detected."""
        records, key = sample_chain
        tampered = copy.deepcopy(records)
        
        tampered[3]["prev_hmac"] = "0" * 64  # Wrong prev_hmac
        
        assert AuditLogger.verify_chain(tampered, key) is False
    
    def test_forged_hmac_detected(self, sample_chain):
        """Forged HMAC is detected."""
        records, key = sample_chain
        tampered = copy.deepcopy(records)
        
        # Modify record and try to forge HMAC
        tampered[2]["action"] = "forged_action"
        tampered[2]["hmac"] = "a" * 64  # Fake HMAC
        
        assert AuditLogger.verify_chain(tampered, key) is False
    
    def test_wrong_key_fails_verification(self, sample_chain):
        """Verification fails with wrong key."""
        records, _ = sample_chain
        wrong_key = b"different-key"
        
        assert AuditLogger.verify_chain(records, wrong_key) is False
    
    def test_deleted_record_detected(self, sample_chain):
        """Deleting a record breaks the chain."""
        records, key = sample_chain
        
        # Delete middle record
        incomplete = records[:2] + records[3:]
        
        assert AuditLogger.verify_chain(incomplete, key) is False
    
    def test_reordered_records_detected(self, sample_chain):
        """Reordering records breaks the chain."""
        records, key = sample_chain
        
        # Swap records
        reordered = copy.deepcopy(records)
        reordered[1], reordered[2] = reordered[2], reordered[1]
        
        assert AuditLogger.verify_chain(reordered, key) is False
