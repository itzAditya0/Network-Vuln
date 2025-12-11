#!/usr/bin/env python3
"""
Audit Chain Verification Script

Verifies the integrity of the HMAC audit chain.
"""

import sys
from src.logger import AuditLogger
from src.secrets import get_secrets_manager
from database.db_utils import get_database


def verify_audit_chain() -> bool:
    """Verify all audit records using HMAC chain."""
    db = get_database()
    
    # Get all audit records
    records = db.execute(
        "SELECT * FROM audit_log ORDER BY id"
    )
    
    if not records:
        print("No audit records found.")
        return True
    
    # Get HMAC key from Vault
    try:
        secrets = get_secrets_manager()
        hmac_key = secrets.get_hmac_key()
    except Exception as e:
        print(f"Error getting HMAC key: {e}")
        return False
    
    # Convert to dicts
    record_dicts = []
    for r in records:
        record_dicts.append({
            "id": r[0],
            "timestamp": r[1].isoformat() if r[1] else None,
            "user_id": r[2],
            "action": r[3],
            "target": r[4],
            "scope_ticket": r[5],
            "trace_id": r[6],
            "result": r[7],
            "prev_hmac": r[8],
            "hmac": r[9],
        })
    
    # Verify chain
    valid = AuditLogger.verify_chain(record_dicts, hmac_key)
    
    if valid:
        print(f"✓ Audit chain verified: {len(record_dicts)} records")
        return True
    else:
        print("✗ Audit chain verification FAILED!")
        
        # Use DB function for detailed check
        results = db.verify_audit_chain()
        for r in results:
            if not r["valid"]:
                print(f"  Record {r['id']}: {r['error']}")
        
        return False


if __name__ == "__main__":
    success = verify_audit_chain()
    sys.exit(0 if success else 1)
