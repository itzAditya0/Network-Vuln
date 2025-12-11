#!/usr/bin/env python3
"""
Audit Chain Verification Demo

Interactive demonstration of the HMAC audit chain:
1. Creates sample audit records with chained HMACs
2. Verifies chain integrity
3. Demonstrates tamper detection

Run: python ops/demo_audit_chain.py
"""

import sys
from pathlib import Path
from typing import Any

# Add project root to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.logger import AuditLogger  # noqa: E402


# ANSI colors for terminal output
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_header(text: str) -> None:
    """Print a section header."""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{text}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.RESET}\n")


def print_record(record: dict[str, Any], index: int) -> None:
    """Print a formatted audit record."""
    print(f"{Colors.YELLOW}Record #{index}:{Colors.RESET}")
    print(f"  Action:    {record['action']}")
    print(f"  User:      {record['user_id']}")
    print(f"  Target:    {record.get('target', 'N/A')}")
    print(f"  Timestamp: {record['timestamp']}")
    print(f"  Prev HMAC: {(record.get('prev_hmac') or 'None')[:16]}...")
    print(f"  HMAC:      {record['hmac'][:16]}...")
    print()


def demo_chain_creation() -> tuple[list[dict[str, Any]], bytes]:
    """Demonstrate creating an HMAC chain."""
    print_header("Phase 1: Creating Audit Chain")
    
    # Create logger with demo key
    hmac_key = b"demo-hmac-key-for-audit-chain"
    logger = AuditLogger(hmac_key=hmac_key)
    
    # Create sample audit records
    records = []
    
    actions = [
        ("scan_started", "operator1", "10.0.0.1", "VULN-001"),
        ("vulnerability_found", "operator1", "10.0.0.1", "VULN-001"),
        ("validation_requested", "operator1", "10.0.0.1", "VULN-001"),
        ("exploit_approval_required", "admin1", "10.0.0.1", "VULN-001"),
        ("exploit_approved", "admin2", "10.0.0.1", "VULN-001"),
    ]
    
    print(f"Creating {len(actions)} chained audit records...\n")
    
    for action, user_id, target, ticket in actions:
        record = logger.log(
            action=action,
            user_id=user_id,
            target=target,
            scope_ticket=ticket,
            result={"status": "success"},
        )
        records.append(record)
        print_record(record, len(records))
    
    print(f"{Colors.GREEN}✓ Created {len(records)} records with chained HMACs{Colors.RESET}")
    return records, hmac_key


def demo_verification(records: list[dict[str, Any]], hmac_key: bytes) -> bool:
    """Demonstrate chain verification."""
    print_header("Phase 2: Verifying Audit Chain")
    
    print("Checking cryptographic integrity of chain...\n")
    
    valid = AuditLogger.verify_chain(records, hmac_key)
    
    if valid:
        print(f"{Colors.GREEN}✓ All {len(records)} records verified{Colors.RESET}")
        print(f"{Colors.GREEN}✓ Chain integrity CONFIRMED{Colors.RESET}")
    else:
        print(f"{Colors.RED}✗ Chain verification FAILED{Colors.RESET}")
    
    return valid


def demo_tamper_detection(records: list[dict[str, Any]], hmac_key: bytes) -> None:
    """Demonstrate tamper detection."""
    print_header("Phase 3: Tamper Detection Demo")
    
    # Create a copy and tamper with it
    import copy
    tampered_records = copy.deepcopy(records)
    
    # Tamper with the third record
    tamper_index = 2
    original_action = tampered_records[tamper_index]["action"]
    tampered_records[tamper_index]["action"] = "exploit_executed"  # Attacker change
    
    print(f"Simulating attacker modifying record #{tamper_index + 1}:")
    print(f"  Original action: '{original_action}'")
    print(f"  Tampered action: 'exploit_executed'")
    print()
    
    print("Attempting to verify tampered chain...\n")
    
    valid = AuditLogger.verify_chain(tampered_records, hmac_key)
    
    if not valid:
        print(f"{Colors.RED}✗ TAMPERING DETECTED!{Colors.RESET}")
        print(f"{Colors.GREEN}✓ System successfully detected the modification{Colors.RESET}")
    else:
        print(f"{Colors.RED}WARNING: Tamper not detected (this should not happen){Colors.RESET}")
    
    # Also test broken chain
    print("\n--- Testing broken chain link ---\n")
    broken_records = copy.deepcopy(records)
    broken_records[3]["prev_hmac"] = "0" * 64  # Break the chain
    
    print("Breaking prev_hmac link in record #4...")
    print()
    
    valid_broken = AuditLogger.verify_chain(broken_records, hmac_key)
    
    if not valid_broken:
        print(f"{Colors.RED}✗ CHAIN LINK TAMPERING DETECTED!{Colors.RESET}")
        print(f"{Colors.GREEN}✓ System detected the broken chain link{Colors.RESET}")


def demo_original_restored(records: list[dict[str, Any]], hmac_key: bytes) -> None:
    """Verify original chain still works."""
    print_header("Phase 4: Original Chain Still Valid")
    
    print("Re-verifying original (unmodified) chain...\n")
    
    valid = AuditLogger.verify_chain(records, hmac_key)
    
    if valid:
        print(f"{Colors.GREEN}✓ Original chain integrity CONFIRMED{Colors.RESET}")
        print(f"{Colors.GREEN}✓ Demo complete - tamper-evident audit logging verified{Colors.RESET}")


def main() -> int:
    """Run the audit chain demo."""
    print()
    print(f"{Colors.BOLD}{Colors.CYAN}")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║        HMAC Audit Chain Verification Demo                ║")
    print("║       Network Vulnerability Scanner Project              ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")
    
    # Phase 1: Create chain
    records, hmac_key = demo_chain_creation()
    
    # Phase 2: Verify chain
    if not demo_verification(records, hmac_key):
        print(f"\n{Colors.RED}ERROR: Initial verification failed{Colors.RESET}")
        return 1
    
    # Phase 3: Tamper detection
    demo_tamper_detection(records, hmac_key)
    
    # Phase 4: Confirm original still valid
    demo_original_restored(records, hmac_key)
    
    print()
    print(f"{Colors.BOLD}Summary:{Colors.RESET}")
    print(" • Each audit record contains an HMAC of its contents + prev HMAC")
    print(" • Any modification breaks the cryptographic chain")
    print(" • Attackers cannot forge valid HMACs without the secret key")
    print(" • Key is stored in Vault and rotated according to policy")
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
