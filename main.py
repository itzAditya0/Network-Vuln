#!/usr/bin/env python3
"""
Network Vulnerability Scanner - CLI Entry Point

Commands:
- scan: Run vulnerability scan
- validate: Validate specific vulnerability
- report: Generate reports
- status: Check scan status
"""

import argparse
import asyncio
import sys
from pathlib import Path

from src.cve_mapper import CVEMapper
from src.endpoint_manager import EndpointManager
from src.logger import configure_logging, get_logger
from src.metrics import get_metrics_collector
from src.nmap_controller import NmapController, ScanType
from src.pipeline import PipelineConfig, ScanPipeline
from src.rbac import RBACManager, Role, User
from src.report_generator import ReportGenerator
from src.safe_mode import SafeModeController
from src.scoring_engine import ScoringEngine
from src.secrets import get_secrets_manager

logger = get_logger(__name__)


def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="vulnscanner",
        description="Network Vulnerability Scanner with Exploit Validation",
    )
    
    parser.add_argument(
        "--config",
        type=str,
        default="config/config.yaml",
        help="Path to configuration file",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level",
    )
    parser.add_argument(
        "--metrics-port",
        type=int,
        default=9090,
        help="Prometheus metrics port",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # === Scan Command ===
    scan_parser = subparsers.add_parser("scan", help="Run vulnerability scan")
    scan_parser.add_argument(
        "--target",
        type=str,
        help="Single target IP/hostname",
    )
    scan_parser.add_argument(
        "--targets-file",
        type=str,
        help="File with target list (CSV/JSON)",
    )
    scan_parser.add_argument(
        "--scan-type",
        choices=["quick", "full", "stealth", "vuln"],
        default="full",
        help="Scan type",
    )
    scan_parser.add_argument(
        "--user-id",
        type=str,
        required=True,
        help="Operator user ID",
    )
    scan_parser.add_argument(
        "--ticket-id",
        type=str,
        required=True,
        help="Authorization ticket ID (JIRA or signed)",
    )
    scan_parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate vulnerabilities with Metasploit",
    )
    scan_parser.add_argument(
        "--output",
        type=str,
        default="reports",
        help="Output directory for reports",
    )
    scan_parser.add_argument(
        "--format",
        choices=["json", "csv", "html", "all"],
        default="all",
        help="Report format",
    )
    
    # === Validate Command ===
    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate specific vulnerability"
    )
    validate_parser.add_argument(
        "--target",
        type=str,
        required=True,
        help="Target IP/hostname",
    )
    validate_parser.add_argument(
        "--module",
        type=str,
        required=True,
        help="Metasploit module path",
    )
    validate_parser.add_argument(
        "--user-id",
        type=str,
        required=True,
        help="Operator user ID",
    )
    validate_parser.add_argument(
        "--ticket-id",
        type=str,
        required=True,
        help="Authorization ticket ID",
    )
    validate_parser.add_argument(
        "--allow-exploit",
        action="store_true",
        help="Allow exploit mode (requires approval ID)",
    )
    validate_parser.add_argument(
        "--approval-id",
        type=str,
        help="Two-person approval ID for exploit mode",
    )
    
    # === Report Command ===
    report_parser = subparsers.add_parser("report", help="Generate reports")
    report_parser.add_argument(
        "--scan-id",
        type=str,
        required=True,
        help="Scan ID to generate report for",
    )
    report_parser.add_argument(
        "--format",
        choices=["json", "csv", "html", "all"],
        default="all",
        help="Report format",
    )
    report_parser.add_argument(
        "--output",
        type=str,
        default="reports",
        help="Output directory",
    )
    
    # === Status Command ===
    status_parser = subparsers.add_parser("status", help="Check scan status")
    status_parser.add_argument(
        "--scan-id",
        type=str,
        help="Specific scan ID",
    )
    
    return parser


async def run_scan(args: argparse.Namespace) -> int:
    """Execute scan command."""
    logger.info(
        "scan_command",
        user_id=args.user_id,
        ticket_id=args.ticket_id
    )
    
    # Initialize components
    endpoint_manager = EndpointManager()
    
    # Load targets
    if args.target:
        from src.endpoint_manager import Endpoint
        import socket
        
        # Resolve hostname to IP if needed
        target_ip = args.target
        try:
            # Check if it's already an IP address
            socket.inet_aton(target_ip)
        except socket.error:
            # Not a valid IP, try to resolve as hostname
            try:
                target_ip = socket.gethostbyname(args.target)
                logger.info("hostname_resolved", hostname=args.target, ip=target_ip)
            except socket.gaierror as e:
                print(f"Error: Cannot resolve hostname '{args.target}': {e}", file=sys.stderr)
                return 1
        
        targets = [Endpoint(ip=target_ip, hostname=args.target)]
    elif args.targets_file:
        targets = endpoint_manager.load_from_file(args.targets_file)
    else:
        print("Error: Specify --target or --targets-file", file=sys.stderr)
        return 1
    
    # Setup RBAC (simplified for CLI)
    rbac = RBACManager(admin_mfa_required=False)
    rbac.add_user(User(id=args.user_id, username=args.user_id, role=Role.OPERATOR))
    
    # Setup safe mode with demo scope
    from src.logger import AuditLogger
    from ipaddress import IPv4Network
    from datetime import datetime, timezone, timedelta
    from src.safe_mode import ScopeAuthorization
    
    # Create audit logger (simplified without Vault for CLI)
    audit = AuditLogger(hmac_key=b"demo-key-replace-with-vault")
    
    # Add authorized scope for targets
    scopes = []
    for target in targets:
        scopes.append(ScopeAuthorization(
            id="cli-scope",
            cidr=IPv4Network(f"{target.ip}/32"),
            ticket_id=args.ticket_id,
            approved_by=[args.user_id],
            valid_from=datetime.now(timezone.utc) - timedelta(hours=1),
            valid_until=datetime.now(timezone.utc) + timedelta(hours=24),
        ))
    
    safe_mode = SafeModeController(
        rbac=rbac,
        audit=audit,
        authorized_scopes=scopes,
    )
    
    # Initialize pipeline
    scan_type = ScanType[args.scan_type.upper()]
    
    nmap = NmapController()
    cve_mapper = CVEMapper()
    cve_mapper.build_default_index()
    
    config = PipelineConfig(
        scan_type=scan_type,
        validate_exploits=args.validate,
        generate_reports=True,
    )
    
    report_gen = ReportGenerator(output_dir=args.output)
    
    pipeline = ScanPipeline(
        endpoint_manager=endpoint_manager,
        nmap_controller=nmap,
        cve_mapper=cve_mapper,
        report_generator=report_gen,
        safe_mode=safe_mode,
        config=config,
    )
    
    # Run pipeline
    try:
        result = await pipeline.run(
            user_id=args.user_id,
            ticket_id=args.ticket_id,
            targets=targets,
        )
        
        print(f"\n{'='*60}")
        print(f"Scan Complete: {result.scan_id}")
        print(f"{'='*60}")
        print(f"Targets Scanned:    {result.targets_scanned}")
        print(f"Vulnerabilities:    {result.vulnerabilities_found}")
        print(f"Exploitable:        {result.exploitable_vulns}")
        print(f"Duration:           {(result.end_time - result.start_time).total_seconds():.1f}s")
        print(f"\nReports:")
        for fmt, path in result.reports.items():
            print(f"  {fmt}: {path}")
        
        # Show top vulnerabilities
        top = pipeline.get_top_vulnerabilities(result, n=5)
        if top:
            print(f"\nTop Vulnerabilities:")
            for i, v in enumerate(top, 1):
                print(f"  {i}. [{v.severity.value.upper()}] {v.target}:{v.port} "
                      f"{v.cve or v.service} (score: {v.final_score:.2f})")
        
        return 0
        
    except Exception as e:
        logger.error("scan_failed", error=str(e))
        print(f"Error: {e}", file=sys.stderr)
        return 1


async def run_validate(args: argparse.Namespace) -> int:
    """Execute validate command."""
    # Placeholder - requires Metasploit connection
    print("Validation command requires Metasploit RPC connection.")
    print("Ensure msfrpcd is running with mTLS proxy.")
    return 1


async def run_report(args: argparse.Namespace) -> int:
    """Execute report command."""
    # Placeholder - requires database
    print("Report generation requires database connection.")
    return 1


async def run_status(args: argparse.Namespace) -> int:
    """Execute status command."""
    metrics = get_metrics_collector()
    stats = {
        "active_scans": 0,  # Would query from queue
        "pending_tasks": 0,
        "dead_letter": 0,
    }
    
    print(f"\nScanner Status:")
    print(f"  Active Scans:   {stats['active_scans']}")
    print(f"  Pending Tasks:  {stats['pending_tasks']}")
    print(f"  Dead Letter:    {stats['dead_letter']}")
    
    return 0


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Configure logging
    configure_logging(level=args.log_level)
    
    # Start metrics server
    metrics = get_metrics_collector(port=args.metrics_port)
    metrics.set_info(version="1.0.0", environment="cli")
    
    # Run command
    if args.command == "scan":
        return asyncio.run(run_scan(args))
    elif args.command == "validate":
        return asyncio.run(run_validate(args))
    elif args.command == "report":
        return asyncio.run(run_report(args))
    elif args.command == "status":
        return asyncio.run(run_status(args))
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
