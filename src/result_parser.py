"""
Result Parser

Parses Nmap scan results into normalized JSON schema.
Extracts ports, services, banners, CVEs, and vulnerabilities.
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.logger import get_logger
from src.nmap_controller import ScanResult

logger = get_logger(__name__)


@dataclass
class ParsedVulnerability:
    """Normalized vulnerability from scan results."""
    id: str
    target: str
    port: int | None
    protocol: str
    service: str | None
    version: str | None
    cves: list[str] = field(default_factory=list)
    script_name: str | None = None
    script_output: str | None = None
    confidence: float = 0.5  # 0.0-1.0
    raw_data: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "cves": self.cves,
            "script_name": self.script_name,
            "script_output": self.script_output,
            "confidence": self.confidence,
        }


@dataclass
class ParsedScanResult:
    """Normalized scan result."""
    scan_id: str
    target: str
    scan_time: datetime
    duration_seconds: float
    state: str
    hostname: str | None
    os_matches: list[dict[str, Any]]
    open_ports: list[dict[str, Any]]
    vulnerabilities: list[ParsedVulnerability]
    total_ports_scanned: int
    raw_cves: list[str]
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "scan_time": self.scan_time.isoformat(),
            "duration_seconds": self.duration_seconds,
            "state": self.state,
            "hostname": self.hostname,
            "os_matches": self.os_matches,
            "open_ports": self.open_ports,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "total_ports_scanned": self.total_ports_scanned,
            "summary": {
                "total_open_ports": len(self.open_ports),
                "total_vulnerabilities": len(self.vulnerabilities),
                "total_cves": len(self.raw_cves),
                "unique_cves": list(set(self.raw_cves)),
            }
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class ResultParser:
    """
    Parses and normalizes scan results.
    
    Converts raw Nmap output to structured schema suitable for
    further processing (CVE mapping, scoring, reporting).
    """
    
    # CVE pattern
    CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    
    # Vulnerability indicators in script output
    VULN_INDICATORS = [
        "vulnerable",
        "vulnerability",
        "exploit",
        "cve-",
        "critical",
        "high risk",
        "remote code execution",
        "rce",
        "buffer overflow",
        "authentication bypass",
        "sql injection",
        "command injection",
    ]
    
    def __init__(self):
        self._vuln_counter = 0
    
    def parse(self, scan_result: ScanResult) -> ParsedScanResult:
        """
        Parse ScanResult into normalized format.
        
        Extracts:
        - Open ports with service info
        - Vulnerabilities from script outputs
        - CVE references
        - OS fingerprints
        """
        import uuid
        scan_id = str(uuid.uuid4())[:8]
        
        open_ports = []
        vulnerabilities = []
        all_cves = []
        
        for port in scan_result.ports:
            if port.state != "open":
                continue
            
            port_info = {
                "port": port.port,
                "protocol": port.protocol,
                "service": port.service,
                "version": port.version,
                "product": port.product,
            }
            open_ports.append(port_info)
            
            # Extract CVEs from port
            all_cves.extend(port.cves)
            
            # Parse script outputs for vulnerabilities
            for script_name, output in port.scripts.items():
                vuln = self._parse_script_output(
                    target=scan_result.target,
                    port=port.port,
                    protocol=port.protocol,
                    service=port.service,
                    version=port.version,
                    script_name=script_name,
                    output=output,
                )
                if vuln:
                    vulnerabilities.append(vuln)
                    all_cves.extend(vuln.cves)
        
        # Also process pre-extracted vulnerabilities
        for vuln_data in scan_result.vulnerabilities:
            cves = vuln_data.get("cves", [])
            all_cves.extend(cves)
        
        parsed = ParsedScanResult(
            scan_id=scan_id,
            target=scan_result.target,
            scan_time=scan_result.scan_time,
            duration_seconds=scan_result.duration_seconds,
            state=scan_result.state,
            hostname=scan_result.hostname,
            os_matches=scan_result.os_matches,
            open_ports=open_ports,
            vulnerabilities=vulnerabilities,
            total_ports_scanned=len(scan_result.ports),
            raw_cves=list(set(all_cves)),
        )
        
        logger.info(
            "scan_parsed",
            target=scan_result.target,
            open_ports=len(open_ports),
            vulnerabilities=len(vulnerabilities),
            cves=len(set(all_cves))
        )
        
        return parsed
    
    def _parse_script_output(
        self,
        target: str,
        port: int,
        protocol: str,
        service: str | None,
        version: str | None,
        script_name: str,
        output: str,
    ) -> ParsedVulnerability | None:
        """Parse script output for vulnerability indicators."""
        
        # Check for vulnerability indicators
        output_lower = output.lower()
        is_vuln = any(ind in output_lower for ind in self.VULN_INDICATORS)
        
        if not is_vuln:
            return None
        
        # Extract CVEs
        cves = list(set(self.CVE_PATTERN.findall(output)))
        
        # Calculate confidence based on indicators
        confidence = self._calculate_confidence(output, cves)
        
        self._vuln_counter += 1
        
        return ParsedVulnerability(
            id=f"VULN-{self._vuln_counter:04d}",
            target=target,
            port=port,
            protocol=protocol,
            service=service,
            version=version,
            cves=[cve.upper() for cve in cves],
            script_name=script_name,
            script_output=output[:1000],  # Truncate
            confidence=confidence,
        )
    
    def _calculate_confidence(self, output: str, cves: list[str]) -> float:
        """Calculate confidence score based on output analysis."""
        score = 0.3  # Base score for having vulnerability indicator
        
        output_lower = output.lower()
        
        # CVE presence increases confidence
        if cves:
            score += 0.2
        
        # Strong indicators
        if "is vulnerable" in output_lower:
            score += 0.3
        elif "vulnerable" in output_lower:
            score += 0.2
        
        if "exploit" in output_lower:
            score += 0.1
        
        return min(1.0, score)
    
    def normalize_results(
        self,
        parsed_results: list[ParsedScanResult]
    ) -> dict[str, Any]:
        """
        Normalize multiple scan results into unified format.
        
        Returns summary with all targets, vulnerabilities, and CVEs.
        """
        all_vulns = []
        all_cves = set()
        targets_summary = []
        
        for result in parsed_results:
            targets_summary.append({
                "target": result.target,
                "state": result.state,
                "open_ports": len(result.open_ports),
                "vulnerabilities": len(result.vulnerabilities),
            })
            
            for vuln in result.vulnerabilities:
                all_vulns.append(vuln.to_dict())
                all_cves.update(vuln.cves)
            
            all_cves.update(result.raw_cves)
        
        return {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "total_targets": len(parsed_results),
            "targets": targets_summary,
            "total_vulnerabilities": len(all_vulns),
            "vulnerabilities": all_vulns,
            "unique_cves": sorted(all_cves),
        }
    
    def get_vulnerabilities(
        self,
        parsed_result: ParsedScanResult
    ) -> list[dict[str, Any]]:
        """Extract vulnerabilities in format suitable for scoring engine."""
        vulns = []
        
        for vuln in parsed_result.vulnerabilities:
            vulns.append({
                "target": vuln.target,
                "port": vuln.port,
                "service": vuln.service,
                "version": vuln.version,
                "cves": vuln.cves,
                "confidence": vuln.confidence,
            })
        
        return vulns
