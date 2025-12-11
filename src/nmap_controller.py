"""
Nmap Controller

Integration with Nmap for vulnerability scanning:
- Async scanning with rate limiting
- Retry logic with exponential backoff
- Fallback scripts for service misidentification
- Result normalization to JSON schema
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import nmap
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from src.logger import get_logger

logger = get_logger(__name__)


class ScanType(Enum):
    """Predefined scan configurations."""
    QUICK = "quick"  # Fast port scan
    FULL = "full"  # Version + OS + vuln scripts
    STEALTH = "stealth"  # SYN scan, minimal noise
    VULN_ONLY = "vuln"  # Focus on vulnerability scripts


# Scan type configurations
SCAN_CONFIGS = {
    ScanType.QUICK: {
        "arguments": "-sV -T4 --top-ports 100",
        "timeout": 120,
    },
    ScanType.FULL: {
        "arguments": "-sV -O --script vuln,version -T2",
        "timeout": 300,
    },
    ScanType.STEALTH: {
        "arguments": "-sS -T2 -Pn",
        "timeout": 180,
    },
    ScanType.VULN_ONLY: {
        "arguments": "-sV --script vuln -T2",
        "timeout": 240,
    },
}

# Fallback scripts for service misidentification
FALLBACK_SCRIPTS = ["banner", "http-headers", "ssl-cert", "ssh-hostkey"]


@dataclass
class PortResult:
    """Scan result for a single port."""
    port: int
    protocol: str
    state: str
    service: str | None = None
    version: str | None = None
    product: str | None = None
    scripts: dict[str, str] = field(default_factory=dict)
    cves: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Complete scan result for a target."""
    target: str
    scan_time: datetime
    duration_seconds: float
    ports: list[PortResult] = field(default_factory=list)
    os_matches: list[dict[str, Any]] = field(default_factory=list)
    hostname: str | None = None
    state: str = "unknown"
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    raw_xml: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scan_time": self.scan_time.isoformat(),
            "duration_seconds": self.duration_seconds,
            "hostname": self.hostname,
            "state": self.state,
            "ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service": p.service,
                    "version": p.version,
                    "product": p.product,
                    "scripts": p.scripts,
                    "cves": p.cves,
                }
                for p in self.ports
            ],
            "os_matches": self.os_matches,
            "vulnerabilities": self.vulnerabilities,
        }


class NmapError(Exception):
    """Raised when Nmap scan fails."""
    pass


class NmapController:
    """
    Controls Nmap scanning operations.
    
    Features:
    - Configurable scan types with timing templates
    - Automatic retry with exponential backoff
    - Fallback scripts for service fingerprinting
    - Result normalization to structured format
    """
    
    def __init__(
        self,
        timing_template: str = "T2",
        timeout_seconds: int = 300,
        max_retries: int = 3,
    ):
        self._timing = timing_template
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._scanner = nmap.PortScanner()
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=60),
        retry=retry_if_exception_type((NmapError, TimeoutError)),
    )
    def scan(
        self,
        target: str,
        scan_type: ScanType = ScanType.FULL,
        ports: str | None = None,
        custom_args: str | None = None,
    ) -> ScanResult:
        """
        Execute Nmap scan on target.
        
        Args:
            target: IP address or hostname
            scan_type: Predefined scan configuration
            ports: Optional port specification (e.g., "22,80,443")
            custom_args: Override scan arguments
        
        Returns:
            ScanResult with normalized data
        
        Raises:
            NmapError: If scan fails after retries
        """
        config = SCAN_CONFIGS[scan_type]
        arguments: str = custom_args or config["arguments"]
        
        # Add timing template
        if "-T" not in arguments:
            arguments = f"-{self._timing} {arguments}"
        
        # Add port specification
        if ports:
            arguments = f"-p {ports} {arguments}"
        
        logger.info(
            "nmap_scan_start",
            target=target,
            scan_type=scan_type.value,
            arguments=arguments
        )
        
        start_time = datetime.now(timezone.utc)
        
        try:
            self._scanner.scan(
                hosts=target,
                arguments=arguments,
                timeout=self._timeout
            )
        except nmap.PortScannerError as e:
            logger.error("nmap_scan_error", target=target, error=str(e))
            raise NmapError(f"Nmap scan failed: {e}")
        except Exception as e:
            logger.error("nmap_scan_error", target=target, error=str(e))
            raise NmapError(f"Scan error: {e}")
        
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        # Parse results
        result = self._parse_results(target, start_time, duration)
        
        # Run fallback if service detection failed
        if self._needs_fallback(result):
            result = self._run_fallback_scan(target, result)
        
        logger.info(
            "nmap_scan_complete",
            target=target,
            duration=duration,
            ports_found=len(result.ports),
            vulnerabilities=len(result.vulnerabilities)
        )
        
        return result
    
    def _parse_results(
        self,
        target: str,
        scan_time: datetime,
        duration: float
    ) -> ScanResult:
        """Parse Nmap scan results into structured format."""
        result = ScanResult(
            target=target,
            scan_time=scan_time,
            duration_seconds=duration
        )
        
        if target not in self._scanner.all_hosts():
            result.state = "down"
            return result
        
        host = self._scanner[target]
        result.state = host.state()
        result.hostname = host.hostname() or None
        
        # Parse OS matches
        if "osmatch" in host:
            result.os_matches = [
                {"name": m["name"], "accuracy": m["accuracy"]}
                for m in host["osmatch"][:3]  # Top 3
            ]
        
        # Parse ports
        for protocol in ["tcp", "udp"]:
            if protocol not in host:
                continue
            
            for port, data in host[protocol].items():
                port_result = PortResult(
                    port=port,
                    protocol=protocol,
                    state=data.get("state", "unknown"),
                    service=data.get("name"),
                    version=data.get("version"),
                    product=data.get("product"),
                )
                
                # Extract script outputs
                if "script" in data:
                    for script_name, output in data["script"].items():
                        port_result.scripts[script_name] = output
                        
                        # Extract CVEs from script output
                        cves = self._extract_cves(output)
                        port_result.cves.extend(cves)
                        
                        # Add to vulnerabilities list
                        if cves:
                            result.vulnerabilities.append({
                                "port": port,
                                "script": script_name,
                                "cves": cves,
                                "output": output[:500],  # Truncate
                            })
                
                result.ports.append(port_result)
        
        # Store raw XML for debugging
        try:
            result.raw_xml = self._scanner.get_nmap_last_output()
        except Exception:
            pass
        
        return result
    
    def _extract_cves(self, script_output: str) -> list[str]:
        """Extract CVE IDs from script output."""
        import re
        pattern = r"CVE-\d{4}-\d{4,7}"
        return list(set(re.findall(pattern, script_output, re.IGNORECASE)))
    
    def _needs_fallback(self, result: ScanResult) -> bool:
        """Check if fallback scripts are needed."""
        for port in result.ports:
            if port.state == "open" and not port.service:
                return True
        return False
    
    def _run_fallback_scan(
        self,
        target: str,
        original_result: ScanResult
    ) -> ScanResult:
        """Run fallback scripts for ports with unknown services."""
        unknown_ports = [
            str(p.port) for p in original_result.ports
            if p.state == "open" and not p.service
        ]
        
        if not unknown_ports:
            return original_result
        
        logger.info(
            "nmap_fallback_scan",
            target=target,
            ports=unknown_ports
        )
        
        scripts = ",".join(FALLBACK_SCRIPTS)
        port_spec = ",".join(unknown_ports)
        
        try:
            self._scanner.scan(
                hosts=target,
                arguments=f"-sV --script {scripts} -p {port_spec}",
                timeout=60
            )
            
            # Merge fallback results
            if target in self._scanner.all_hosts():
                host = self._scanner[target]
                for protocol in ["tcp", "udp"]:
                    if protocol not in host:
                        continue
                    for port, data in host[protocol].items():
                        for p in original_result.ports:
                            if p.port == port and p.protocol == protocol:
                                p.service = p.service or data.get("name")
                                p.version = p.version or data.get("version")
                                if "script" in data:
                                    p.scripts.update(data["script"])
                                break
        
        except Exception as e:
            logger.warning("nmap_fallback_error", target=target, error=str(e))
        
        return original_result
    
    async def async_scan(
        self,
        targets: list[str],
        scan_type: ScanType = ScanType.FULL,
        max_concurrent: int = 5,
    ) -> list[ScanResult]:
        """
        Scan multiple targets concurrently.
        
        Uses asyncio to manage concurrent scans with rate limiting.
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_limit(target: str) -> ScanResult:
            async with semaphore:
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    None, self.scan, target, scan_type
                )
        
        tasks = [scan_with_limit(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out errors
        valid_results: list[ScanResult] = []
        for target, result in zip(targets, results):
            if isinstance(result, Exception):
                logger.error("async_scan_error", target=target, error=str(result))
            elif isinstance(result, ScanResult):
                valid_results.append(result)
        
        return valid_results
