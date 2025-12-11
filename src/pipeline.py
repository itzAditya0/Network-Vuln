"""
Scan Pipeline

Orchestrates the complete vulnerability scanning workflow:
1. Load endpoints
2. Queue scans
3. Parse results
4. Map CVEs to exploits
5. Validate with Metasploit
6. Score and prioritize
7. Generate reports
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from src.cve_mapper import CVEMapper
from src.endpoint_manager import Endpoint, EndpointManager
from src.logger import get_logger
from src.metrics import get_metrics_collector
from src.msf_validator import MetasploitValidator, ValidationResult
from src.nmap_controller import NmapController, ScanType
from src.report_generator import ReportGenerator
from src.result_parser import ResultParser
from src.safe_mode import SafeModeController
from src.scoring_engine import ScoredVulnerability, ScoringEngine
from src.worker_queue import ScanQueue

logger = get_logger(__name__)


@dataclass
class PipelineConfig:
    """Pipeline configuration."""
    scan_type: ScanType = ScanType.FULL
    max_concurrent_scans: int = 5
    validate_exploits: bool = True
    generate_reports: bool = True
    report_formats: list[str] = None
    
    def __post_init__(self):
        if self.report_formats is None:
            self.report_formats = ["json", "csv", "html"]


@dataclass
class PipelineResult:
    """Result of pipeline execution."""
    scan_id: str
    start_time: datetime
    end_time: datetime
    targets_scanned: int
    vulnerabilities_found: int
    exploitable_vulns: int
    reports: dict[str, str]
    scored_vulnerabilities: list[ScoredVulnerability]
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": (self.end_time - self.start_time).total_seconds(),
            "targets_scanned": self.targets_scanned,
            "vulnerabilities_found": self.vulnerabilities_found,
            "exploitable_vulns": self.exploitable_vulns,
            "reports": self.reports,
        }


class ScanPipeline:
    """
    Orchestrates complete vulnerability scanning workflow.
    
    Integrates all modules:
    - EndpointManager: Target loading
    - NmapController: Scanning
    - ResultParser: Normalization
    - CVEMapper: Exploit mapping
    - MetasploitValidator: Validation
    - ScoringEngine: Prioritization
    - ReportGenerator: Output
    """
    
    def __init__(
        self,
        endpoint_manager: EndpointManager,
        nmap_controller: NmapController,
        cve_mapper: CVEMapper,
        msf_validator: MetasploitValidator | None = None,
        scoring_engine: ScoringEngine | None = None,
        report_generator: ReportGenerator | None = None,
        safe_mode: SafeModeController | None = None,
        config: PipelineConfig | None = None,
    ):
        self._endpoints = endpoint_manager
        self._nmap = nmap_controller
        self._cve_mapper = cve_mapper
        self._msf = msf_validator
        self._scoring = scoring_engine or ScoringEngine()
        self._reports = report_generator or ReportGenerator()
        self._safe_mode = safe_mode
        self._config = config or PipelineConfig()
        
        self._parser = ResultParser()
        self._metrics = get_metrics_collector()
        self._queue: ScanQueue | None = None
    
    async def run(
        self,
        user_id: str,
        ticket_id: str,
        targets: list[Endpoint] | None = None,
    ) -> PipelineResult:
        """
        Execute full scanning pipeline.
        
        Args:
            user_id: Operator user ID for audit
            ticket_id: Authorized scope ticket
            targets: Optional target list (defaults to all loaded endpoints)
        
        Returns:
            PipelineResult with scan summary and reports
        """
        import uuid
        scan_id = str(uuid.uuid4())[:8]
        start_time = datetime.now(timezone.utc)
        
        logger.info(
            "pipeline_started",
            scan_id=scan_id,
            user_id=user_id,
            ticket_id=ticket_id
        )
        
        # Get targets
        if targets is None:
            targets = self._endpoints.get_all()
        
        if not targets:
            logger.warning("pipeline_no_targets", scan_id=scan_id)
            return PipelineResult(
                scan_id=scan_id,
                start_time=start_time,
                end_time=datetime.now(timezone.utc),
                targets_scanned=0,
                vulnerabilities_found=0,
                exploitable_vulns=0,
                reports={},
                scored_vulnerabilities=[],
            )
        
        # Phase 1: Scan targets
        logger.info("pipeline_phase", phase="scanning", targets=len(targets))
        scan_results = await self._scan_targets(targets, user_id, ticket_id)
        
        # Phase 2: Parse results
        logger.info("pipeline_phase", phase="parsing")
        parsed_results = [self._parser.parse(r) for r in scan_results]
        
        # Phase 3: Map CVEs to exploits
        logger.info("pipeline_phase", phase="mapping")
        all_vulns = []
        for parsed in parsed_results:
            vulns = self._parser.get_vulnerabilities(parsed)
            mapped = self._cve_mapper.map_scan_results(
                vulnerabilities=vulns,
                ports=parsed.open_ports
            )
            all_vulns.extend(mapped)
        
        # Phase 4: Validate exploitability (optional)
        if self._config.validate_exploits and self._msf:
            logger.info("pipeline_phase", phase="validating")
            all_vulns = await self._validate_vulnerabilities(
                all_vulns, user_id, ticket_id
            )
        
        # Phase 5: Score and prioritize
        logger.info("pipeline_phase", phase="scoring")
        asset_criticality = {
            e.ip: e.asset_criticality for e in targets
        }
        scored = self._scoring.prioritize(all_vulns, asset_criticality)
        
        # Record metrics
        for vuln in scored:
            self._metrics.record_vulnerability(vuln.severity.value)
        
        # Phase 6: Generate reports
        reports = {}
        if self._config.generate_reports:
            logger.info("pipeline_phase", phase="reporting")
            metadata = {
                "scan_id": scan_id,
                "user_id": user_id,
                "ticket_id": ticket_id,
                "targets": len(targets),
            }
            reports = self._reports.generate_all(
                scored,
                metadata,
                f"scan_{scan_id}"
            )
        
        end_time = datetime.now(timezone.utc)
        
        # Count exploitable
        exploitable = sum(
            1 for v in scored
            if v.validation_result == ValidationResult.VULNERABLE
        )
        
        result = PipelineResult(
            scan_id=scan_id,
            start_time=start_time,
            end_time=end_time,
            targets_scanned=len(targets),
            vulnerabilities_found=len(scored),
            exploitable_vulns=exploitable,
            reports=reports,
            scored_vulnerabilities=scored,
        )
        
        logger.info(
            "pipeline_completed",
            scan_id=scan_id,
            duration=(end_time - start_time).total_seconds(),
            vulnerabilities=len(scored),
            exploitable=exploitable
        )
        
        return result
    
    async def _scan_targets(
        self,
        targets: list[Endpoint],
        user_id: str,
        ticket_id: str,
    ) -> list:
        """Scan all targets with rate limiting."""
        results = []
        
        # Pre-check scope for all targets
        if self._safe_mode:
            for target in targets:
                try:
                    self._safe_mode.pre_scan_check(target.ip, user_id, ticket_id)
                except Exception as e:
                    logger.warning(
                        "target_blocked",
                        target=target.ip,
                        error=str(e)
                    )
        
        # Async scan
        scan_results = await self._nmap.async_scan(
            [t.ip for t in targets],
            scan_type=self._config.scan_type,
            max_concurrent=self._config.max_concurrent_scans,
        )
        
        for result in scan_results:
            self._metrics.record_scan(
                duration=result.duration_seconds,
                scan_type=self._config.scan_type.value,
                success=result.state != "down"
            )
            results.append(result)
        
        return results
    
    async def _validate_vulnerabilities(
        self,
        vulnerabilities: list[dict[str, Any]],
        user_id: str,
        ticket_id: str,
    ) -> list[dict[str, Any]]:
        """Validate vulnerabilities with Metasploit."""
        validated = []
        
        for vuln in vulnerabilities:
            modules = vuln.get("recommended_modules", [])
            
            if not modules:
                vuln["validation_result"] = None
                validated.append(vuln)
                continue
            
            # Use first module with check support
            module_info = None
            for m in modules:
                if m.get("check_supported"):
                    module_info = m
                    break
            
            if not module_info:
                vuln["validation_result"] = None
                validated.append(vuln)
                continue
            
            # Validate
            try:
                result = self._msf.validate(
                    target=vuln["target"],
                    module=module_info["fullname"],
                    user_id=user_id,
                    ticket_id=ticket_id,
                )
                
                vuln["validation_result"] = result.result.value
                vuln["validation_output"] = result.output[:500]
                vuln["module"] = module_info["fullname"]
                
                self._metrics.record_validation(
                    duration=result.duration_seconds,
                    module_type=module_info["fullname"].split("/")[0],
                    result=result.result.value
                )
                
            except Exception as e:
                logger.error(
                    "validation_error",
                    target=vuln["target"],
                    error=str(e)
                )
                vuln["validation_result"] = "error"
            
            validated.append(vuln)
        
        return validated
    
    def get_top_vulnerabilities(
        self,
        result: PipelineResult,
        n: int = 10
    ) -> list[ScoredVulnerability]:
        """Get top N vulnerabilities from pipeline result."""
        return self._scoring.get_top_n(result.scored_vulnerabilities, n)
