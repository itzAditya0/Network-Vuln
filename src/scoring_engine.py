"""
Threat Prioritization Scoring Engine

Calculates vulnerability priority scores using:
- CVSS base score
- Exploit success probability (from Metasploit validation)
- Asset criticality weight
- False positive factor

Score = (CVSS × Exploit_Probability × Asset_Weight) - FP_Factor
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any

from src.logger import get_logger
from src.msf_validator import ValidationResult

logger = get_logger(__name__)


class SeverityLevel(Enum):
    """Severity classification based on score."""
    CRITICAL = "critical"  # Score >= 9.0
    HIGH = "high"  # Score >= 7.0
    MEDIUM = "medium"  # Score >= 4.0
    LOW = "low"  # Score >= 0.1
    INFO = "info"  # Score < 0.1


# CVSS V3 base scores for common vulnerabilities
# In production, fetch from NVD API
DEFAULT_CVSS_SCORES: dict[str, float] = {
    "CVE-2017-0143": 8.1,  # EternalBlue
    "CVE-2017-0144": 8.1,
    "CVE-2021-44228": 10.0,  # Log4Shell
    "CVE-2014-0160": 7.5,  # Heartbleed
    "CVE-2018-15473": 5.3,  # SSH enumeration
    "CVE-2011-2523": 9.8,  # vsftpd backdoor
}


# Exploit probability based on validation result
EXPLOIT_PROBABILITY: dict[ValidationResult, float] = {
    ValidationResult.VULNERABLE: 0.95,
    ValidationResult.NOT_VULNERABLE: 0.05,
    ValidationResult.UNKNOWN: 0.50,
    ValidationResult.ERROR: 0.30,
    ValidationResult.SAFE_MODE_BLOCKED: 0.50,
}


@dataclass
class ScoredVulnerability:
    """Vulnerability with calculated priority score."""
    target: str
    port: int | None
    cve: str | None
    service: str | None
    cvss: float
    exploit_probability: float
    asset_criticality: float
    fp_factor: float
    raw_score: float
    final_score: float
    severity: SeverityLevel
    validation_result: ValidationResult | None
    module: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "port": self.port,
            "cve": self.cve,
            "service": self.service,
            "cvss": self.cvss,
            "exploit_probability": self.exploit_probability,
            "asset_criticality": self.asset_criticality,
            "fp_factor": self.fp_factor,
            "raw_score": round(self.raw_score, 2),
            "final_score": round(self.final_score, 2),
            "severity": self.severity.value,
            "validation_result": self.validation_result.value if self.validation_result else None,
            "module": self.module,
        }


class ScoringEngine:
    """
    Calculates threat priority scores for vulnerabilities.
    
    The scoring formula:
    Score = (CVSS × Exploit_Probability × Asset_Weight) - FP_Factor
    
    This produces scores that:
    - Prioritize exploitable vulnerabilities over theoretical ones
    - Weight by asset importance
    - Reduce noise from likely false positives
    """
    
    def __init__(
        self,
        cvss_scores: dict[str, float] | None = None,
        default_cvss: float = 5.0,
        default_asset_weight: float = 1.0,
    ):
        self._cvss_scores = cvss_scores or DEFAULT_CVSS_SCORES
        self._default_cvss = default_cvss
        self._default_asset_weight = default_asset_weight
    
    def get_cvss(self, cve: str | None) -> float:
        """Get CVSS score for CVE, or default if not found."""
        if not cve:
            return self._default_cvss
        return self._cvss_scores.get(cve.upper(), self._default_cvss)
    
    def get_exploit_probability(
        self,
        validation_result: ValidationResult | None
    ) -> float:
        """Get exploit probability based on validation result."""
        if validation_result is None:
            return 0.50  # Unknown
        return EXPLOIT_PROBABILITY.get(validation_result, 0.50)
    
    def calculate_fp_factor(
        self,
        validation_result: ValidationResult | None,
        has_exploit_module: bool,
    ) -> float:
        """
        Calculate false positive reduction factor.
        
        Higher FP factor for:
        - Unvalidated vulnerabilities
        - No exploit module available
        """
        factor = 0.0
        
        # No validation = higher FP risk
        if validation_result is None:
            factor += 1.0
        elif validation_result == ValidationResult.UNKNOWN:
            factor += 0.5
        elif validation_result == ValidationResult.NOT_VULNERABLE:
            factor += 2.0  # Strong FP indicator
        
        # No exploit module = higher FP risk
        if not has_exploit_module:
            factor += 0.5
        
        return factor
    
    def calculate_score(
        self,
        cve: str | None = None,
        validation_result: ValidationResult | None = None,
        asset_criticality: float | None = None,
        has_exploit_module: bool = False,
    ) -> tuple[float, float, SeverityLevel]:
        """
        Calculate vulnerability priority score.
        
        Returns:
            Tuple of (raw_score, final_score, severity_level)
        """
        cvss = self.get_cvss(cve)
        exploit_prob = self.get_exploit_probability(validation_result)
        asset_weight = asset_criticality or self._default_asset_weight
        fp_factor = self.calculate_fp_factor(validation_result, has_exploit_module)
        
        # Core formula
        raw_score = cvss * exploit_prob * asset_weight
        final_score = max(0, raw_score - fp_factor)
        
        # Classify severity
        severity = self._classify_severity(final_score)
        
        return raw_score, final_score, severity
    
    def _classify_severity(self, score: float) -> SeverityLevel:
        """Classify score into severity level."""
        if score >= 9.0:
            return SeverityLevel.CRITICAL
        elif score >= 7.0:
            return SeverityLevel.HIGH
        elif score >= 4.0:
            return SeverityLevel.MEDIUM
        elif score >= 0.1:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    def score_vulnerability(
        self,
        target: str,
        port: int | None,
        cve: str | None,
        service: str | None,
        validation_result: ValidationResult | None,
        asset_criticality: float = 1.0,
        module: str | None = None,
    ) -> ScoredVulnerability:
        """
        Score a single vulnerability.
        
        Returns ScoredVulnerability with all scoring details.
        """
        has_module = module is not None
        raw_score, final_score, severity = self.calculate_score(
            cve=cve,
            validation_result=validation_result,
            asset_criticality=asset_criticality,
            has_exploit_module=has_module,
        )
        
        return ScoredVulnerability(
            target=target,
            port=port,
            cve=cve,
            service=service,
            cvss=self.get_cvss(cve),
            exploit_probability=self.get_exploit_probability(validation_result),
            asset_criticality=asset_criticality,
            fp_factor=self.calculate_fp_factor(validation_result, has_module),
            raw_score=raw_score,
            final_score=final_score,
            severity=severity,
            validation_result=validation_result,
            module=module,
        )
    
    def prioritize(
        self,
        vulnerabilities: list[dict[str, Any]],
        asset_criticality_map: dict[str, float] | None = None,
    ) -> list[ScoredVulnerability]:
        """
        Score and prioritize a list of vulnerabilities.
        
        Returns vulnerabilities sorted by priority (highest first).
        """
        asset_map = asset_criticality_map or {}
        scored = []
        
        for vuln in vulnerabilities:
            target = vuln.get("target", "")
            asset_crit = asset_map.get(target, self._default_asset_weight)
            
            # Get validation result if available
            val_result = None
            if result_str := vuln.get("validation_result"):
                try:
                    val_result = ValidationResult(result_str)
                except ValueError:
                    pass
            
            # Handle multiple CVEs
            cves = vuln.get("cves", [])
            if not cves and (cve := vuln.get("cve")):
                cves = [cve]
            
            # Score each CVE separately
            if cves:
                for cve in cves:
                    scored_vuln = self.score_vulnerability(
                        target=target,
                        port=vuln.get("port"),
                        cve=cve,
                        service=vuln.get("service"),
                        validation_result=val_result,
                        asset_criticality=asset_crit,
                        module=vuln.get("module"),
                    )
                    scored.append(scored_vuln)
            else:
                # No CVE - score by service
                scored_vuln = self.score_vulnerability(
                    target=target,
                    port=vuln.get("port"),
                    cve=None,
                    service=vuln.get("service"),
                    validation_result=val_result,
                    asset_criticality=asset_crit,
                    module=vuln.get("module"),
                )
                scored.append(scored_vuln)
        
        # Sort by final score (descending)
        sorted_vulns = sorted(
            scored,
            key=lambda v: v.final_score,
            reverse=True
        )
        
        logger.info(
            "vulnerabilities_prioritized",
            total=len(sorted_vulns),
            critical=sum(1 for v in sorted_vulns if v.severity == SeverityLevel.CRITICAL),
            high=sum(1 for v in sorted_vulns if v.severity == SeverityLevel.HIGH),
        )
        
        return sorted_vulns
    
    def get_top_n(
        self,
        vulnerabilities: list[ScoredVulnerability],
        n: int = 10,
        min_severity: SeverityLevel = SeverityLevel.LOW,
    ) -> list[ScoredVulnerability]:
        """Get top N vulnerabilities at or above minimum severity."""
        severity_order = [
            SeverityLevel.CRITICAL,
            SeverityLevel.HIGH,
            SeverityLevel.MEDIUM,
            SeverityLevel.LOW,
            SeverityLevel.INFO,
        ]
        min_index = severity_order.index(min_severity)
        allowed = set(severity_order[:min_index + 1])
        
        filtered = [v for v in vulnerabilities if v.severity in allowed]
        return filtered[:n]
