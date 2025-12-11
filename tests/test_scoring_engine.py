"""
Tests for Scoring Engine

Verifies threat prioritization logic.
"""

import pytest

from src.scoring_engine import SeverityLevel
from src.msf_validator import ValidationResult


class TestScoringEngine:
    """Tests for vulnerability scoring."""
    
    def test_exploitable_vuln_scores_high(self, scoring_engine):
        """Exploitable vulnerabilities should score highly."""
        raw, final, severity = scoring_engine.calculate_score(
            cve="CVE-2021-44228",
            validation_result=ValidationResult.VULNERABLE,
            asset_criticality=2.0,
            has_exploit_module=True,
        )
        
        assert final > 15.0  # High score
        assert severity == SeverityLevel.CRITICAL
    
    def test_not_vulnerable_scores_low(self, scoring_engine):
        """Non-exploitable vulnerabilities should score lower."""
        raw, final, severity = scoring_engine.calculate_score(
            cve="CVE-2021-44228",
            validation_result=ValidationResult.NOT_VULNERABLE,
            asset_criticality=1.0,
            has_exploit_module=True,
        )
        
        # Even with high CVSS, validation failure reduces score
        assert final < 3.0
    
    def test_unknown_validation_middle_score(self, scoring_engine):
        """Unknown validation should have middle probability."""
        _, final_unknown, _ = scoring_engine.calculate_score(
            cve="CVE-2017-0143",
            validation_result=ValidationResult.UNKNOWN,
        )
        
        _, final_vuln, _ = scoring_engine.calculate_score(
            cve="CVE-2017-0143",
            validation_result=ValidationResult.VULNERABLE,
        )
        
        assert final_unknown < final_vuln
    
    def test_no_exploit_module_increases_fp_factor(self, scoring_engine):
        """Missing exploit module should increase FP factor."""
        _, final_with_module, _ = scoring_engine.calculate_score(
            cve="CVE-2017-0143",
            has_exploit_module=True,
        )
        
        _, final_without, _ = scoring_engine.calculate_score(
            cve="CVE-2017-0143",
            has_exploit_module=False,
        )
        
        assert final_without < final_with_module
    
    def test_prioritize_returns_sorted(
        self, scoring_engine, sample_vulnerabilities
    ):
        """Prioritize should return vulns sorted by score."""
        scored = scoring_engine.prioritize(sample_vulnerabilities)
        
        # Should be sorted descending by final_score
        for i in range(len(scored) - 1):
            assert scored[i].final_score >= scored[i + 1].final_score
    
    def test_asset_criticality_affects_score(self, scoring_engine):
        """Higher asset criticality should increase score."""
        _, final_low, _ = scoring_engine.calculate_score(
            cve="CVE-2017-0143",
            asset_criticality=1.0,
        )
        
        _, final_high, _ = scoring_engine.calculate_score(
            cve="CVE-2017-0143",
            asset_criticality=3.0,
        )
        
        assert final_high > final_low


class TestSeverityClassification:
    """Tests for severity level classification."""
    
    @pytest.mark.parametrize("score,expected", [
        (10.0, SeverityLevel.CRITICAL),
        (9.0, SeverityLevel.CRITICAL),
        (8.0, SeverityLevel.HIGH),
        (7.0, SeverityLevel.HIGH),
        (5.0, SeverityLevel.MEDIUM),
        (4.0, SeverityLevel.MEDIUM),
        (2.0, SeverityLevel.LOW),
        (0.1, SeverityLevel.LOW),
        (0.0, SeverityLevel.INFO),
    ])
    def test_severity_thresholds(self, scoring_engine, score, expected):
        """Test severity classification thresholds."""
        severity = scoring_engine._classify_severity(score)
        assert severity == expected
