"""
Report Generator

Generates vulnerability reports in multiple formats:
- JSON (machine-readable)
- CSV (spreadsheet-compatible)
- HTML (human-readable with Jinja2)
"""

import csv
import json
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.logger import get_logger
from src.scoring_engine import ScoredVulnerability, SeverityLevel

logger = get_logger(__name__)


class ReportGenerator:
    """
    Generates vulnerability reports in various formats.
    
    Supports:
    - JSON: Full data export
    - CSV: Spreadsheet import
    - HTML: Executive summary with Jinja2 templates
    """
    
    def __init__(
        self,
        template_dir: str | Path = "templates",
        output_dir: str | Path = "reports",
    ):
        self._template_dir = Path(template_dir)
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup Jinja2
        if self._template_dir.exists():
            self._jinja_env = Environment(
                loader=FileSystemLoader(str(self._template_dir)),
                autoescape=select_autoescape(["html", "xml"]),
            )
        else:
            self._jinja_env: Environment | None = None
    
    def generate_json(
        self,
        vulnerabilities: list[ScoredVulnerability],
        metadata: dict[str, Any] | None = None,
        filename: str | None = None,
    ) -> str:
        """
        Generate JSON report.
        
        Returns JSON string and optionally saves to file.
        """
        report = {
            "report_type": "vulnerability_scan",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
            "summary": self._generate_summary(vulnerabilities),
            "vulnerabilities": [v.to_dict() for v in vulnerabilities],
        }
        
        json_str = json.dumps(report, indent=2)
        
        if filename:
            output_path = self._output_dir / filename
            with open(output_path, "w") as f:
                f.write(json_str)
            logger.info("report_generated", format="json", path=str(output_path))
        
        return json_str
    
    def generate_csv(
        self,
        vulnerabilities: list[ScoredVulnerability],
        filename: str | None = None,
    ) -> str:
        """
        Generate CSV report.
        
        Returns CSV string and optionally saves to file.
        """
        output = StringIO()
        
        fieldnames = [
            "severity",
            "final_score",
            "target",
            "port",
            "cve",
            "service",
            "cvss",
            "exploit_probability",
            "validation_result",
            "module",
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for vuln in vulnerabilities:
            writer.writerow({
                "severity": vuln.severity.value,
                "final_score": round(vuln.final_score, 2),
                "target": vuln.target,
                "port": vuln.port or "",
                "cve": vuln.cve or "",
                "service": vuln.service or "",
                "cvss": vuln.cvss,
                "exploit_probability": round(vuln.exploit_probability, 2),
                "validation_result": vuln.validation_result.value if vuln.validation_result else "",
                "module": vuln.module or "",
            })
        
        csv_str = output.getvalue()
        
        if filename:
            output_path = self._output_dir / filename
            with open(output_path, "w") as f:
                f.write(csv_str)
            logger.info("report_generated", format="csv", path=str(output_path))
        
        return csv_str
    
    def generate_html(
        self,
        vulnerabilities: list[ScoredVulnerability],
        metadata: dict[str, Any] | None = None,
        filename: str | None = None,
        template_name: str = "report.html",
    ) -> str:
        """
        Generate HTML report using Jinja2 template.
        
        Returns HTML string and optionally saves to file.
        """
        if not self._jinja_env:
            # Fallback to basic HTML
            return self._generate_basic_html(vulnerabilities, metadata, filename)
        
        try:
            template = self._jinja_env.get_template(template_name)
        except Exception:
            return self._generate_basic_html(vulnerabilities, metadata, filename)
        
        context = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {},
            "summary": self._generate_summary(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "severity_levels": SeverityLevel,
        }
        
        html_str = template.render(**context)
        
        if filename:
            output_path = self._output_dir / filename
            with open(output_path, "w") as f:
                f.write(html_str)
            logger.info("report_generated", format="html", path=str(output_path))
        
        return html_str
    
    def _generate_basic_html(
        self,
        vulnerabilities: list[ScoredVulnerability],
        metadata: dict[str, Any] | None,
        filename: str | None,
    ) -> str:
        """Generate basic HTML without template."""
        summary = self._generate_summary(vulnerabilities)
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4a4a4a; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <p>Generated: {datetime.now(timezone.utc).isoformat()}</p>
    
    <h2>Summary</h2>
    <ul>
        <li>Total Vulnerabilities: {summary['total']}</li>
        <li class="critical">Critical: {summary['by_severity']['critical']}</li>
        <li class="high">High: {summary['by_severity']['high']}</li>
        <li class="medium">Medium: {summary['by_severity']['medium']}</li>
        <li class="low">Low: {summary['by_severity']['low']}</li>
    </ul>
    
    <h2>Vulnerabilities</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Score</th>
            <th>Target</th>
            <th>Port</th>
            <th>CVE</th>
            <th>Service</th>
            <th>CVSS</th>
        </tr>
"""
        
        for vuln in vulnerabilities:
            severity_class = vuln.severity.value
            html += f"""        <tr>
            <td class="{severity_class}">{vuln.severity.value.upper()}</td>
            <td>{vuln.final_score:.2f}</td>
            <td>{vuln.target}</td>
            <td>{vuln.port or '-'}</td>
            <td>{vuln.cve or '-'}</td>
            <td>{vuln.service or '-'}</td>
            <td>{vuln.cvss}</td>
        </tr>
"""
        
        html += """    </table>
</body>
</html>"""
        
        if filename:
            output_path = self._output_dir / filename
            with open(output_path, "w") as f:
                f.write(html)
            logger.info("report_generated", format="html", path=str(output_path))
        
        return html
    
    def _generate_summary(
        self,
        vulnerabilities: list[ScoredVulnerability]
    ) -> dict[str, Any]:
        """Generate summary statistics."""
        by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        
        targets = set()
        cves = set()
        
        for vuln in vulnerabilities:
            by_severity[vuln.severity.value] += 1
            targets.add(vuln.target)
            if vuln.cve:
                cves.add(vuln.cve)
        
        return {
            "total": len(vulnerabilities),
            "by_severity": by_severity,
            "unique_targets": len(targets),
            "unique_cves": len(cves),
            "exploitable": sum(
                1 for v in vulnerabilities
                if v.validation_result and v.validation_result.value == "vulnerable"
            ),
        }
    
    def generate_all(
        self,
        vulnerabilities: list[ScoredVulnerability],
        metadata: dict[str, Any] | None = None,
        base_filename: str = "scan_report",
    ) -> dict[str, str]:
        """
        Generate reports in all formats.
        
        Returns dict of format -> output path.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        outputs = {}
        
        # JSON
        json_file = f"{base_filename}_{timestamp}.json"
        self.generate_json(vulnerabilities, metadata, json_file)
        outputs["json"] = str(self._output_dir / json_file)
        
        # CSV
        csv_file = f"{base_filename}_{timestamp}.csv"
        self.generate_csv(vulnerabilities, csv_file)
        outputs["csv"] = str(self._output_dir / csv_file)
        
        # HTML
        html_file = f"{base_filename}_{timestamp}.html"
        self.generate_html(vulnerabilities, metadata, html_file)
        outputs["html"] = str(self._output_dir / html_file)
        
        logger.info(
            "all_reports_generated",
            base_filename=base_filename,
            outputs=outputs
        )
        
        return outputs
