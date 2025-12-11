"""
CVE to Exploit Mapper

Maps discovered CVEs and service/version information to Metasploit modules.
Uses local metadata index for fast lookups.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ExploitModule:
    """Represents a Metasploit exploit module."""
    name: str
    fullname: str
    rank: str  # excellent, great, good, normal, average, low, manual
    cves: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    description: str = ""
    check_supported: bool = False  # Safe mode capability
    
    @property
    def rank_score(self) -> int:
        """Numeric rank for sorting (higher is better)."""
        ranks = {
            "excellent": 6,
            "great": 5,
            "good": 4,
            "normal": 3,
            "average": 2,
            "low": 1,
            "manual": 0,
        }
        return ranks.get(self.rank.lower(), 0)


@dataclass
class ServiceSignature:
    """Service signature for matching."""
    name: str
    version_pattern: str | None = None
    product: str | None = None
    
    def matches(
        self,
        service: str | None,
        version: str | None,
        product: str | None
    ) -> bool:
        """Check if signature matches discovered service."""
        if not service:
            return False
        
        # Service name match
        if self.name.lower() != service.lower():
            return False
        
        # Version pattern match (optional)
        if self.version_pattern and version:
            if not re.search(self.version_pattern, version, re.IGNORECASE):
                return False
        
        # Product match (optional)
        if self.product and product:
            if self.product.lower() not in product.lower():
                return False
        
        return True


class CVEMapper:
    """
    Maps CVEs and services to Metasploit modules.
    
    Uses a local metadata index built from Metasploit module database.
    """
    
    def __init__(self, index_path: str | Path | None = None):
        self._cve_index: dict[str, list[ExploitModule]] = {}
        self._service_index: dict[str, list[tuple[ServiceSignature, ExploitModule]]] = {}
        
        if index_path:
            self.load_index(index_path)
    
    def load_index(self, path: str | Path) -> None:
        """Load exploit index from JSON file."""
        path = Path(path)
        
        if not path.exists():
            logger.warning("exploit_index_not_found", path=str(path))
            return
        
        with open(path, "r") as f:
            data = json.load(f)
        
        # Build CVE index
        for module_data in data.get("modules", []):
            module = ExploitModule(
                name=module_data["name"],
                fullname=module_data.get("fullname", module_data["name"]),
                rank=module_data.get("rank", "normal"),
                cves=module_data.get("cves", []),
                platforms=module_data.get("platforms", []),
                references=module_data.get("references", []),
                description=module_data.get("description", ""),
                check_supported=module_data.get("check_supported", False),
            )
            
            for cve in module.cves:
                cve_upper = cve.upper()
                if cve_upper not in self._cve_index:
                    self._cve_index[cve_upper] = []
                self._cve_index[cve_upper].append(module)
            
            # Build service index
            for sig_data in module_data.get("service_signatures", []):
                sig = ServiceSignature(
                    name=sig_data["name"],
                    version_pattern=sig_data.get("version_pattern"),
                    product=sig_data.get("product"),
                )
                service_key = sig.name.lower()
                if service_key not in self._service_index:
                    self._service_index[service_key] = []
                self._service_index[service_key].append((sig, module))
        
        logger.info(
            "exploit_index_loaded",
            cves=len(self._cve_index),
            services=len(self._service_index)
        )
    
    def build_default_index(self) -> None:
        """
        Build a default index with common vulnerability mappings.
        
        In production, this should be replaced with the full
        Metasploit module database.
        """
        # Example: Common exploits for demo purposes
        common_modules = [
            ExploitModule(
                name="ms17_010_eternalblue",
                fullname="exploit/windows/smb/ms17_010_eternalblue",
                rank="excellent",
                cves=["CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145"],
                platforms=["windows"],
                check_supported=True,
            ),
            ExploitModule(
                name="apache_log4j_rce",
                fullname="exploit/multi/http/log4shell_header_injection",
                rank="excellent",
                cves=["CVE-2021-44228", "CVE-2021-45046"],
                platforms=["linux", "windows"],
                check_supported=True,
            ),
            ExploitModule(
                name="vsftpd_234_backdoor",
                fullname="exploit/unix/ftp/vsftpd_234_backdoor",
                rank="excellent",
                cves=["CVE-2011-2523"],
                platforms=["unix"],
                check_supported=True,
            ),
            ExploitModule(
                name="ssh_user_enumeration",
                fullname="auxiliary/scanner/ssh/ssh_enumusers",
                rank="normal",
                cves=["CVE-2018-15473"],
                platforms=["linux", "unix"],
                check_supported=True,
            ),
            ExploitModule(
                name="heartbleed",
                fullname="auxiliary/scanner/ssl/openssl_heartbleed",
                rank="good",
                cves=["CVE-2014-0160"],
                platforms=["linux", "unix", "windows"],
                check_supported=True,
            ),
        ]
        
        for module in common_modules:
            for cve in module.cves:
                cve_upper = cve.upper()
                if cve_upper not in self._cve_index:
                    self._cve_index[cve_upper] = []
                self._cve_index[cve_upper].append(module)
        
        # Service signatures
        service_mappings = [
            (
                ServiceSignature(name="ftp", version_pattern=r"vsftpd 2\.3\.4"),
                common_modules[2]  # vsftpd backdoor
            ),
            (
                ServiceSignature(name="ssh", version_pattern=r"OpenSSH.*[67]\."),
                common_modules[3]  # SSH enumeration
            ),
            (
                ServiceSignature(name="ssl", version_pattern=r"OpenSSL 1\.0\.1"),
                common_modules[4]  # Heartbleed
            ),
        ]
        
        for sig, module in service_mappings:
            service_key = sig.name.lower()
            if service_key not in self._service_index:
                self._service_index[service_key] = []
            self._service_index[service_key].append((sig, module))
        
        logger.info("default_exploit_index_built")
    
    def search_by_cve(self, cve_id: str) -> list[ExploitModule]:
        """
        Find exploit modules for a CVE ID.
        
        Returns modules sorted by rank (best first).
        """
        cve_upper = cve_id.upper()
        modules = self._cve_index.get(cve_upper, [])
        return sorted(modules, key=lambda m: m.rank_score, reverse=True)
    
    def search_by_service(
        self,
        service: str,
        version: str | None = None,
        product: str | None = None
    ) -> list[ExploitModule]:
        """
        Find exploit modules matching a service/version.
        
        Returns modules sorted by rank (best first).
        """
        service_key = service.lower()
        entries = self._service_index.get(service_key, [])
        
        matched = []
        for sig, module in entries:
            if sig.matches(service, version, product):
                matched.append(module)
        
        return sorted(
            list(set(matched)),  # Dedupe
            key=lambda m: m.rank_score,
            reverse=True
        )
    
    def map_scan_results(
        self,
        vulnerabilities: list[dict[str, Any]],
        ports: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Map scan results to exploit modules.
        
        Returns enriched vulnerability list with module recommendations.
        """
        results = []
        
        # Map CVEs
        for vuln in vulnerabilities:
            cves = vuln.get("cves", [])
            modules = []
            
            for cve in cves:
                for module in self.search_by_cve(cve):
                    modules.append({
                        "name": module.name,
                        "fullname": module.fullname,
                        "rank": module.rank,
                        "check_supported": module.check_supported,
                        "matched_cve": cve,
                    })
            
            results.append({
                **vuln,
                "recommended_modules": modules,
            })
        
        # Map services without specific CVEs
        for port in ports:
            service = port.get("service")
            version = port.get("version")
            product = port.get("product")
            
            if not service:
                continue
            
            modules = self.search_by_service(service, version, product)
            if modules:
                results.append({
                    "port": port.get("port"),
                    "service": service,
                    "version": version,
                    "cves": [],
                    "recommended_modules": [
                        {
                            "name": m.name,
                            "fullname": m.fullname,
                            "rank": m.rank,
                            "check_supported": m.check_supported,
                            "matched_service": service,
                        }
                        for m in modules
                    ],
                })
        
        return results
    
    def get_safe_modules_only(
        self,
        modules: list[ExploitModule]
    ) -> list[ExploitModule]:
        """Filter to only modules that support check mode."""
        return [m for m in modules if m.check_supported]
    
    def save_index(self, path: str | Path) -> None:
        """Save current index to JSON file."""
        modules = []
        seen = set()
        
        for module_list in self._cve_index.values():
            for module in module_list:
                if module.fullname not in seen:
                    modules.append({
                        "name": module.name,
                        "fullname": module.fullname,
                        "rank": module.rank,
                        "cves": module.cves,
                        "platforms": module.platforms,
                        "check_supported": module.check_supported,
                    })
                    seen.add(module.fullname)
        
        with open(path, "w") as f:
            json.dump({"modules": modules}, f, indent=2)
        
        logger.info("exploit_index_saved", path=str(path))
