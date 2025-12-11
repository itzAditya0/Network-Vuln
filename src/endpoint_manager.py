"""
Endpoint Manager

Manages target endpoints for scanning:
- Load from file (CSV/JSON) or database
- Liveness checks
- CIDR aggregation for rate limiting
"""

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any

from src.logger import get_logger

logger = get_logger(__name__)


@dataclass
class Endpoint:
    """Represents a scanning target."""
    ip: str
    hostname: str | None = None
    port: int | None = None
    asset_criticality: float = 1.0  # Weight for scoring (0.0-3.0)
    owner: str | None = None
    environment: str = "production"  # production, staging, lab
    last_scan: datetime | None = None
    tags: list[str] = field(default_factory=list)
    
    @property
    def cidr_24(self) -> str:
        """Get /24 CIDR for rate limiting aggregation."""
        try:
            ip = IPv4Address(self.ip)
            network = IPv4Network(f"{ip}/24", strict=False)
            return str(network)
        except ValueError:
            return self.ip
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "port": self.port,
            "asset_criticality": self.asset_criticality,
            "owner": self.owner,
            "environment": self.environment,
            "last_scan": self.last_scan.isoformat() if self.last_scan else None,
            "tags": self.tags
        }


class EndpointManager:
    """
    Manages endpoint loading, validation, and storage.
    
    Supports:
    - CSV/JSON file input
    - PostgreSQL database backend
    - Liveness checking
    - CIDR aggregation
    """
    
    def __init__(self, db_connection: Any | None = None):
        self._endpoints: dict[str, Endpoint] = {}
        self._db = db_connection
    
    def load_from_file(self, path: str | Path) -> list[Endpoint]:
        """
        Load endpoints from CSV or JSON file.
        
        CSV format: ip,hostname,port,asset_criticality,owner,environment,tags
        JSON format: [{"ip": "...", ...}, ...]
        """
        path = Path(path)
        
        if path.suffix == ".csv":
            return self._load_csv(path)
        elif path.suffix == ".json":
            return self._load_json(path)
        else:
            raise ValueError(f"Unsupported file format: {path.suffix}")
    
    def _load_csv(self, path: Path) -> list[Endpoint]:
        """Load endpoints from CSV file."""
        endpoints = []
        
        with open(path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                endpoint = Endpoint(
                    ip=row["ip"],
                    hostname=row.get("hostname"),
                    port=int(row["port"]) if row.get("port") else None,
                    asset_criticality=float(row.get("asset_criticality", 1.0)),
                    owner=row.get("owner"),
                    environment=row.get("environment", "production"),
                    tags=row.get("tags", "").split(",") if row.get("tags") else []
                )
                endpoints.append(endpoint)
                self._endpoints[endpoint.ip] = endpoint
        
        logger.info("endpoints_loaded", source=str(path), count=len(endpoints))
        return endpoints
    
    def _load_json(self, path: Path) -> list[Endpoint]:
        """Load endpoints from JSON file."""
        with open(path, "r") as f:
            data = json.load(f)
        
        endpoints = []
        for item in data:
            endpoint = Endpoint(**item)
            endpoints.append(endpoint)
            self._endpoints[endpoint.ip] = endpoint
        
        logger.info("endpoints_loaded", source=str(path), count=len(endpoints))
        return endpoints
    
    def load_from_db(self) -> list[Endpoint]:
        """Load endpoints from database."""
        if not self._db:
            raise RuntimeError("Database connection not configured")
        
        # TODO: Implement with SQLAlchemy
        # cursor = self._db.execute("SELECT * FROM endpoints WHERE active = true")
        # ...
        
        logger.info("endpoints_loaded", source="database", count=len(self._endpoints))
        return list(self._endpoints.values())
    
    def get_endpoint(self, ip: str) -> Endpoint | None:
        """Get endpoint by IP address."""
        return self._endpoints.get(ip)
    
    def get_all(self) -> list[Endpoint]:
        """Get all loaded endpoints."""
        return list(self._endpoints.values())
    
    def get_by_environment(self, env: str) -> list[Endpoint]:
        """Filter endpoints by environment (production, staging, lab)."""
        return [e for e in self._endpoints.values() if e.environment == env]
    
    def get_by_cidr(self, cidr: str) -> list[Endpoint]:
        """Get all endpoints in a CIDR range."""
        try:
            network = IPv4Network(cidr, strict=False)
            return [
                e for e in self._endpoints.values()
                if IPv4Address(e.ip) in network
            ]
        except ValueError:
            return []
    
    def aggregate_by_cidr(self) -> dict[str, list[Endpoint]]:
        """Group endpoints by /24 CIDR for rate limiting."""
        result: dict[str, list[Endpoint]] = {}
        for endpoint in self._endpoints.values():
            cidr = endpoint.cidr_24
            if cidr not in result:
                result[cidr] = []
            result[cidr].append(endpoint)
        return result
    
    def check_liveness(self, ip: str, timeout: float = 2.0) -> bool:
        """
        Check if endpoint is alive via ICMP ping.
        
        Returns True if host responds, False otherwise.
        """
        import subprocess
        
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(int(timeout)), ip],
                capture_output=True,
                timeout=timeout + 1
            )
            alive = result.returncode == 0
            logger.debug("liveness_check", ip=ip, alive=alive)
            return alive
        except subprocess.TimeoutExpired:
            logger.debug("liveness_check", ip=ip, alive=False, reason="timeout")
            return False
        except Exception as e:
            logger.warning("liveness_check_error", ip=ip, error=str(e))
            return False
    
    def get_active_endpoints(self, check_liveness: bool = False) -> list[Endpoint]:
        """
        Get endpoints that are active.
        
        If check_liveness is True, performs ping check on each.
        """
        endpoints = self.get_all()
        
        if not check_liveness:
            return endpoints
        
        active = []
        for endpoint in endpoints:
            if self.check_liveness(endpoint.ip):
                active.append(endpoint)
        
        logger.info(
            "active_endpoints",
            total=len(endpoints),
            active=len(active)
        )
        return active
    
    def update_last_scan(self, ip: str) -> None:
        """Update last scan timestamp for endpoint."""
        if endpoint := self._endpoints.get(ip):
            endpoint.last_scan = datetime.now(timezone.utc)
            # TODO: Persist to database
