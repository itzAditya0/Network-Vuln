"""
Prometheus Metrics

Exposes metrics for monitoring:
- Scan duration
- Vulnerabilities found
- Validation success rate
- Queue depth
- Error rates
"""

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    Info,
    start_http_server,
)

from src.logger import get_logger

logger = get_logger(__name__)

# Cardinality limit - avoid high-cardinality labels
MAX_LABEL_CARDINALITY = 100

# === Histograms ===

scan_duration = Histogram(
    "vulnscanner_scan_duration_seconds",
    "Time spent on Nmap scans",
    ["scan_type"],
    buckets=[10, 30, 60, 120, 300, 600, 1200],
)

validation_duration = Histogram(
    "vulnscanner_validation_duration_seconds",
    "Time spent on Metasploit validation",
    ["module_type"],
    buckets=[5, 15, 30, 60, 120],
)

# === Counters ===

vulnerabilities_found = Counter(
    "vulnscanner_vulnerabilities_total",
    "Total vulnerabilities discovered",
    ["severity"],
)

scans_completed = Counter(
    "vulnscanner_scans_completed_total",
    "Total scans completed",
    ["status"],  # success, failed, timeout
)

validations_completed = Counter(
    "vulnscanner_validations_completed_total",
    "Total Metasploit validations",
    ["result"],  # vulnerable, not_vulnerable, unknown, error, blocked
)

errors_total = Counter(
    "vulnscanner_errors_total",
    "Total errors by module",
    ["module"],
)

# === Gauges ===

active_scans = Gauge(
    "vulnscanner_active_scans",
    "Currently running scans",
)

queue_depth = Gauge(
    "vulnscanner_queue_depth",
    "Tasks waiting in queue",
    ["queue_type"],  # pending, dead_letter
)

worker_count = Gauge(
    "vulnscanner_workers",
    "Active worker count",
)

# === Info ===

scanner_info = Info(
    "vulnscanner",
    "Scanner version and configuration",
)


class MetricsCollector:
    """
    Collects and exposes Prometheus metrics.
    
    Enforces cardinality limits to prevent metric explosion.
    """
    
    def __init__(self, port: int = 9090):
        self._port = port
        self._started = False
        self._label_counts: dict[str, set] = {}
    
    def start_server(self) -> None:
        """Start Prometheus HTTP server."""
        if self._started:
            return
        
        start_http_server(self._port)
        self._started = True
        logger.info("metrics_server_started", port=self._port)
    
    def _check_cardinality(self, metric_name: str, label_value: str) -> str:
        """Enforce cardinality limit on labels."""
        if metric_name not in self._label_counts:
            self._label_counts[metric_name] = set()
        
        if len(self._label_counts[metric_name]) >= MAX_LABEL_CARDINALITY:
            return "other"  # Bucket overflow into 'other'
        
        self._label_counts[metric_name].add(label_value)
        return label_value
    
    def record_scan(
        self,
        duration: float,
        scan_type: str,
        success: bool,
    ) -> None:
        """Record scan metrics."""
        scan_type = self._check_cardinality("scan_type", scan_type)
        scan_duration.labels(scan_type=scan_type).observe(duration)
        
        status = "success" if success else "failed"
        scans_completed.labels(status=status).inc()
    
    def record_vulnerability(self, severity: str) -> None:
        """Record vulnerability discovery."""
        severity = self._check_cardinality("severity", severity)
        vulnerabilities_found.labels(severity=severity).inc()
    
    def record_validation(
        self,
        duration: float,
        module_type: str,
        result: str,
    ) -> None:
        """Record Metasploit validation metrics."""
        module_type = self._check_cardinality("module_type", module_type)
        result = self._check_cardinality("result", result)
        
        validation_duration.labels(module_type=module_type).observe(duration)
        validations_completed.labels(result=result).inc()
    
    def record_error(self, module: str) -> None:
        """Record error occurrence."""
        module = self._check_cardinality("module", module)
        errors_total.labels(module=module).inc()
    
    def set_active_scans(self, count: int) -> None:
        """Update active scan count."""
        active_scans.set(count)
    
    def set_queue_depth(self, pending: int, dead_letter: int) -> None:
        """Update queue depths."""
        queue_depth.labels(queue_type="pending").set(pending)
        queue_depth.labels(queue_type="dead_letter").set(dead_letter)
    
    def set_worker_count(self, count: int) -> None:
        """Update worker count."""
        worker_count.set(count)
    
    def set_info(self, version: str, environment: str) -> None:
        """Set scanner info."""
        scanner_info.info({
            "version": version,
            "environment": environment,
        })


# Singleton instance
_collector: MetricsCollector | None = None


def get_metrics_collector(port: int = 9090) -> MetricsCollector:
    """Get singleton MetricsCollector instance."""
    global _collector
    if _collector is None:
        _collector = MetricsCollector(port=port)
    return _collector
