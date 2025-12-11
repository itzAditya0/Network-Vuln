"""
Performance Tests for Network Vulnerability Scanner

Tests scan pipeline performance with 100 endpoints:
- Latency: Total pipeline execution time
- Memory: Peak memory usage during scan
- CPU: CPU time consumed

Run: pytest tests/perf/test_performance.py -v
"""

import asyncio
import csv
import os
import resource
import time
import tracemalloc
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.endpoint_manager import Endpoint, EndpointManager
from src.logger import AuditLogger
from src.nmap_controller import NmapController, ScanResult, ScanType
from src.pipeline import PipelineConfig, ScanPipeline
from src.cve_mapper import CVEMapper
from src.scoring_engine import ScoringEngine


@dataclass
class PerformanceMetrics:
    """Container for performance metrics."""
    endpoint_count: int
    latency_seconds: float
    peak_memory_mb: float
    cpu_time_seconds: float
    timestamp: str


def generate_mock_endpoints(count: int) -> list[Endpoint]:
    """Generate mock endpoints for performance testing."""
    return [
        Endpoint(
            ip=f"10.0.{i // 256}.{i % 256}",
            hostname=f"server-{i:04d}",
            asset_criticality=1.0 + (i % 3),
            environment="test"
        )
        for i in range(count)
    ]


def generate_mock_scan_result(target_ip: str) -> ScanResult:
    """Generate a mock scan result for an endpoint."""
    from src.nmap_controller import PortResult
    
    return ScanResult(
        target=target_ip,
        state="up",
        ports=[
            PortResult(port=22, protocol="tcp", state="open", service="ssh", version="OpenSSH 8.0"),
            PortResult(port=80, protocol="tcp", state="open", service="http", version="nginx 1.18"),
            PortResult(port=443, protocol="tcp", state="open", service="https", version="nginx 1.18"),
        ],
        os_matches=[{"name": "Linux 5.x", "accuracy": 95}],
        scan_time=datetime.now(timezone.utc),
        duration_seconds=2.5,
    )


def write_metrics_csv(metrics: PerformanceMetrics, output_path: Path) -> None:
    """Write metrics to CSV file for reproducibility."""
    file_exists = output_path.exists()
    
    with open(output_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "timestamp", "endpoint_count", "latency_seconds",
            "peak_memory_mb", "cpu_time_seconds"
        ])
        
        if not file_exists:
            writer.writeheader()
        
        writer.writerow({
            "timestamp": metrics.timestamp,
            "endpoint_count": metrics.endpoint_count,
            "latency_seconds": round(metrics.latency_seconds, 3),
            "peak_memory_mb": round(metrics.peak_memory_mb, 2),
            "cpu_time_seconds": round(metrics.cpu_time_seconds, 3),
        })


class TestScanPerformance:
    """Performance tests for scan pipeline."""
    
    @pytest.fixture
    def mock_audit_logger(self):
        """Audit logger with test key."""
        return AuditLogger(hmac_key=b"perf-test-key")
    
    @pytest.fixture
    def mock_nmap_controller(self):
        """Mock Nmap controller that returns results quickly."""
        controller = MagicMock(spec=NmapController)
        
        async def mock_async_scan(targets, scan_type=None, max_concurrent=5):
            # Simulate scanning delay (reduced for performance testing)
            await asyncio.sleep(0.01 * len(targets))
            return [generate_mock_scan_result(ip) for ip in targets]
        
        controller.async_scan = AsyncMock(side_effect=mock_async_scan)
        return controller
    
    @pytest.fixture
    def mock_cve_mapper(self):
        """Mock CVE mapper."""
        mapper = MagicMock(spec=CVEMapper)
        mapper.map_scan_results.return_value = [
            {
                "target": "10.0.0.1",
                "port": 22,
                "service": "ssh",
                "cves": ["CVE-2021-28041"],
                "recommended_modules": [],
            }
        ]
        return mapper
    
    @pytest.fixture
    def performance_pipeline(self, mock_nmap_controller, mock_cve_mapper, mock_audit_logger):
        """Create pipeline for performance testing."""
        endpoint_manager = EndpointManager()
        
        return ScanPipeline(
            endpoint_manager=endpoint_manager,
            nmap_controller=mock_nmap_controller,
            cve_mapper=mock_cve_mapper,
            scoring_engine=ScoringEngine(),
            config=PipelineConfig(
                validate_exploits=False,  # Skip MSF validation for perf tests
                generate_reports=False,   # Skip report generation
            ),
        )
    
    @pytest.mark.asyncio
    async def test_scan_100_endpoints_latency(self, performance_pipeline):
        """
        Test pipeline latency with 100 endpoints.
        
        Acceptance: Complete within reasonable time (<30s for mocked scan).
        """
        endpoints = generate_mock_endpoints(100)
        
        # Start timing
        start_time = time.perf_counter()
        
        result = await performance_pipeline.run(
            user_id="perf-test",
            ticket_id="VULN-PERF",
            targets=endpoints,
        )
        
        end_time = time.perf_counter()
        latency = end_time - start_time
        
        # Assertions
        assert result.targets_scanned == 100
        assert latency < 30.0, f"Pipeline took {latency:.2f}s, expected < 30s"
        
        print(f"\n✓ 100 endpoints scanned in {latency:.3f}s")
    
    @pytest.mark.asyncio
    async def test_memory_pressure(self, performance_pipeline):
        """
        Test memory usage under load with 100 endpoints.
        
        Acceptance: Peak memory delta < 500MB for mocked scan.
        """
        endpoints = generate_mock_endpoints(100)
        
        # Start memory tracking
        tracemalloc.start()
        initial_memory = tracemalloc.get_traced_memory()[0]
        
        result = await performance_pipeline.run(
            user_id="perf-test",
            ticket_id="VULN-PERF",
            targets=endpoints,
        )
        
        # Get peak memory
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        
        peak_delta_mb = (peak - initial_memory) / (1024 * 1024)
        
        # Assertions
        assert result.targets_scanned == 100
        assert peak_delta_mb < 500, f"Peak memory delta {peak_delta_mb:.2f}MB, expected < 500MB"
        
        print(f"\n✓ Peak memory delta: {peak_delta_mb:.2f}MB")
    
    @pytest.mark.asyncio
    async def test_cpu_utilization(self, performance_pipeline):
        """
        Test CPU time usage with 100 endpoints.
        
        Records CPU time for benchmarking.
        """
        endpoints = generate_mock_endpoints(100)
        
        # Get initial CPU time
        initial_usage = resource.getrusage(resource.RUSAGE_SELF)
        initial_cpu = initial_usage.ru_utime + initial_usage.ru_stime
        
        result = await performance_pipeline.run(
            user_id="perf-test",
            ticket_id="VULN-PERF",
            targets=endpoints,
        )
        
        # Get final CPU time
        final_usage = resource.getrusage(resource.RUSAGE_SELF)
        final_cpu = final_usage.ru_utime + final_usage.ru_stime
        cpu_time = final_cpu - initial_cpu
        
        # Assertions
        assert result.targets_scanned == 100
        
        print(f"\n✓ CPU time: {cpu_time:.3f}s")
    
    @pytest.mark.asyncio
    async def test_full_performance_benchmark(self, performance_pipeline):
        """
        Complete performance benchmark with all metrics.
        
        Outputs CSV report to reports/ directory.
        """
        endpoints = generate_mock_endpoints(100)
        
        # Start all measurements
        tracemalloc.start()
        initial_usage = resource.getrusage(resource.RUSAGE_SELF)
        initial_cpu = initial_usage.ru_utime + initial_usage.ru_stime
        start_time = time.perf_counter()
        
        # Run pipeline
        result = await performance_pipeline.run(
            user_id="perf-test",
            ticket_id="VULN-PERF",
            targets=endpoints,
        )
        
        # Collect metrics
        end_time = time.perf_counter()
        latency = end_time - start_time
        
        final_usage = resource.getrusage(resource.RUSAGE_SELF)
        final_cpu = final_usage.ru_utime + final_usage.ru_stime
        cpu_time = final_cpu - initial_cpu
        
        _, peak_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peak_mb = peak_memory / (1024 * 1024)
        
        # Create metrics object
        metrics = PerformanceMetrics(
            endpoint_count=100,
            latency_seconds=latency,
            peak_memory_mb=peak_mb,
            cpu_time_seconds=cpu_time,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        
        # Write to CSV
        reports_dir = Path(__file__).parent.parent.parent / "reports"
        reports_dir.mkdir(exist_ok=True)
        csv_path = reports_dir / "performance_metrics.csv"
        write_metrics_csv(metrics, csv_path)
        
        # Assertions
        assert result.targets_scanned == 100
        
        print(f"\n{'='*50}")
        print("Performance Benchmark Results")
        print(f"{'='*50}")
        print(f"Endpoints:    {metrics.endpoint_count}")
        print(f"Latency:      {metrics.latency_seconds:.3f}s")
        print(f"Peak Memory:  {metrics.peak_memory_mb:.2f}MB")
        print(f"CPU Time:     {metrics.cpu_time_seconds:.3f}s")
        print(f"CSV Report:   {csv_path}")
        print(f"{'='*50}")
