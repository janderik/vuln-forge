"""Tests for scanner modules."""

from __future__ import annotations

import pytest

from src.scanners.base import ScanResult
from src.scanners.cve_checker import CVEChecker
from src.scanners.port_scanner import PortScanner
from src.scanners.service_detector import ServiceDetector, parse_banner
from src.scanners.web_vuln import WebVulnScanner


class TestScanResult:
    def test_to_dict(self) -> None:
        r = ScanResult(target="127.0.0.1", scanner_name="test", severity="high")
        d = r.to_dict()
        assert d["target"] == "127.0.0.1"
        assert d["scanner"] == "test"
        assert d["severity"] == "high"
        assert d["findings"] == []

    def test_to_dict_with_findings(self) -> None:
        r = ScanResult(
            target="example.com",
            scanner_name="test",
            findings=[{"type": "test", "severity": "low"}],
        )
        d = r.to_dict()
        assert len(d["findings"]) == 1
        assert d["findings"][0]["type"] == "test"


class TestPortScanner:
    @pytest.mark.asyncio
    async def test_scan_localhost(self) -> None:
        scanner = PortScanner(timeout=2.0)
        result = await scanner.scan("127.0.0.1", ports=[22, 80, 443])
        assert result.target == "127.0.0.1"
        assert isinstance(result.findings, list)
        assert result.scanner_name == "port_scanner"

    @pytest.mark.asyncio
    async def test_syn_scan_fallback(self) -> None:
        scanner = PortScanner(timeout=2.0)
        result = await scanner.scan("127.0.0.1", ports=[22, 80], scan_type="syn")
        assert result.scanner_name == "port_scanner"

    @pytest.mark.asyncio
    async def test_scan_invalid_host(self) -> None:
        scanner = PortScanner(timeout=1.0)
        result = await scanner.scan("192.0.2.1", ports=[22])
        assert len(result.findings) == 0


class TestServiceDetector:
    def test_parse_apache_banner(self) -> None:
        info = parse_banner("Apache/2.4.41 (Ubuntu) Server at localhost")
        assert info["product"] == "Apache"
        assert info["version"] == "2.4.41"

    def test_parse_nginx_banner(self) -> None:
        info = parse_banner("nginx/1.20.1")
        assert info["product"] == "nginx"
        assert info["version"] == "1.20.1"

    def test_parse_ssh_banner(self) -> None:
        info = parse_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        assert "OpenSSH" in info.get("product", "") or info.get("product") == "OpenSSH"
        assert info["version"] == "2.0"

    def test_parse_iis_banner(self) -> None:
        info = parse_banner("Microsoft-IIS/10.0")
        assert info["product"] == "IIS"
        assert info["version"] == "10.0"

    def test_parse_unknown_banner(self) -> None:
        info = parse_banner("220 ProFTPD 1.3.5 Server ready")
        assert info["banner"] is not None

    @pytest.mark.asyncio
    async def test_scan_localhost(self) -> None:
        detector = ServiceDetector(timeout=2.0)
        result = await detector.scan("127.0.0.1", ports=[22, 80])
        assert result.target == "127.0.0.1"
        assert result.scanner_name == "service_detector"


class TestWebVulnScanner:
    @pytest.mark.asyncio
    async def test_scan_localhost(self) -> None:
        scanner = WebVulnScanner(timeout=2.0)
        try:
            result = await scanner.scan("http://127.0.0.1:1", test_xss=False, test_sqli=False, test_dirs=False, test_headers=False)
            assert result.target == "http://127.0.0.1:1"
        finally:
            await scanner.close()

    @pytest.mark.asyncio
    async def test_scan_with_headers(self) -> None:
        scanner = WebVulnScanner(timeout=2.0)
        try:
            result = await scanner.scan(
                "http://127.0.0.1:1",
                test_xss=False,
                test_sqli=False,
                test_dirs=False,
                test_headers=True,
            )
            assert result.target == "http://127.0.0.1:1"
        finally:
            await scanner.close()


class TestCVEChecker:
    def test_local_db_lookup_apache(self) -> None:
        checker = CVEChecker()
        results = checker.cache.lookup("Apache", "2.4.49")
        assert len(results) > 0
        assert any("CVE-2022-26377" in r["id"] for r in results)

    def test_local_db_lookup_nginx(self) -> None:
        checker = CVEChecker()
        results = checker.cache.lookup("nginx", "1.20.0")
        assert len(results) > 0

    def test_local_db_lookup_openssh(self) -> None:
        checker = CVEChecker()
        results = checker.cache.lookup("OpenSSH", "8.9p1")
        assert len(results) > 0

    def test_local_db_lookup_nonexistent(self) -> None:
        checker = CVEChecker()
        results = checker.cache.lookup("NonexistentProduct")
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_scan_with_services(self) -> None:
        checker = CVEChecker()
        services = [
            {"product": "Apache", "version": "2.4.49", "port": 80},
        ]
        result = await checker.scan("127.0.0.1", services=services)
        assert len(result.findings) > 0
        assert any(f["cve_id"] == "CVE-2022-26377" for f in result.findings)
