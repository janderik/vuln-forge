"""Tests for report generation."""

from __future__ import annotations

import json

from src.report.generator import ReportGenerator
from src.scanners.base import ScanResult


class TestReportGenerator:
    def test_html_generation(self) -> None:
        gen = ReportGenerator()
        results = [
            ScanResult(
                target="test.local",
                scanner_name="port_scanner",
                severity="medium",
                findings=[
                    {"type": "open_port", "severity": "medium", "port": 22, "detail": "SSH port open"},
                ],
            ),
            ScanResult(
                target="test.local",
                scanner_name="cve_checker",
                severity="high",
                findings=[
                    {
                        "type": "cve_match",
                        "severity": "high",
                        "cve_id": "CVE-2024-1234",
                        "detail": "Test vulnerability",
                        "description": "A test CVE",
                    },
                ],
            ),
        ]
        html = gen.generate(results, "html")
        assert "<!DOCTYPE html>" in html
        assert "test.local" in html
        assert "CVE-2024-1234" in html
        assert "medium" in html
        assert "high" in html

    def test_json_generation(self) -> None:
        gen = ReportGenerator()
        results = [
            ScanResult(
                target="test.local",
                scanner_name="port_scanner",
                severity="info",
                findings=[{"type": "info", "severity": "info", "detail": "no issues"}],
            ),
        ]
        data = gen.generate(results, "json")
        parsed = json.loads(data)
        assert "vulnforge_report" in parsed
        assert "results" in parsed["vulnforge_report"]
        assert len(parsed["vulnforge_report"]["results"]) == 1
        assert parsed["vulnforge_report"]["results"][0]["target"] == "test.local"

    def test_empty_results(self) -> None:
        gen = ReportGenerator()
        html = gen.generate([], "html")
        assert "<!DOCTYPE html>" in html
        json_out = gen.generate([], "json")
        parsed = json.loads(json_out)
        assert len(parsed["vulnforge_report"]["results"]) == 0

    def test_html_with_all_severities(self) -> None:
        gen = ReportGenerator()
        results = [
            ScanResult(
                target="target.test",
                scanner_name="multi_scan",
                severity="critical",
                findings=[
                    {"type": "critical_issue", "severity": "critical", "detail": "Critical finding"},
                    {"type": "high_issue", "severity": "high", "detail": "High finding"},
                    {"type": "medium_issue", "severity": "medium", "detail": "Medium finding"},
                    {"type": "low_issue", "severity": "low", "detail": "Low finding"},
                    {"type": "info_issue", "severity": "info", "detail": "Info finding"},
                ],
            ),
        ]
        html = gen.generate(results, "html")
        assert "critical" in html
        assert "high" in html
        assert "medium" in html
        assert "low" in html
        assert "info" in html
        assert "5" in html  # 5 total findings
