"""Web vulnerability scanner for XSS, SQLi, directory busting, and header analysis."""

from __future__ import annotations

import asyncio
import os
import re
from typing import Any
from urllib.parse import urljoin

import httpx

from src.scanners.base import BaseScanner, ScanResult

XSS_INDICATORS = [
    re.compile(r"<script>alert", re.IGNORECASE),
    re.compile(r"<img\s+src\s*=\s*x\s+onerror\s*=", re.IGNORECASE),
    re.compile(r"<svg\s+onload\s*=", re.IGNORECASE),
]

SQLI_INDICATORS = [
    re.compile(r"SQL syntax.*MySQL", re.IGNORECASE),
    re.compile(r"Warning.*mysql_.*", re.IGNORECASE),
    re.compile(r"Unclosed quotation mark", re.IGNORECASE),
    re.compile(r"Microsoft OLE DB.*SQL Server", re.IGNORECASE),
    re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
    re.compile(r"ORA-[0-9]{5}", re.IGNORECASE),
    re.compile(r"SQLite.*Exception", re.IGNORECASE),
    re.compile(r"Division by zero.*SQL", re.IGNORECASE),
    re.compile(r"you have an error in your sql", re.IGNORECASE),
    re.compile(r"unknown column", re.IGNORECASE),
]

SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "'; DROP TABLE users--",
    "\" OR \"1\"=\"1",
    "1 AND 1=1",
    "1 AND 1=2",
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '00:00:05'--",
]

COMMON_DIRS = [
    "admin", "login", "wp-admin", "administrator", "backup",
    "config", "css", "js", "images", "img", "uploads", "files",
    "api", "v1", "v2", "graphql", ".git", ".env", "robots.txt",
    "sitemap.xml", "crossdomain.xml", "phpinfo.php", "test.php",
    "dashboard", "manager", "console", "swagger", "docs",
]

INSECURE_HEADERS = {
    "strict-transport-security": "missing HSTS header",
    "x-content-type-options": "missing X-Content-Type-Options",
    "x-frame-options": "missing X-Frame-Options",
    "x-xss-protection": "missing X-XSS-Protection",
    "content-security-policy": "missing Content-Security-Policy",
}


def load_xss_payloads() -> list[str]:
    payloads_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "data", "payloads", "xss_payloads.txt"
    )
    try:
        with open(payloads_path, encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]


class WebVulnScanner(BaseScanner):
    def __init__(self, timeout: float = 10.0, max_concurrency: int = 50):
        super().__init__(timeout, max_concurrency)
        self.xss_payloads = load_xss_payloads()
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=True,
                verify=False,
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def scan(
        self,
        target: str,
        test_xss: bool = True,
        test_sqli: bool = True,
        test_dirs: bool = True,
        test_headers: bool = True,
        **kwargs: Any,
    ) -> ScanResult:
        findings: list[dict[str, Any]] = []
        client = await self._get_client()
        target = target.rstrip("/")

        self.logger.info("Web vulnerability scan started on %s", target)

        tasks = []
        if test_headers:
            tasks.append(self._check_headers(client, target, findings))
        if test_dirs:
            tasks.append(self._check_directories(client, target, findings))
        if test_xss:
            tasks.append(self._check_xss(client, target, findings))
        if test_sqli:
            tasks.append(self._check_sqli(client, target, findings))

        await asyncio.gather(*tasks)

        result = ScanResult(
            target=target,
            scanner_name="web_vuln",
            severity="high" if findings else "info",
            findings=findings,
        )
        return result

    async def _check_headers(
        self,
        client: httpx.AsyncClient,
        target: str,
        findings: list,
    ) -> None:
        try:
            resp = await client.get(target)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            for hdr, msg in INSECURE_HEADERS.items():
                if hdr not in headers:
                    findings.append({
                        "type": "missing_header",
                        "severity": "low",
                        "detail": msg,
                        "header": hdr,
                    })
            if "server" in headers:
                findings.append({
                    "type": "server_banner",
                    "severity": "low",
                    "detail": f"Server header discloses: {headers['server']}",
                    "header": "Server",
                    "value": headers["server"],
                })
            cookies = resp.headers.get_list("set-cookie")
            for c in cookies:
                if "httponly" not in c.lower():
                    findings.append({
                        "type": "insecure_cookie",
                        "severity": "medium",
                        "detail": "Cookie missing HttpOnly flag",
                        "cookie": c.split(";")[0],
                    })
                if "secure" not in c.lower():
                    findings.append({
                        "type": "insecure_cookie",
                        "severity": "medium",
                        "detail": "Cookie missing Secure flag",
                        "cookie": c.split(";")[0],
                    })
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            self.logger.debug("Header check failed for %s: %s", target, e)

    async def _check_directories(
        self,
        client: httpx.AsyncClient,
        target: str,
        findings: list,
    ) -> None:
        sem = asyncio.Semaphore(self.max_concurrency)

        async def _check(path: str) -> None:
            async with sem:
                url = urljoin(target + "/", path)
                try:
                    resp = await client.get(url)
                    if resp.status_code in (200, 401, 403):
                        findings.append({
                            "type": "exposed_directory",
                            "severity": "medium" if resp.status_code == 200 else "low",
                            "url": url,
                            "status": resp.status_code,
                            "detail": f"Accessible path: {url}",
                        })
                except httpx.RequestError:
                    pass

        await asyncio.gather(*[_check(p) for p in COMMON_DIRS])

    async def _check_xss(
        self,
        client: httpx.AsyncClient,
        target: str,
        findings: list,
    ) -> None:
        sem = asyncio.Semaphore(self.max_concurrency)

        async def _test(payload: str) -> None:
            async with sem:
                params = {"q": payload, "search": payload, "input": payload}
                try:
                    resp = await client.get(target, params=params)
                    body = resp.text
                    for indicator in XSS_INDICATORS:
                        if indicator.search(body):
                            findings.append({
                                "type": "reflected_xss",
                                "severity": "high",
                                "payload": payload[:80],
                                "parameter": list(params.keys())[0],
                                "detail": "Reflected XSS detected with parameter injection",
                                "evidence": indicator.pattern[:60],
                            })
                            return
                except httpx.RequestError:
                    pass

        await asyncio.gather(*[_test(p) for p in self.xss_payloads[:6]])

    async def _check_sqli(
        self,
        client: httpx.AsyncClient,
        target: str,
        findings: list,
    ) -> None:
        sem = asyncio.Semaphore(self.max_concurrency)

        async def _test(payload: str) -> None:
            async with sem:
                params = {"id": payload, "page": payload, "user": payload}
                try:
                    resp = await client.get(target, params=params)
                    body = resp.text
                    for indicator in SQLI_INDICATORS:
                        if indicator.search(body):
                            findings.append({
                                "type": "sql_injection",
                                "severity": "critical",
                                "payload": payload[:80],
                                "detail": f"SQL injection indicator matched: {indicator.pattern[:60]}",
                                "evidence": body[:200],
                            })
                            return
                except httpx.RequestError:
                    pass

        await asyncio.gather(*[_test(p) for p in SQLI_PAYLOADS])
