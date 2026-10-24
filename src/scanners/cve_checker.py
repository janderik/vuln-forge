"""CVE checker with local DB and optional CIRCL API enrichment."""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import quote

import httpx

from src.db.cve_cache import CVECache
from src.scanners.base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)

CIRCL_API_BASE = "https://cve.circl.lu/api/cve"


def _parse_version(version_str: str | None) -> tuple[int, ...]:
    if not version_str:
        return (0,)
    parts = []
    for part in version_str.replace("p", ".").split("."):
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def _version_in_range(
    version: str | None, version_start: str, version_end: str
) -> bool:
    if not version:
        return True
    v = _parse_version(version)
    vs = _parse_version(version_start) if version_start else (0,)
    ve = _parse_version(version_end) if version_end else (999999,)
    return vs <= v <= ve


class CVEChecker(BaseScanner):
    def __init__(
        self,
        timeout: float = 10.0,
        max_concurrency: int = 50,
        use_circl_api: bool = False,
    ):
        super().__init__(timeout, max_concurrency)
        self.cache = CVECache()
        self.use_circl_api = use_circl_api
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                verify=False,
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def scan(
        self,
        target: str,
        services: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> ScanResult:
        findings: list[dict[str, Any]] = []

        if services is None:
            services = kwargs.get("findings", [])

        for svc in services:
            product = svc.get("product") or svc.get("service", "")
            version = svc.get("version")
            port = svc.get("port", 0)

            if not product:
                continue

            results = self.cache.lookup(product, version)

            for entry in results:
                if _version_in_range(version, entry.get("version_start", ""), entry.get("version_end", "")):
                    findings.append({
                        "type": "cve_match",
                        "severity": entry.get("severity", "medium"),
                        "cve_id": entry["id"],
                        "port": port,
                        "product": product,
                        "version": version,
                        "description": entry.get("description", ""),
                        "remediation": f"Upgrade {product} to a version newer than {entry.get('version_end', 'the current version')}",
                    })

            if self.use_circl_api and version:
                await self._check_circl(product, version, port, findings)

        result = ScanResult(
            target=target,
            scanner_name="cve_checker",
            severity="high" if findings else "info",
            findings=findings,
            raw_data={"services_checked": len(services)},
        )
        return result

    async def _check_circl(
        self,
        product: str,
        version: str,
        port: int,
        findings: list,
    ) -> None:
        try:
            client = await self._get_client()
            search_query = quote(f"{product} {version}")
            resp = await client.get(f"{CIRCL_API_BASE}/search/{search_query}")
            if resp.status_code != 200:
                return
            data = resp.json()
            if isinstance(data, list):
                for cve in data[:5]:
                    findings.append({
                        "type": "cve_match_circl",
                        "severity": cve.get("cvss", "unknown"),
                        "cve_id": cve.get("id", "unknown"),
                        "port": port,
                        "product": product,
                        "version": version,
                        "description": cve.get("summary", "")[:300],
                        "remediation": "Apply vendor patch or upgrade to latest version",
                        "source": "circl",
                    })
        except (httpx.RequestError, json.JSONDecodeError) as e:
            logger.debug("CIRCL API lookup failed for %s %s: %s", product, version, e)
