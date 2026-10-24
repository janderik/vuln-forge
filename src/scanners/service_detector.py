"""Service detection and banner grabbing."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from src.scanners.base import BaseScanner, ScanResult

SERVICE_PROBES: dict[int, bytes] = {
    21: b"",
    22: b"",
    25: b"EHLO scan\r\n",
    80: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    110: b"",
    143: b"",
    443: b"",
    3306: b"",
    5432: b"",
    6379: b"PING\r\n",
    8080: b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8443: b"",
}

SERVICE_BANNER_PATTERNS: dict[str, list[re.Pattern]] = {
    "HTTP": [re.compile(r"HTTP/\d\.\d", re.IGNORECASE)],
    "SSH": [re.compile(r"SSH-\d\.\d", re.IGNORECASE)],
    "FTP": [re.compile(r"220.*FTP", re.IGNORECASE)],
    "SMTP": [re.compile(r"220.*SMTP", re.IGNORECASE)],
    "MySQL": [re.compile(r"mysql", re.IGNORECASE)],
    "PostgreSQL": [re.compile(r"PostgreSQL", re.IGNORECASE)],
    "Redis": [re.compile(r"redis", re.IGNORECASE), re.compile(r"\+PONG", re.IGNORECASE)],
    "OpenSSH": [re.compile(r"OpenSSH", re.IGNORECASE)],
    "Apache": [re.compile(r"Apache", re.IGNORECASE)],
    "Nginx": [re.compile(r"nginx", re.IGNORECASE)],
    "IIS": [re.compile(r"Microsoft-IIS", re.IGNORECASE)],
    "nginx": [re.compile(r"nginx", re.IGNORECASE)],
}


def parse_banner(banner: str, service_hint: str = "") -> dict[str, str]:
    info: dict[str, str] = {"banner": banner.strip()[:500]}
    b = banner

    m = re.search(r"SSH-(\d\.\d+)-(\S+)", b)
    if m:
        # "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3": 2.0 is the protocol, not the product.
        info["protocol"] = m.group(1)
        software = m.group(2)
        product, _, version = software.partition("_")
        info["product"] = product or "OpenSSH"
        if version:
            info["version"] = version
        return info

    m = re.search(r"(Apache)/([\d.]+)", b, re.IGNORECASE)
    if m:
        info["product"] = "Apache"
        info["version"] = m.group(2)
        return info

    m = re.search(r"(nginx)/([\d.]+)", b, re.IGNORECASE)
    if m:
        info["product"] = "nginx"
        info["version"] = m.group(2)
        return info

    m = re.search(r"Microsoft-IIS/([\d.]+)", b, re.IGNORECASE)
    if m:
        info["product"] = "IIS"
        info["version"] = m.group(1)
        return info

    m = re.search(r"Server:\s*(.*)", b, re.IGNORECASE)
    if m:
        info["server"] = m.group(1).strip()

    m = re.search(r"(\d[\d.]*\d)", b)
    if m:
        info["version"] = m.group(1)

    if "product" not in info:
        for svc, patterns in SERVICE_BANNER_PATTERNS.items():
            if any(p.search(b) for p in patterns):
                info["product"] = svc
                break
    if "product" not in info and service_hint:
        info["product"] = service_hint

    return info


class ServiceDetector(BaseScanner):
    async def scan(
        self,
        target: str,
        ports: list[int] | None = None,
        **kwargs: Any,
    ) -> ScanResult:
        if ports is None:
            ports = [22, 80, 443, 3306, 5432, 6379, 8080]

        sem = asyncio.Semaphore(self.max_concurrency)
        findings: list[dict[str, Any]] = []

        async def _grab(port: int) -> dict[str, Any] | None:
            async with sem:
                try:
                    probe = SERVICE_PROBES.get(port, b"")
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=self.timeout,
                    )

                    if probe:
                        writer.write(probe)
                        await writer.drain()

                    banner_bytes = await asyncio.wait_for(
                        reader.read(2048), timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()

                    if not banner_bytes:
                        return None

                    # errors="replace" never raises, so no fallback is needed.
                    banner = banner_bytes.decode("utf-8", errors="replace")

                    parsed = parse_banner(banner)
                    return {
                        "port": port,
                        "banner": banner[:200],
                        **parsed,
                    }
                except (TimeoutError, ConnectionRefusedError, ConnectionError, OSError):
                    return None

        tasks = [_grab(p) for p in ports]
        results = await asyncio.gather(*tasks)

        for r in results:
            if r:
                findings.append(r)

        result = ScanResult(
            target=target,
            scanner_name="service_detector",
            severity="info",
            findings=findings,
            raw_data={"ports_checked": len(ports)},
        )
        return result
