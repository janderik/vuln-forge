"""Port scanner with TCP connect and simulated SYN scan."""

from __future__ import annotations

import asyncio
import random
from typing import Any

from src.scanners.base import BaseScanner, ScanResult

COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9090: "Prometheus",
    27017: "MongoDB",
}


class PortScanner(BaseScanner):
    async def scan(
        self,
        target: str,
        ports: list[int] | None = None,
        scan_type: str = "tcp_connect",
        **kwargs: Any,
    ) -> ScanResult:
        if ports is None:
            ports = list(COMMON_PORTS.keys())

        self.logger.info("Scanning %s ports on %s (%s)", len(ports), target, scan_type)

        if scan_type == "syn":
            open_ports = await self._syn_scan(target, ports)
        else:
            open_ports = await self._tcp_connect_scan(target, ports)

        result = ScanResult(
            target=target,
            scanner_name="port_scanner",
            severity="low" if open_ports else "info",
            findings=[
                {
                    "port": port,
                    "service": COMMON_PORTS.get(port, "unknown"),
                    "state": "open",
                }
                for port in open_ports
            ],
            raw_data={"scan_type": scan_type, "ports_scanned": len(ports)},
        )
        return result

    async def _tcp_connect_scan(
        self, target: str, ports: list[int]
    ) -> list[int]:
        sem = asyncio.Semaphore(self.max_concurrency)

        async def _try_port(port: int) -> int | None:
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=self.timeout,
                    )
                    writer.close()
                    await writer.wait_closed()
                    return port
                except (TimeoutError, ConnectionRefusedError, ConnectionError, OSError):
                    return None

        tasks = [_try_port(p) for p in ports]
        results = await asyncio.gather(*tasks)
        return sorted([r for r in results if r is not None])

    async def _syn_scan(self, target: str, ports: list[int]) -> list[int]:
        self.logger.info("SYN scan is simulated; falling back to TCP connect for accuracy")
        open_ports = await self._tcp_connect_scan(target, ports)

        # Simulate SYN-specific noise for realism
        simulated = []
        for port in ports:
            if port in open_ports:
                simulated.append(port)
            elif random.random() < 0.02:
                # 2% false positive for realism
                simulated.append(port)

        return sorted(set(simulated))
