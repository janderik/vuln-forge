"""VulnForge CLI with rich output."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from typing import Any

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from src.report.generator import ReportGenerator
from src.scanners.cve_checker import CVEChecker
from src.scanners.port_scanner import PortScanner
from src.scanners.service_detector import ServiceDetector
from src.scanners.web_vuln import WebVulnScanner

console = Console()


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, show_path=False)],
    )


def _severity_color(severity: str) -> str:
    return {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "white",
    }.get(severity, "white")


def _print_results(results: list[Any]) -> None:
    for r in results:
        title = f"[{r.scanner_name.replace('_',' ').title()}] {r.target}"
        style = _severity_color(r.severity)
        console.print(Panel(f"Severity: [{style}]{r.severity.upper()}[/]", title=title))

        if not r.findings:
            console.print("  No findings.\n")
            continue

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Severity", width=10)
        table.add_column("Type", width=18)
        table.add_column("Detail", width=70)

        for f in sorted(
            r.findings,
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                x.get("severity", "info"), 99
            ),
        ):
            sev = f.get("severity", "info")
            st = Text(sev.upper(), style=_severity_color(sev))
            ftype = f.get("type", "")
            detail = f.get("detail", f.get("description", ""))
            if f.get("cve_id"):
                detail = f"{detail} [{_severity_color(sev)}]{f['cve_id']}[/]"
            table.add_row(st, ftype, detail[:120])

        console.print(table)
        console.print()


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
@click.version_option("1.0.0", prog_name="vulnforge")
def cli(verbose: bool) -> None:
    """VulnForge - Comprehensive vulnerability scanner."""
    setup_logging(verbose)


@cli.command()
@click.argument("target")
@click.option("-p", "--ports", default="", help="Port range (e.g. 22,80,443 or 1-1000)")
@click.option("--scan-type", type=click.Choice(["tcp_connect", "syn"]), default="tcp_connect")
@click.option("--timeout", default=10.0, help="Timeout per port in seconds")
@click.option("--concurrency", default=100, help="Max concurrent connections")
@click.option("--service-detect", is_flag=True, help="Enable service detection")
@click.option("--web-scan", is_flag=True, help="Enable web vulnerability scan")
@click.option("--cve-check", is_flag=True, help="Enable CVE matching")
@click.option("--circl-api", is_flag=True, help="Use CIRCL API for CVE lookups")
@click.option("-o", "--output", default="", help="Output file (suffix .html or .json)")
@click.option("-f", "--format", "output_format", type=click.Choice(["html", "json"]), default="html")
def scan(
    target: str,
    ports: str,
    scan_type: str,
    timeout: float,
    concurrency: int,
    service_detect: bool,
    web_scan: bool,
    cve_check: bool,
    circl_api: bool,
    output: str,
    output_format: str,
) -> None:
    """Run a vulnerability scan against a target."""
    console.print(Panel(f"[bold cyan]VulnForge v1.0.0[/]\nTarget: {target}", title="Scan Starting"))

    port_list: list[int] = []
    if ports:
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    s, e = part.split("-", 1)
                    port_list.extend(range(int(s), int(e) + 1))
                except ValueError:
                    console.print(f"[red]Invalid port range: {part}[/]")
                    sys.exit(1)
            else:
                try:
                    port_list.append(int(part))
                except ValueError:
                    console.print(f"[red]Invalid port: {part}[/]")
                    sys.exit(1)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        results: list[Any] = []

        if not service_detect and not web_scan and not cve_check:
            service_detect = web_scan = cve_check = True

        ps = PortScanner(timeout=timeout, max_concurrency=concurrency)
        sd = ServiceDetector(timeout=timeout, max_concurrency=concurrency)
        wv = WebVulnScanner(timeout=timeout, max_concurrency=concurrency)
        cv = CVEChecker(timeout=timeout, max_concurrency=concurrency, use_circl_api=circl_api)

        async def _run() -> None:
            port_result = await ps.scan(target, ports=port_list or None, scan_type=scan_type)
            results.append(port_result)

            open_ports_list = [f["port"] for f in port_result.findings]
            open_ports_list.sort()
            console.print(f"[green]Found {len(open_ports_list)} open ports: {open_ports_list}[/]")

            service_result = None
            if service_detect and open_ports_list:
                task = progress.add_task("[cyan]Detecting services...", total=None)
                service_result = await sd.scan(target, ports=open_ports_list)
                progress.remove_task(task)
                results.append(service_result)
                for f in service_result.findings:
                    console.print(f"  Port {f['port']}: {f.get('product','?')} {f.get('version','')}")

            web_result = None
            if web_scan:
                task = progress.add_task("[cyan]Scanning web vulnerabilities...", total=None)
                web_result = await wv.scan(target)
                progress.remove_task(task)
                results.append(web_result)
                console.print(f"[green]Web scan complete: {len(web_result.findings)} findings[/]")

            cve_result = None
            if cve_check:
                task = progress.add_task("[cyan]Checking CVEs...", total=None)
                services = []
                if service_result:
                    services.extend(service_result.findings)
                if web_result:
                    services.extend(web_result.findings)
                cve_result = await cv.scan(target, services=services)
                progress.remove_task(task)
                results.append(cve_result)
                console.print(f"[green]CVE check complete: {len(cve_result.findings)} matches[/]")

            await wv.close()
            await cv.close()

        asyncio.run(_run())

    console.print()
    _print_results(results)

    rg = ReportGenerator()
    report_content = rg.generate(results, output_format)

    if output:
        filepath = output
    else:
        sanitized = target.replace("://", "_").replace("/", "_").replace(":", "_")
        filepath = f"vulnforge_{sanitized}.{output_format}"

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report_content)

    console.print(f"[bold green]Report saved to: {os.path.abspath(filepath)}[/]")


@cli.command()
def list_payloads() -> None:
    """List available XSS test payloads."""
    try:
        from src.scanners.web_vuln import load_xss_payloads
        payloads = load_xss_payloads()
        console.print("[bold]Loaded XSS Payloads:[/]")
        for i, p in enumerate(payloads, 1):
            console.print(f"  {i:>2}. {p}")
    except Exception as e:
        console.print(f"[red]Error loading payloads: {e}[/]")


@cli.command()
@click.argument("product")
@click.option("-v", "--version", default=None, help="Product version filter")
def cves(product: str, version: str | None) -> None:
    """Look up CVEs for a product."""
    from src.db.cve_cache import CVECache
    cache = CVECache()
    results = cache.lookup(product, version)
    if not results:
        console.print(f"[yellow]No CVEs found for {product} {version or ''}[/]")
        return
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("CVE ID", width=18)
    table.add_column("Severity", width=10)
    table.add_column("Description", width=70)
    for r in sorted(results, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity", "info"), 99)):
        sev = r.get("severity", "info")
        table.add_row(
            r["id"],
            Text(sev.upper(), style=_severity_color(sev)),
            r.get("description", "")[:100],
        )
    console.print(table)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
