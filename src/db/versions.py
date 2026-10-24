"""Numeric version comparison shared by the CVE cache and the CVE checker."""

from __future__ import annotations


def parse_version(version_str: str | None) -> tuple[int, ...]:
    """Turn "2.4.41" or "8.9p1" into a tuple that compares numerically.

    Comparing version strings as text is wrong ("2.4.9" > "2.4.55"), so
    every range check must go through this function.
    """
    if not version_str:
        return (0,)
    parts = []
    for part in version_str.replace("p", ".").split("."):
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def version_in_range(version: str | None, version_start: str, version_end: str) -> bool:
    """True when ``version`` lies in [start, end]; unknown versions match."""
    if not version:
        return True
    v = parse_version(version)
    vs = parse_version(version_start) if version_start else (0,)
    ve = parse_version(version_end) if version_end else (999999,)
    return vs <= v <= ve
