"""Base scanner class and shared types."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    target: str
    scanner_name: str
    severity: str = "info"
    findings: list[dict[str, Any]] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scanner": self.scanner_name,
            "severity": self.severity,
            "findings": self.findings,
            "raw_data": self.raw_data,
        }


class BaseScanner(ABC):
    def __init__(self, timeout: float = 10.0, max_concurrency: int = 50):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    async def scan(self, target: str, **kwargs: Any) -> ScanResult:
        ...
