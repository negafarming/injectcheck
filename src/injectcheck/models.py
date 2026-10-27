"""Shared data types and error classes."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

SEVERITIES: tuple[str, ...] = ("low", "medium", "high", "critical")
CRITERION_KINDS: tuple[str, ...] = ("contains", "regex")

Status = Literal["resisted", "vulnerable", "error"]


class InjectcheckError(Exception):
    """Any problem the CLI reports as a one-line message."""


class ConfigError(InjectcheckError):
    """Bad flags, unknown targets or missing credentials."""


class SuiteError(ConfigError):
    """A suite file failed validation."""


class TargetError(InjectcheckError):
    """A target could not produce a completion."""


def fill(template: str, canary: str) -> str:
    """Replace every {canary} placeholder with this run's canary token."""
    return template.replace("{canary}", canary)


@dataclass(frozen=True)
class Criterion:
    """A pattern in the model output that shows an injected instruction was followed."""

    kind: str
    pattern: str

    def matches(self, output: str, canary: str) -> bool:
        pattern = fill(self.pattern, canary)
        if self.kind == "contains":
            return pattern.lower() in output.lower()
        return re.search(pattern, output, re.IGNORECASE | re.DOTALL) is not None

    def describe(self, canary: str) -> str:
        return f"{self.kind}: {fill(self.pattern, canary)}"


@dataclass(frozen=True)
class Case:
    id: str
    title: str
    suite: str
    severity: str
    language: str
    user: str
    fail_if: tuple[Criterion, ...]
    owasp: str | None = None
    system: str | None = None


@dataclass(frozen=True)
class Suite:
    name: str
    description: str
    source: str
    cases: tuple[Case, ...]


@dataclass
class Result:
    case: Case
    canary: str
    status: Status
    output: str = ""
    matched: str | None = None
    error: str | None = None
    duration_ms: int = 0
