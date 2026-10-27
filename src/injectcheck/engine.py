"""Run cases against a target and decide, case by case, whether the injection worked."""

from __future__ import annotations

import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

from injectcheck.models import SEVERITIES, Case, ConfigError, Result, Status, Suite, TargetError, fill
from injectcheck.targets import Target


def new_canary() -> str:
    """A fresh token for every case in every run, so no model can have memorized it."""
    return f"CANARY-{secrets.token_hex(4).upper()}"


def run_case(case: Case, target: Target) -> Result:
    canary = new_canary()
    system = fill(case.system, canary) if case.system else None
    user = fill(case.user, canary)
    started = time.perf_counter()
    try:
        output = target.complete(system, user)
    except TargetError as exc:
        return Result(
            case=case, canary=canary, status="error", error=str(exc), duration_ms=_elapsed_ms(started)
        )
    hit = next((criterion for criterion in case.fail_if if criterion.matches(output, canary)), None)
    status: Status = "vulnerable" if hit else "resisted"
    return Result(
        case=case,
        canary=canary,
        status=status,
        output=output,
        matched=hit.describe(canary) if hit else None,
        duration_ms=_elapsed_ms(started),
    )


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def select_cases(suites: list[Suite], language: str | None = None) -> list[Case]:
    wanted = (language or "all").lower()
    cases = [case for suite in suites for case in suite.cases if wanted in ("all", case.language)]
    if not cases:
        raise ConfigError(f"no cases match language '{wanted}' in the selected suites")
    return cases


@dataclass
class Run:
    target: str
    started_at: datetime
    duration_s: float
    results: list[Result] = field(default_factory=list)


def run(suites: list[Suite], target: Target, *, language: str | None = None, concurrency: int = 4) -> Run:
    if concurrency < 1:
        raise ConfigError("--concurrency must be at least 1")
    cases = select_cases(suites, language)
    started_at = datetime.now(timezone.utc)
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(lambda case: run_case(case, target), cases))
    return Run(
        target=target.label,
        started_at=started_at,
        duration_s=round(time.perf_counter() - t0, 2),
        results=results,
    )


@dataclass(frozen=True)
class Summary:
    total: int
    resisted: int
    vulnerable: int
    errors: int
    by_severity: dict[str, int]

    @property
    def resistance_rate(self) -> float | None:
        executed = self.resisted + self.vulnerable
        return self.resisted / executed if executed else None


def summarize(results: list[Result]) -> Summary:
    by_severity = {level: 0 for level in SEVERITIES}
    counts = {"resisted": 0, "vulnerable": 0, "error": 0}
    for result in results:
        counts[result.status] += 1
        if result.status == "vulnerable":
            by_severity[result.case.severity] += 1
    return Summary(
        total=len(results),
        resisted=counts["resisted"],
        vulnerable=counts["vulnerable"],
        errors=counts["error"],
        by_severity=by_severity,
    )


def breaches(results: list[Result], fail_on: str | None) -> list[Result]:
    """Vulnerabilities at or above the given severity. Empty when no threshold is set."""
    if fail_on is None:
        return []
    threshold = SEVERITIES.index(fail_on)
    return [r for r in results if r.status == "vulnerable" and SEVERITIES.index(r.case.severity) >= threshold]
