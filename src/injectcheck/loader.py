"""Load and validate attack suites: bundled YAML files, or YAML files supplied by the user."""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path

import yaml

from injectcheck.models import CRITERION_KINDS, SEVERITIES, Case, Criterion, Suite, SuiteError

CASE_KEYS = ("id", "title", "severity", "language", "user", "fail_if")


def bundled_names() -> list[str]:
    folder = resources.files("injectcheck") / "suites"
    return sorted(entry.name[: -len(".yaml")] for entry in folder.iterdir() if entry.name.endswith(".yaml"))


def load_suites(selectors: list[str] | None = None) -> list[Suite]:
    """Load bundled suites by name or YAML files by path. With no selectors, load every bundled suite."""
    if not selectors:
        return [_bundled(name) for name in bundled_names()]
    suites: list[Suite] = []
    for selector in selectors:
        path = Path(selector)
        if path.is_file():
            suites.append(_from_text(path.read_text(encoding="utf-8"), str(path)))
        elif selector in bundled_names():
            suites.append(_bundled(selector))
        else:
            known = ", ".join(bundled_names())
            raise SuiteError(f"no suite named '{selector}' and no such file (bundled: {known})")
    return suites


def _bundled(name: str) -> Suite:
    text = (resources.files("injectcheck") / "suites" / f"{name}.yaml").read_text(encoding="utf-8")
    return _from_text(text, f"bundled:{name}")


def _from_text(text: str, source: str) -> Suite:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SuiteError(f"{source}: invalid YAML: {exc}") from exc
    return parse_suite(data, source)


def parse_suite(data: object, source: str) -> Suite:
    if not isinstance(data, dict) or not isinstance(data.get("name"), str):
        raise SuiteError(f"{source}: expected a mapping with a string 'name'")
    raw_cases = data.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise SuiteError(f"{source}: 'cases' must be a non-empty list")
    cases: list[Case] = []
    seen: set[str] = set()
    for raw in raw_cases:
        case = _parse_case(raw, data["name"], source)
        if case.id in seen:
            raise SuiteError(f"{source}: duplicate case id {case.id}")
        seen.add(case.id)
        cases.append(case)
    return Suite(
        name=data["name"],
        description=str(data.get("description") or "").strip(),
        source=source,
        cases=tuple(cases),
    )


def _parse_case(raw: object, suite: str, source: str) -> Case:
    if not isinstance(raw, dict):
        raise SuiteError(f"{source}: every case must be a mapping")
    case_id = str(raw.get("id", "?"))
    where = f"{source} [{case_id}]"
    missing = [key for key in CASE_KEYS if key not in raw]
    if missing:
        raise SuiteError(f"{where}: missing {', '.join(missing)}")
    severity = str(raw["severity"]).lower()
    if severity not in SEVERITIES:
        raise SuiteError(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
    if not isinstance(raw["fail_if"], list) or not raw["fail_if"]:
        raise SuiteError(f"{where}: fail_if must be a non-empty list")
    return Case(
        id=case_id,
        title=str(raw["title"]).strip(),
        suite=suite,
        severity=severity,
        language=str(raw["language"]).strip().lower(),
        user=str(raw["user"]).strip(),
        system=str(raw["system"]).strip() if raw.get("system") else None,
        owasp=str(raw["owasp"]) if raw.get("owasp") else None,
        fail_if=tuple(_parse_criterion(item, where) for item in raw["fail_if"]),
    )


def _parse_criterion(item: object, where: str) -> Criterion:
    if not isinstance(item, dict) or len(item) != 1:
        raise SuiteError(f"{where}: each fail_if entry needs exactly one of: {', '.join(CRITERION_KINDS)}")
    kind, pattern = next(iter(item.items()))
    if kind not in CRITERION_KINDS or not isinstance(pattern, str) or not pattern:
        raise SuiteError(f"{where}: unsupported criterion {kind!r}")
    if kind == "regex":
        try:
            re.compile(pattern.replace("{canary}", "CANARY-00000000"))
        except re.error as exc:
            raise SuiteError(f"{where}: invalid regex {pattern!r}: {exc}") from exc
    return Criterion(kind=kind, pattern=pattern)
