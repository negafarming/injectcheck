"""Render a run as text, Markdown or JSON."""

from __future__ import annotations

import json

from injectcheck import __version__
from injectcheck.engine import Run, Summary, summarize
from injectcheck.models import Result

EXCERPT_CHARS = 300


def render(run: Run, fmt: str) -> str:
    if fmt == "json":
        return _json(run)
    if fmt == "markdown":
        return _markdown(run)
    return _text(run)


def summary_line(summary: Summary) -> str:
    rate = "n/a" if summary.resistance_rate is None else f"{summary.resistance_rate:.0%}"
    return (
        f"resisted {summary.resisted} | vulnerable {summary.vulnerable} | "
        f"errors {summary.errors} | resistance {rate}"
    )


def _text(run: Run) -> str:
    header = f"injectcheck {__version__} | target {run.target} | {len(run.results)} cases | {run.duration_s}s"
    lines = [header, ""]
    for r in run.results:
        lines.append(
            f"{r.status.upper():<10} {r.case.severity:<9} {r.case.id:<8} {r.case.language:<3}"
            f" {r.duration_ms:>6} ms  {r.case.title}"
        )
    errors = [r for r in run.results if r.status == "error"]
    if errors:
        lines += ["", "Errors:"] + [f"  {r.case.id}: {r.error}" for r in errors]
    lines += ["", summary_line(summarize(run.results))]
    return "\n".join(lines) + "\n"


def _markdown(run: Run) -> str:
    s = summarize(run.results)
    rate = "n/a" if s.resistance_rate is None else f"{s.resistance_rate:.0%}"
    severities = ", ".join(f"{level} {count}" for level, count in s.by_severity.items())
    out = [
        "# injectcheck report",
        "",
        f"- Target: `{run.target}`",
        f"- Run at: {run.started_at:%Y-%m-%d %H:%M} UTC",
        f"- Cases: {s.total} ({s.resisted} resisted, {s.vulnerable} vulnerable, {s.errors} errors)",
        f"- Resistance rate: {rate}",
        f"- Vulnerable by severity: {severities}",
        "",
    ]
    vulnerable = [r for r in run.results if r.status == "vulnerable"]
    if vulnerable:
        out += ["## Vulnerable cases", ""]
        for r in vulnerable:
            out += [
                f"### {r.case.id}: {r.case.title}",
                "",
                f"Severity {r.case.severity}, language {r.case.language}, OWASP {r.case.owasp or 'n/a'}, suite {r.case.suite}.",
                "",
                f"Matched `{r.matched}`",
                "",
                "```text",
                _excerpt(r.output),
                "```",
                "",
            ]
    errors = [r for r in run.results if r.status == "error"]
    if errors:
        out += ["## Errors", ""] + [f"- {r.case.id}: {r.error}" for r in errors] + [""]
    out += [
        "## All cases",
        "",
        "| ID | Title | Severity | Lang | Result | Latency (ms) |",
        "| --- | --- | --- | --- | --- | ---: |",
    ]
    for r in run.results:
        title = r.case.title.replace("|", "\\|")
        out.append(
            f"| {r.case.id} | {title} | {r.case.severity} | {r.case.language} | {r.status} | {r.duration_ms} |"
        )
    return "\n".join(out) + "\n"


def _excerpt(text: str) -> str:
    cleaned = text.strip().replace("```", "'''")
    if not cleaned:
        return "(empty output)"
    return cleaned[:EXCERPT_CHARS] + ("..." if len(cleaned) > EXCERPT_CHARS else "")


def _json(run: Run) -> str:
    s = summarize(run.results)
    payload = {
        "injectcheck_version": __version__,
        "target": run.target,
        "started_at": run.started_at.isoformat(),
        "duration_s": run.duration_s,
        "summary": {
            "total": s.total,
            "resisted": s.resisted,
            "vulnerable": s.vulnerable,
            "errors": s.errors,
            "resistance_rate": s.resistance_rate,
            "vulnerable_by_severity": s.by_severity,
        },
        "results": [_result_dict(r) for r in run.results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _result_dict(r: Result) -> dict:
    return {
        "id": r.case.id,
        "title": r.case.title,
        "suite": r.case.suite,
        "severity": r.case.severity,
        "language": r.case.language,
        "owasp": r.case.owasp,
        "status": r.status,
        "matched": r.matched,
        "error": r.error,
        "output": r.output,
        "duration_ms": r.duration_ms,
    }
