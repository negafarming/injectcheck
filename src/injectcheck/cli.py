"""Command-line interface: `injectcheck list` and `injectcheck run`."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from injectcheck import __version__
from injectcheck.engine import Summary, breaches, run, summarize
from injectcheck.loader import bundled_names, load_suites
from injectcheck.models import SEVERITIES, ConfigError, InjectcheckError
from injectcheck.report import render, summary_line
from injectcheck.targets import make_target

EXIT_OK = 0
EXIT_BREACH = 1  # a vulnerability at or above --fail-on was found
EXIT_CONFIG = 2  # bad flags, suite, credentials, target or output path
EXIT_ERRORS = 3  # some cases could not run


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="injectcheck",
        description="Regression tests for prompt injection and system prompt leakage in LLM applications.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("list", help="list the bundled suites")

    run_cmd = commands.add_parser("run", help="run suites against a target")
    run_cmd.add_argument("--target", required=True, help="mock:naive, mock:hardened, openai or anthropic")
    run_cmd.add_argument("--model", help="model name (required for openai and anthropic)")
    run_cmd.add_argument("--base-url", help="API base URL, e.g. http://localhost:11434/v1 for Ollama")
    run_cmd.add_argument(
        "--suite",
        action="append",
        metavar="NAME|PATH",
        help="bundled suite name or YAML file; repeat for several (default: all bundled suites)",
    )
    run_cmd.add_argument("--language", help="only run cases in this language, e.g. fr or en")
    run_cmd.add_argument("--format", choices=("text", "markdown", "json"), default="text")
    run_cmd.add_argument("--out", type=Path, help="write the report to this file instead of stdout")
    run_cmd.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        help="exit 1 if a vulnerability at or above this severity is found",
    )
    run_cmd.add_argument("--concurrency", type=int, default=4, help="parallel requests (default: 4)")
    run_cmd.add_argument("--timeout", type=float, default=60.0, help="per-request timeout in seconds")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _list() if args.command == "list" else _run(args)
    except InjectcheckError as exc:
        print(f"injectcheck: error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except BrokenPipeError:
        # The reader closed the pipe early, as in `injectcheck list | head -1`.
        _silence_stdout()
        return EXIT_OK


def _list() -> int:
    for name in bundled_names():
        suite = load_suites([name])[0]
        languages = ", ".join(sorted({case.language for case in suite.cases}))
        blurb = (suite.description.splitlines() or [""])[0][:70]
        print(f"{name:<22} {len(suite.cases):>3} cases  [{languages}]  {blurb}")
    sys.stdout.flush()
    return EXIT_OK


def _run(args: argparse.Namespace) -> int:
    # Check the output location before any request is made, so a typo cannot cost API calls.
    if args.out is not None and not args.out.parent.is_dir():
        raise ConfigError(f"cannot write --out {args.out}: the folder {args.out.parent} does not exist")
    suites = load_suites(args.suite)
    target = make_target(args.target, model=args.model, base_url=args.base_url, timeout=args.timeout)
    result = run(suites, target, language=args.language, concurrency=args.concurrency)
    summary = summarize(result.results)
    if breaches(result.results, args.fail_on):
        code = EXIT_BREACH
    elif summary.errors:
        code = EXIT_ERRORS
    else:
        code = EXIT_OK
    _emit(render(result, args.format), args, summary)
    return code


def _emit(report: str, args: argparse.Namespace, summary: Summary) -> None:
    try:
        if args.out:
            args.out.write_text(report, encoding="utf-8")
            print(f"wrote {args.out} ({summary_line(summary)})")
        else:
            sys.stdout.write(report)
            sys.stdout.flush()
            if args.format != "text":
                print(summary_line(summary), file=sys.stderr)
    except BrokenPipeError:
        _silence_stdout()  # the exit code still reflects the run
    except OSError as exc:
        raise ConfigError(f"cannot write the report: {exc.strerror or exc}") from exc


def _silence_stdout() -> None:
    """Send stdout to devnull so Python does not report the broken pipe again at exit."""
    os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
