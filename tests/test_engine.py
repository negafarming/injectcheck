import pytest

from injectcheck.engine import breaches, run, summarize
from injectcheck.loader import load_suites
from injectcheck.models import ConfigError, TargetError
from injectcheck.targets import MockTarget


class BrokenTarget:
    label = "broken"

    def complete(self, system, user):
        raise TargetError("connection refused")


def test_naive_mock_falls_for_everything_except_the_control():
    result = run(load_suites(), MockTarget("naive"), concurrency=3)
    resisted = {r.case.id for r in result.results if r.status == "resisted"}
    assert resisted == {"SPL-005"}
    assert summarize(result.results).vulnerable == 18


def test_hardened_mock_resists_every_case():
    summary = summarize(run(load_suites(), MockTarget("hardened")).results)
    assert summary.vulnerable == 0
    assert summary.errors == 0
    assert summary.resistance_rate == 1.0


def test_language_filter_selects_only_matching_cases():
    result = run(load_suites(), MockTarget("hardened"), language="fr")
    assert len(result.results) == 7
    assert {r.case.language for r in result.results} == {"fr"}


def test_unmatched_language_is_a_config_error():
    with pytest.raises(ConfigError):
        run(load_suites(), MockTarget("hardened"), language="de")


def test_target_failures_are_recorded_not_raised():
    result = run(load_suites(["exfiltration"]), BrokenTarget())
    assert summarize(result.results).errors == len(result.results) == 3
    assert {r.error for r in result.results} == {"connection refused"}


def test_fail_on_selects_breaches_at_or_above_threshold():
    results = run(load_suites(), MockTarget("naive")).results
    assert {r.case.id for r in breaches(results, "critical")} == {"IPI-006", "EXF-001"}
    assert len(breaches(results, "low")) == 18
    assert breaches(results, None) == []


def test_canaries_are_fresh_on_every_run():
    first = run(load_suites(["exfiltration"]), MockTarget("hardened")).results
    second = run(load_suites(["exfiltration"]), MockTarget("hardened")).results
    assert {r.canary for r in first}.isdisjoint({r.canary for r in second})
