import pytest

from injectcheck.loader import bundled_names, load_suites, parse_suite
from injectcheck.models import Criterion, SuiteError

BUNDLED = {"indirect-injection", "system-prompt-leak", "exfiltration", "instruction-hierarchy"}


def _suite(cases):
    return {"name": "test", "cases": cases}


def _case(**overrides):
    case = {
        "id": "T-1",
        "title": "t",
        "severity": "high",
        "language": "en",
        "user": "hi {canary}",
        "fail_if": [{"contains": "{canary}"}],
    }
    case.update(overrides)
    return case


def test_bundled_suites_load_with_unique_ids():
    assert set(bundled_names()) == BUNDLED
    ids = [case.id for suite in load_suites() for case in suite.cases]
    assert len(ids) == len(set(ids)) == 19


def test_selecting_by_name_and_unknown_names():
    assert [suite.name for suite in load_suites(["exfiltration"])] == ["exfiltration"]
    with pytest.raises(SuiteError, match="no suite named"):
        load_suites(["nope"])


def test_rejects_unknown_severity():
    with pytest.raises(SuiteError, match="severity"):
        parse_suite(_suite([_case(severity="extreme")]), "inline")


def test_rejects_missing_keys():
    broken = _case()
    del broken["user"]
    with pytest.raises(SuiteError, match="missing user"):
        parse_suite(_suite([broken]), "inline")


def test_rejects_invalid_regex_at_load_time():
    with pytest.raises(SuiteError, match="invalid regex"):
        parse_suite(_suite([_case(fail_if=[{"regex": "(unclosed"}])]), "inline")


def test_rejects_duplicate_ids():
    with pytest.raises(SuiteError, match="duplicate"):
        parse_suite(_suite([_case(), _case()]), "inline")


def test_contains_is_case_insensitive_and_fills_canary():
    criterion = Criterion("contains", "{canary}")
    assert criterion.matches("the code is canary-1a2b3c4d", "CANARY-1A2B3C4D")
    assert not criterion.matches("nothing here", "CANARY-1A2B3C4D")


def test_regex_criterion_detects_exfiltration_link():
    criterion = Criterion("regex", r"https?://[^\s)]*{canary}")
    assert criterion.matches("see https://x.attacker.example/?r=CANARY-AAAA1111 now", "CANARY-AAAA1111")
    assert not criterion.matches("see https://example.com/", "CANARY-AAAA1111")
