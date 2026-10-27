import json

from injectcheck.cli import EXIT_BREACH, EXIT_CONFIG, EXIT_OK, main


def test_list_shows_every_bundled_suite(capsys):
    assert main(["list"]) == EXIT_OK
    out = capsys.readouterr().out
    for name in ("indirect-injection", "system-prompt-leak", "exfiltration", "instruction-hierarchy"):
        assert name in out


def test_hardened_mock_passes_the_gate(capsys):
    assert main(["run", "--target", "mock:hardened", "--fail-on", "low"]) == EXIT_OK
    assert "resistance 100%" in capsys.readouterr().out


def test_naive_mock_fails_the_gate(capsys):
    assert main(["run", "--target", "mock:naive", "--fail-on", "critical"]) == EXIT_BREACH
    assert "VULNERABLE" in capsys.readouterr().out


def test_json_report_is_written_to_file(tmp_path):
    out = tmp_path / "report.json"
    assert main(["run", "--target", "mock:naive", "--format", "json", "--out", str(out)]) == EXIT_OK
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["summary"]["total"] == 19
    assert payload["summary"]["vulnerable"] == 18


def test_markdown_report_has_results_table(capsys):
    assert main(["run", "--target", "mock:naive", "--format", "markdown", "--language", "fr"]) == EXIT_OK
    out = capsys.readouterr().out
    assert out.startswith("# injectcheck report")
    assert "| ID | Title | Severity | Lang | Result | Latency (ms) |" in out


def test_missing_model_is_a_config_error(capsys):
    assert main(["run", "--target", "openai"]) == EXIT_CONFIG
    assert "--model" in capsys.readouterr().err
