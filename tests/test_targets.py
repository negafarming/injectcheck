import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from injectcheck import targets
from injectcheck.models import ConfigError, TargetError
from injectcheck.targets import AnthropicTarget, OpenAICompatibleTarget, make_target


@pytest.fixture
def api(monkeypatch):
    """A local HTTP server that replays scripted replies and records every request it receives."""
    monkeypatch.setattr(targets.time, "sleep", lambda _seconds: None)
    state = {"replies": [], "seen": []}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            size = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(size) or b"{}")
            state["seen"].append(
                {
                    "path": self.path,
                    "headers": {key.lower(): value for key, value in self.headers.items()},
                    "body": body,
                }
            )
            status, payload = state["replies"].pop(0)
            data = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    state["url"] = f"http://127.0.0.1:{server.server_address[1]}"
    yield state
    server.shutdown()
    server.server_close()


def test_openai_adapter_sends_chat_request_and_reads_reply(api):
    api["replies"].append((200, {"choices": [{"message": {"content": "hello there"}}]}))
    target = OpenAICompatibleTarget("gpt-test", base_url=api["url"] + "/v1", api_key="sk-test")
    assert target.complete("be brief", "hi") == "hello there"
    request = api["seen"][0]
    assert request["path"] == "/v1/chat/completions"
    assert request["headers"]["authorization"] == "Bearer sk-test"
    assert request["body"]["messages"] == [
        {"role": "system", "content": "be brief"},
        {"role": "user", "content": "hi"},
    ]


def test_anthropic_adapter_sends_version_header_and_joins_text_blocks(api):
    api["replies"].append(
        (200, {"content": [{"type": "text", "text": "foo"}, {"type": "text", "text": "bar"}]})
    )
    target = AnthropicTarget("claude-test", api_key="ak-test", base_url=api["url"])
    assert target.complete("sys", "user msg") == "foobar"
    request = api["seen"][0]
    assert request["path"] == "/v1/messages"
    assert request["headers"]["x-api-key"] == "ak-test"
    assert request["headers"]["anthropic-version"] == "2023-06-01"
    assert request["body"]["system"] == "sys"
    assert request["body"]["max_tokens"] == 1024


def test_transient_errors_are_retried(api):
    api["replies"].extend([(503, {"error": "busy"}), (200, {"choices": [{"message": {"content": "ok"}}]})])
    target = OpenAICompatibleTarget("m", base_url=api["url"])
    assert target.complete(None, "hi") == "ok"
    assert len(api["seen"]) == 2


def test_client_errors_fail_fast_with_the_exact_cause(api):
    api["replies"].append((401, {"error": "invalid api key"}))
    target = OpenAICompatibleTarget("m", base_url=api["url"], api_key="bad")
    with pytest.raises(TargetError, match="HTTP 401.*invalid api key"):
        target.complete(None, "hi")
    assert len(api["seen"]) == 1


def test_make_target_checks_model_and_credentials(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ConfigError, match="--model"):
        make_target("anthropic", model=None, base_url=None, timeout=5)
    with pytest.raises(ConfigError, match="ANTHROPIC_API_KEY"):
        make_target("anthropic", model="claude-test", base_url=None, timeout=5)
    with pytest.raises(ConfigError, match="OPENAI_API_KEY"):
        make_target("openai", model="gpt-test", base_url=None, timeout=5)
    with pytest.raises(ConfigError, match="unknown target"):
        make_target("gemini", model="x", base_url=None, timeout=5)
