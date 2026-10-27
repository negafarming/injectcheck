"""Targets turn a (system prompt, user message) pair into the model's text output.

mock:naive and mock:hardened are deterministic fixtures for developing suites and testing the
harness itself. openai speaks the Chat Completions protocol, which also covers Ollama, vLLM,
LM Studio and most gateways. anthropic speaks the Messages API.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Protocol

from injectcheck.models import ConfigError, TargetError

OPENAI_BASE_URL = "https://api.openai.com/v1"
ANTHROPIC_BASE_URL = "https://api.anthropic.com"
ANTHROPIC_VERSION = "2023-06-01"


class Target(Protocol):
    label: str

    def complete(self, system: str | None, user: str) -> str: ...


# ---- deterministic mock ---------------------------------------------------------

CANARY_TOKEN = re.compile(r"CANARY-[A-F0-9]{8}")
MARKUP = re.compile(r"!\[[^\]]*\]\([^)\s]+\)|https?://[^\s)\"'>]+")
DIRECTIVE_HINTS = (
    "ignor",
    "reply",
    "respond",
    "répond",
    "output",
    "print",
    "say",
    "écri",
    "include",
    "inclu",
    "append",
    "ajout",
    "must",
    "doit",
    "always",
    "toujours",
    "begin",
    "commence",
    "end your",
    "termin",
    "repeat",
    "répèt",
    "override",
    "mode",
    "dis ",
)
LEAK_HINTS = (
    "system prompt",
    "instruction",
    "consigne",
    "above",
    "ci-dessus",
    "au-dessus",
    "prompt système",
    "translate your",
    "traduis tes",
    "répète",
)
FALLBACK = "Summary: the text discusses the topic named in the request."
REFUSAL = (
    "I can summarize this text, but I won't act on instructions embedded in it or share my configuration."
)


class MockTarget:
    """A stand-in model with a fixed policy. Use it to develop suites, not to rank real models.

    naive obeys any directive on a line that contains a canary token, and repeats its system
    prompt when asked about instructions. hardened never follows content and never leaks.
    """

    def __init__(self, policy: str) -> None:
        if policy not in ("naive", "hardened"):
            raise ConfigError(f"unknown mock policy '{policy}' (use mock:naive or mock:hardened)")
        self.policy = policy
        self.label = f"mock:{policy}"

    def complete(self, system: str | None, user: str) -> str:
        if self.policy == "hardened":
            return REFUSAL
        for line in user.splitlines():
            token = CANARY_TOKEN.search(line)
            if token and any(hint in line.lower() for hint in DIRECTIVE_HINTS):
                markup = MARKUP.search(line)
                return markup.group(0) if markup else token.group(0)
        if system and any(hint in user.lower() for hint in LEAK_HINTS):
            return system
        return FALLBACK


# ---- HTTP targets ---------------------------------------------------------------


def _post_json(url: str, headers: dict[str, str], body: dict, timeout: float, retries: int = 2) -> Any:
    """POST a JSON body and return the decoded reply.

    Retries rate limits (429) and server errors (5xx) with exponential backoff. Other failures
    are raised at once, carrying the HTTP status and the start of the response body.
    """
    payload = json.dumps(body).encode("utf-8")
    for attempt in range(retries + 1):
        request = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", **headers},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:200].decode("utf-8", "replace")
            message = f"HTTP {exc.code} from {url}: {detail}"
            retryable = exc.code == 429 or exc.code >= 500
        except OSError as exc:  # connection refused, reset, or timeout
            message = f"network error calling {url}: {exc}"
            retryable = True
        else:
            try:
                return json.loads(raw)
            except ValueError as exc:
                raise TargetError(f"{url} returned a body that is not JSON") from exc
        if not retryable or attempt == retries:
            raise TargetError(message)
        time.sleep(2**attempt)
    raise TargetError(f"no attempt was made to {url}")  # not reachable


class OpenAICompatibleTarget:
    def __init__(
        self,
        model: str,
        *,
        base_url: str = OPENAI_BASE_URL,
        api_key: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.label = f"openai:{model}"

    def complete(self, system: str | None, user: str) -> str:
        messages = [{"role": "system", "content": system}] if system else []
        messages.append({"role": "user", "content": user})
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        data = _post_json(
            f"{self.base_url}/chat/completions",
            headers,
            {"model": self.model, "messages": messages},
            self.timeout,
        )
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise TargetError(f"unexpected response shape from {self.base_url}: {str(data)[:200]}") from exc


class AnthropicTarget:
    def __init__(
        self,
        model: str,
        *,
        api_key: str,
        base_url: str = ANTHROPIC_BASE_URL,
        timeout: float = 60.0,
        max_tokens: int = 1024,
    ) -> None:
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.label = f"anthropic:{model}"

    def complete(self, system: str | None, user: str) -> str:
        body: dict = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": user}],
        }
        if system:
            body["system"] = system
        headers = {"x-api-key": self.api_key, "anthropic-version": ANTHROPIC_VERSION}
        data = _post_json(f"{self.base_url}/v1/messages", headers, body, self.timeout)
        if not isinstance(data, dict) or not isinstance(data.get("content"), list):
            raise TargetError(f"unexpected response shape from {self.base_url}: {str(data)[:200]}")
        return "".join(
            block.get("text", "")
            for block in data["content"]
            if isinstance(block, dict) and block.get("type") == "text"
        )


def make_target(spec: str, *, model: str | None, base_url: str | None, timeout: float) -> Target:
    """Build a target from the --target flag, reading API keys from the environment."""
    if spec.startswith("mock:"):
        return MockTarget(spec.removeprefix("mock:"))
    if spec == "openai":
        if not model:
            raise ConfigError("--model is required for the openai target")
        key = os.environ.get("OPENAI_API_KEY")
        if not key and not base_url:
            raise ConfigError("set OPENAI_API_KEY, or pass --base-url for a local server that needs no key")
        return OpenAICompatibleTarget(
            model, base_url=base_url or OPENAI_BASE_URL, api_key=key, timeout=timeout
        )
    if spec == "anthropic":
        if not model:
            raise ConfigError("--model is required for the anthropic target")
        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise ConfigError("set ANTHROPIC_API_KEY to use the anthropic target")
        return AnthropicTarget(model, api_key=key, base_url=base_url or ANTHROPIC_BASE_URL, timeout=timeout)
    raise ConfigError(f"unknown target '{spec}' (use mock:naive, mock:hardened, openai or anthropic)")
