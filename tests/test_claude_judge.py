"""Claude layer: strictly optional and additive. Activates only when
ANTHROPIC_API_KEY is set; every failure path returns None so the
deterministic verdict stands. These tests never touch the real SDK or
network (conftest clears the key and blocks sockets)."""

import sys
import types

import pytest

from analysis.claude_judge import narrative
from app.scan import scan_artifact
from tests import fixtures


@pytest.fixture
def result():
    return scan_artifact(fixtures.clean_artifact())


def make_fake_anthropic(behavior):
    """Build a fake `anthropic` module whose messages.create runs `behavior`."""
    module = types.ModuleType("anthropic")

    class FakeMessages:
        def create(self, **kwargs):
            return behavior(kwargs)

    class FakeClient:
        def __init__(self, *args, **kwargs):
            self.messages = FakeMessages()

    module.Anthropic = FakeClient
    return module


class TestOptionality:
    def test_no_api_key_returns_none(self, result):
        # conftest guarantees ANTHROPIC_API_KEY is unset.
        assert narrative(result) is None

    def test_sdk_missing_returns_none(self, result, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
        monkeypatch.setitem(sys.modules, "anthropic", None)  # import -> ImportError
        assert narrative(result) is None

    def test_api_error_returns_none(self, result, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")

        def boom(kwargs):
            raise RuntimeError("api unavailable")

        monkeypatch.setitem(sys.modules, "anthropic", make_fake_anthropic(boom))
        assert narrative(result) is None

    def test_empty_response_returns_none(self, result, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")

        def empty(kwargs):
            return types.SimpleNamespace(content=[], stop_reason="end_turn")

        monkeypatch.setitem(sys.modules, "anthropic", make_fake_anthropic(empty))
        assert narrative(result) is None


class TestNarrative:
    def test_returns_text_and_sends_deterministic_report(self, result, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
        seen = {}

        def ok(kwargs):
            seen.update(kwargs)
            block = types.SimpleNamespace(type="text", text="Plain-English verdict here.")
            return types.SimpleNamespace(content=[block], stop_reason="end_turn")

        monkeypatch.setitem(sys.modules, "anthropic", make_fake_anthropic(ok))
        text = narrative(result)
        assert text == "Plain-English verdict here."
        # The prompt must carry the deterministic report — Claude explains it,
        # it never re-scores or overrides.
        prompt = str(seen["messages"])
        assert "Approved with Conditions" in prompt
        assert "not independently verified" in prompt
        assert "re-score" in str(seen["system"]) or "rescore" in str(seen["system"])
