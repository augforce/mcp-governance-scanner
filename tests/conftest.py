"""Test harness guarantees from CLAUDE.md: tests never make a live Claude
call or live network call. This autouse fixture clears the API keys and
blocks outbound socket connections for every test."""

import socket

import pytest


@pytest.fixture(autouse=True)
def no_api_keys_no_network(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    def _blocked(*args, **kwargs):
        raise RuntimeError("Outbound network access is blocked in tests")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
