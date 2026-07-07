"""Opt-in, network-gated provenance check against the GitHub API.

Strictly additive: nothing here runs unless explicitly invoked (the CLI/web
layer calls maybe_fetch_provenance, which is a no-op without GITHUB_TOKEN),
and every failure path returns None — the deterministic offline verdict
("provenance not verified", capped at Approved with Conditions) then stands.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

_GITHUB_REPO_RE = re.compile(r"^https?://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")
_API_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class ProvenanceReport:
    """Independently verified provenance facts about a server's repository."""

    repo: str
    days_since_push: int
    open_issues: int
    archived: bool
    license_id: str | None
    verified: bool


def _default_fetch_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=_API_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_github_provenance(
    repo_url: str,
    fetch_json=None,
    now: datetime | None = None,
) -> ProvenanceReport | None:
    """Fetch and normalize repository facts. Any failure -> None."""
    match = _GITHUB_REPO_RE.match(repo_url or "")
    if not match:
        return None
    owner, repo = match.groups()
    fetch = fetch_json or _default_fetch_json
    try:
        data = fetch(f"https://api.github.com/repos/{owner}/{repo}")
        pushed_at = datetime.strptime(data["pushed_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        reference = now or datetime.now(timezone.utc)
        license_field = data.get("license") or {}
        return ProvenanceReport(
            repo=data["full_name"],
            days_since_push=max(0, (reference - pushed_at).days),
            open_issues=int(data["open_issues_count"]),
            archived=bool(data.get("archived", False)),
            license_id=license_field.get("spdx_id"),
            verified=True,
        )
    except Exception:
        return None  # degrade to the deterministic "not verified" verdict


def maybe_fetch_provenance(manifest: dict, fetch_json=None) -> ProvenanceReport | None:
    """Opt-in entry point: only attempts the network when GITHUB_TOKEN is set."""
    if not os.environ.get("GITHUB_TOKEN"):
        return None
    repo_url = manifest.get("repository")
    if not isinstance(repo_url, str):
        return None
    return fetch_github_provenance(repo_url, fetch_json=fetch_json)
