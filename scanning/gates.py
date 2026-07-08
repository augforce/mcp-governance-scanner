"""Hard-gate checks. Any single finding from any gate = automatic fail.

Gates are independent of the scored rubric and of each other: each check
inspects the artifact for exactly one class of violation and returns the
findings it saw. Static pattern analysis only — the server under test is
never executed.
"""

from __future__ import annotations

import re

from scanning.models import GateFinding, ServerArtifact

GATE_HARDCODED_CREDENTIALS = "hardcoded_credentials"
GATE_UNVALIDATED_INPUT = "unvalidated_input"
GATE_UNDISCLOSED_NETWORK = "undisclosed_network_calls"
GATE_CREDENTIAL_ECHO = "credential_echo"

# Names that indicate a value is a credential.
_CRED_NAME = r"(?:api[_-]?key|apikey|secret|token|password|passwd|access[_-]?key|auth[_-]?key)"

# `api_key = "..."` / `"api_key": "..."` style assignment of a quoted literal.
_CRED_ASSIGN_RE = re.compile(
    rf"(?i)[\"']?\w*{_CRED_NAME}\w*[\"']?\s*[:=]\s*[\"']([^\"']{{8,}})[\"']"
)
# Well-known token shapes, regardless of variable name.
_KNOWN_TOKEN_RE = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})"
)
# Lines that read (or, in test fixtures, write) credentials the approved way,
# plus obvious placeholders.
_ENV_REF_RE = re.compile(r"os\.environ|getenv\(|setenv\(|process\.env|\$\{")
_PLACEHOLDER_RE = re.compile(r"(?i)your[_-]|<[^>]*>|\{\{|x{4,}|example|changeme|todo|placeholder|dummy")

# Injection sinks: (human label, sink pattern). A sink only trips the gate when
# the call also shows dynamic string construction (f-string, concat, format, %).
_SINKS = [
    ("shell command", re.compile(r"\bos\.system\s*\(")),
    (
        "shell command",
        re.compile(r"\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\([^)]*shell\s*=\s*True"),
    ),
    ("file path", re.compile(r"(?<![\w.])open\s*\(")),
    ("query string", re.compile(r"\.execute(?:many|script)?\s*\(")),
]
_DYNAMIC_RE = re.compile(r"f[\"']|\+|\.format\(|%\s*[\w(]")

# Comment text is stripped before URL detection in the network gate: a URL in
# a comment ("# Get a free key at https://...") is guidance for a human, not a
# call the program makes. Best-effort line-level stripping: full-line and
# trailing '#'/'//' comments (never the '//' of a URL scheme), inline /*...*/
# blocks, '/*'-to-end-of-line openers, and '*'-led doc-block continuation
# lines. Unmarked interior lines of a multi-line /* */ block are the known gap.
_INLINE_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/")
_OPEN_BLOCK_COMMENT_RE = re.compile(r"/\*.*$")
_LINE_COMMENT_RE = re.compile(r"(?:^|(?<=\s))(?:#|//).*$")
_BLOCK_CONTINUATION_RE = re.compile(r"^\s*\*")

# Config templates are never executed: a URL there is a hint for whoever fills
# the file in, not an endpoint the server contacts. (Named independently of the
# providers' sweep list — this is gate semantics, not ingest policy.)
_TEMPLATE_CONFIG_NAMES = {".env.example", ".env.sample"}


def strip_comment_text(line: str) -> str:
    """Remove comment text from one source line (see the note above)."""
    if _BLOCK_CONTINUATION_RE.match(line):
        return ""
    line = _INLINE_BLOCK_COMMENT_RE.sub(" ", line)
    line = _OPEN_BLOCK_COMMENT_RE.sub("", line)
    return _LINE_COMMENT_RE.sub("", line)


_URL_RE = re.compile(r"https?://([A-Za-z0-9*.-]+)")
_BARE_HOST_RE = re.compile(r"^\*$|^[A-Za-z0-9*.-]+\.[A-Za-z]{2,}$")
# Namespace/spec identifiers, not endpoints anyone contacts. Deliberately
# tiny; anything else must be disclosed.
_SPEC_HOSTS = {"www.w3.org", "w3.org", "json-schema.org", "xmlns.com", "purl.org"}

# Output/log/error channels that must never carry a credential.
_ECHO_RE = re.compile(
    r"\b(?:print|console\.log|logging\.(?:debug|info|warning|error|critical|exception)"
    r"|logger\.(?:debug|info|warning|error|critical|exception)|raise\s+\w+)\s*\((?P<args>.*)"
)
_CRED_WORD_RE = re.compile(rf"(?i)\w*{_CRED_NAME}\w*")


def _iter_lines(artifact: ServerArtifact):
    for path, content in artifact.source_files.items():
        for lineno, line in enumerate(content.splitlines(), 1):
            yield path, lineno, line


def _walk_manifest_strings(node, key=""):
    """Yield (key, string_value) pairs from every level of the manifest."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_manifest_strings(v, str(k))
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from _walk_manifest_strings(item, key)
    elif isinstance(node, str):
        yield key, node


def check_hardcoded_credentials(artifact: ServerArtifact) -> list[GateFinding]:
    """Gate 1: credentials hardcoded in source or manifest.

    Vendored bundles are exempt from this gate only — minified assets are
    full of secret-shaped strings, and a real credential belongs to the
    server's own code. Every other gate still scans vendored files.
    """
    vendored = set(artifact.vendored)
    findings = []
    for path, lineno, line in _iter_lines(artifact):
        if path in vendored:
            continue
        if _ENV_REF_RE.search(line):
            continue  # reads from the environment — the approved pattern
        assign = _CRED_ASSIGN_RE.search(line)
        if assign and not _PLACEHOLDER_RE.search(assign.group(1)):
            findings.append(
                GateFinding(
                    gate=GATE_HARDCODED_CREDENTIALS,
                    file=path,
                    line=lineno,
                    snippet=line.strip(),
                    explanation="Credential assigned as a literal instead of read from the environment or a secrets manager.",
                )
            )
        elif _KNOWN_TOKEN_RE.search(line):
            findings.append(
                GateFinding(
                    gate=GATE_HARDCODED_CREDENTIALS,
                    file=path,
                    line=lineno,
                    snippet=line.strip(),
                    explanation="String matches a well-known secret token format.",
                )
            )
    for key, value in _walk_manifest_strings(artifact.manifest):
        if _ENV_REF_RE.search(value) or _PLACEHOLDER_RE.search(value):
            continue
        named_cred = re.search(rf"(?i){_CRED_NAME}", key) and len(value) >= 8
        if named_cred or _KNOWN_TOKEN_RE.search(value):
            findings.append(
                GateFinding(
                    gate=GATE_HARDCODED_CREDENTIALS,
                    file="manifest",
                    line=0,
                    snippet=f"{key}: {value}",
                    explanation="Credential embedded in the manifest instead of referenced from the environment.",
                )
            )
    return findings


def check_unvalidated_input(artifact: ServerArtifact) -> list[GateFinding]:
    """Gate 2: unvalidated input passed into a shell command, file path, or query."""
    findings = []
    for path, lineno, line in _iter_lines(artifact):
        for label, sink_re in _SINKS:
            sink = sink_re.search(line)
            if sink and _DYNAMIC_RE.search(line[sink.start():]):
                findings.append(
                    GateFinding(
                        gate=GATE_UNVALIDATED_INPUT,
                        file=path,
                        line=lineno,
                        snippet=line.strip(),
                        explanation=f"Dynamically-built string passed into a {label} — injection risk.",
                    )
                )
                break  # one finding per line is enough
    return findings


def _disclosed_hosts(manifest: dict) -> set[str]:
    hosts: set[str] = set()
    for _, value in _walk_manifest_strings(manifest):
        for match in _URL_RE.finditer(value):
            hosts.add(match.group(1).lower())
        if _BARE_HOST_RE.match(value):
            hosts.add(value.lower())
    return hosts


def _host_is_disclosed(host: str, disclosed: set[str]) -> bool:
    if host in _SPEC_HOSTS or "*" in disclosed or host in disclosed:
        return True
    # "*.example.com" style wildcard disclosures.
    return any(
        d.startswith("*.") and (host == d[2:] or host.endswith(d[1:])) for d in disclosed
    )


def check_undisclosed_network_calls(artifact: ServerArtifact) -> list[GateFinding]:
    """Gate 3: network calls to endpoints not named in the manifest or docs."""
    disclosed = _disclosed_hosts(artifact.manifest)
    for content in artifact.docs.values():
        for match in _URL_RE.finditer(content):
            disclosed.add(match.group(1).lower())
    findings = []
    for path, lineno, line in _iter_lines(artifact):
        if path.rsplit("/", 1)[-1] in _TEMPLATE_CONFIG_NAMES:
            continue
        for match in _URL_RE.finditer(strip_comment_text(line)):
            host = match.group(1).lower()
            if not _host_is_disclosed(host, disclosed):
                findings.append(
                    GateFinding(
                        gate=GATE_UNDISCLOSED_NETWORK,
                        file=path,
                        line=lineno,
                        snippet=line.strip(),
                        explanation=f"Endpoint '{host}' is contacted but not disclosed anywhere in the manifest.",
                    )
                )
    return findings


def check_credential_echo(artifact: ServerArtifact) -> list[GateFinding]:
    """Gate 4: credentials echoed in tool output, logs, or error messages."""
    findings = []
    for path, lineno, line in _iter_lines(artifact):
        echo = _ECHO_RE.search(line)
        if echo and _CRED_WORD_RE.search(echo.group("args")):
            findings.append(
                GateFinding(
                    gate=GATE_CREDENTIAL_ECHO,
                    file=path,
                    line=lineno,
                    snippet=line.strip(),
                    explanation="Credential-named value written to output, a log, or an error message.",
                )
            )
    return findings


def run_gates(artifact: ServerArtifact) -> list[GateFinding]:
    """Run all four gates and return every finding."""
    return [
        *check_hardcoded_credentials(artifact),
        *check_unvalidated_input(artifact),
        *check_undisclosed_network_calls(artifact),
        *check_credential_echo(artifact),
    ]
