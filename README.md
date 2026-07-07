# MCP Server Security & Governance Scanner

A static-analysis tool that ingests an MCP (Model Context Protocol) server — its manifest and
source — and produces a scored, explained governance verdict: **Approved**, **Approved with
Conditions**, **Review Required**, or an automatic **Fail** when a hard gate trips.

Built as a pre-deployment review gate: the kind of check an AI-governance function runs on every
internal or third-party MCP server *before* it's allowed near production. Deterministic first —
the full scan runs offline with no API key and no network. An optional Claude layer (narrative
explanations) and an optional GitHub provenance check plug in on top and never override the
deterministic result.

## How it decides

### Hard gates — any one is an automatic Fail, regardless of score

1. **Hardcoded credentials** in source or manifest (vs. environment variables / secrets manager)
2. **Unvalidated input** passed directly into a shell command, file path, or query string
3. **Undisclosed network calls** to endpoints not named in the manifest or documentation
4. **Credentials echoed** in tool output, logs, or error messages

### Scored categories — weights fixed, validated to sum to 100

| Category | Weight | What it checks |
|---|---|---|
| Permission & Scope | 30 | Requested filesystem/network access vs. need; wildcard or unbounded grants |
| Tool Definition Hygiene | 25 | Description specificity; input schemas and validation constraints |
| Network & Data Exposure | 20 | Disclosed-but-broad scopes; endpoints that can't be statically verified |
| Maintenance & Provenance | 25 | **Offline: N/A by design** — see below. Verified via opt-in GitHub check |

### Bands

**85–100** Approved · **60–84** Approved with Conditions · **below 60** Review Required ·
**any gate tripped** Fail.

### Provenance is never taken on faith

Everything a manifest says about itself (repository, author, version, license) is self-reported —
a malicious server can claim all of it. Offline, Maintenance & Provenance is therefore reported as
**N/A — not independently verified**: the claims are listed for the reviewer, the category is
excluded from the weighted total (the score is reported against the assessed 75/100 weight), and
the verdict is **capped at Approved with Conditions**. No server reaches plain Approved on its own
claims; the condition is verifying provenance.

## Usage

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m app.scan <server-directory> [intake-manifest.json]   # CLI
.venv/bin/python -m app.main    # web UI + scan history at http://127.0.0.1:8901
.venv/bin/pytest -q   # tests are fully offline: API keys cleared, sockets blocked
```

Optional layers (both strictly additive — the deterministic verdict never depends on them):

- `GITHUB_TOKEN` set → the provenance check runs, scoring Maintenance & Provenance from
  verified repository facts (commit recency, open issues, license) and lifting the
  Approved-with-Conditions cap. Any failure degrades back to "not verified."
- `ANTHROPIC_API_KEY` set (plus `pip install anthropic`) → a Claude-written plain-English
  narrative appears above the deterministic report. Every failure path returns nothing and
  the deterministic report stands; Claude never re-scores or overrides a gate.

The scanner looks for `manifest.json` / `manifest.yaml` in the server directory, falls back to
metadata synthesized from `pyproject.toml` / `package.json`, or accepts an explicit intake
manifest authored by the reviewer (the normal path for third-party servers). Rubric weights and
band thresholds live in `config/rubric.yaml` and are validated on load.

## Test corpus

The regression suite includes real servers with labeled expected verdicts:

- **Known good:** Anthropic's reference `time` and `fetch` servers (vendored, MIT), plus the
  author's real-world MCP servers scanned in place from machine-local paths (declared in a
  gitignored `corpus/intake/local_servers.json`; their source and intake manifests are
  deliberately not part of this repo, and those tests skip cleanly on a fresh clone). All pass
  gates cleanly; `fetch` honestly declares wildcard network access and scores 80 (Approved with
  Conditions).
- **Known bad (hand-built):** a server with a hardcoded API key, one passing tool input to
  `os.system`, one phoning home to an undisclosed telemetry endpoint — each trips exactly its
  gate — and one wildcard-everything server that trips no gate but scores 27 (Review Required).

## Known limitations

Static analysis has boundaries, and this tool reports them rather than pretending otherwise:

- **The server is never executed.** All detection is pattern-based inspection of source and
  manifest. Behavior that only exists at runtime is out of scope by design.
- **Runtime-assembled network destinations can't be checked against disclosures.** A URL built
  from an environment variable or config value at runtime is invisible to the
  undisclosed-network gate. Instead of a hard fail (env-based endpoint configuration is
  legitimate practice), these calls are **soft-flagged** — a Network & Data Exposure deduction
  marked "requires manual review." Aliased HTTP clients (e.g. `client = AsyncClient(); client.get(url)`)
  may evade even the soft flag.
- **Offline provenance is N/A, not a score** (see above). The GitHub-based check is opt-in and
  its absence is always reported as "not verified," never silently passed.
- **The server's own test directories are excluded** from the directory sweep: dummy keys and
  dummy URLs in test fixtures are noise, not deployed behavior. A malicious payload hidden in a
  test directory would evade the scan — but it would also never be loaded by the MCP runtime.
- **Vendored bundles (vendor/ dirs, minified assets) are scanned like all other code** — an
  undisclosed network call in a bundled dependency still trips the gate — but they are exempt
  from the hardcoded-credentials gate specifically, which minified code would flood with
  secret-shaped noise. Install trees (`node_modules/`, `.venv/`) are excluded entirely:
  auditing the installed dependency tree is a supply-chain scanner's job, not this tool's.
- **Regex-based detection can be evaded** by deliberate obfuscation (string splitting, encoding).
  The scanner is a governance gate for honest-but-flawed servers and a tripwire for lazy
  malicious ones; it is not a substitute for sandboxing or runtime egress controls.

## Architecture

```
providers/local_dir      ingest a server directory (manifest discovery + config/doc sweep)
providers/upload         ingest uploaded files
scanning/gates           the four hard gates (regex/pattern static analysis)
scanning/rubric          scored categories -> weighted, normalized score + band
scanning/provenance      opt-in GitHub provenance check (Phase 3)
analysis/explainer       deterministic markdown report of every finding (default, offline)
analysis/claude_judge    optional Claude narrative layer (Phase 3; failures degrade to deterministic)
app/scan.py              orchestrator: ingest -> gates -> rubric -> verdict
```

MIT licensed. The reasoning behind the gate/category split, the weight choices, and the
provenance N/A-then-cap design is written up in [`docs/rubric-design.md`](docs/rubric-design.md).
