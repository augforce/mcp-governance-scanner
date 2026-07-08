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

### Reports are written for non-experts, with the evidence kept

Every report opens with a plain-English **Bottom line** stating what the verdict means and why,
and every finding is a plain sentence with the engine's technical finding cited beneath it as
evidence and a **suggested fix** where one applies — readable by whoever has to sign off,
auditable by whoever has to verify, actionable for whoever has to remediate. For example:

> **Bottom line:** This server fails automatically because a secret key or password is written
> directly into its code or settings, so anyone who obtains a copy of this server gets the
> secret too. A problem like this is a deal-breaker regardless of how well the server would
> have scored elsewhere, so no category scores are reported.
>
> **Hard gate: Hardcoded credentials**
> - **server.py:7** — Credential assigned as a literal instead of read from the environment or
>   a secrets manager.
>   - `API_KEY = "sk-live-9f8e..."`
>
> **Suggested fix:** Remove the secret from the code, read it from an environment variable or a
> secrets manager instead, and rotate the exposed key — treat it as already leaked.

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

**Web UI:** the home page is a folder picker plus a local-path fallback. Choosing a folder opens
the operating system's native folder browser, and you can point it at a real project's **root**
folder: dependency and system bulk (`.venv`, `node_modules`, `.git`, caches, build output, hidden
folders, files over 1MB, non-source file types) is excluded in the browser *before* upload, using
the same skip list as the server-side sweep. Uploads accept up to 20,000 files after exclusion;
for anything larger, the "enter a folder path" field reads the folder directly on the machine
through the identical pipeline — no upload, no size limit. Either way the scanner checks whether
the folder is actually an MCP server (a manifest file or MCP-server code) and shows the full
report or a plain "No MCP server found in this folder" message. Past scans are stored and
browsable under History.

## Example Scan:
job-match — Approved with Conditions (76/100)
Source: folder · Scanned: 2026-07-08T15:04:41+00:00

**Verdict: Approved with Conditions**

**Bottom line:** This server scored 76 out of 100 on what could be checked — good, but not good enough for automatic approval — it should only be used once the conditions below are addressed. The biggest problem: its tools don't clearly say what they do or check the input they receive. We also could not confirm who publishes or maintains this server, so that part is left out of the score.

Score: **76/100**, based on the 75/100 rubric points that could be verified offline.

**Conditions**

1. Manually review the runtime-built network call destinations flagged under Network & Data Exposure against the disclosed endpoints.
2. Independently verify provenance (Maintenance & Provenance) via the opt-in GitHub check or manual review — self-reported manifest claims are never accepted as evidence of legitimacy.

**Permission & Scope: 100/100**
*Does it ask for only the access it needs?*

- No problems found.

**Tool Definition Hygiene: 40/100**
*Do its tools say what they do and check their inputs?*

- The tool 'score_posting' doesn't say what input it expects.
  - Evidence: Tool 'score_posting' declares no input schema.
  - Suggested fix: Add an inputSchema to the tool listing each parameter and its type.
- The tool 'score_posting' accepts anything sent to it, with no checks or limits.
  - Evidence: Tool 'score_posting' has no input constraints or validation.
  - Suggested fix: Add validation to the schema: mark required fields and set limits (enum, maxLength, minimum/maximum, pattern).
- The tool 'batch_score' doesn't say what input it expects.
  - Evidence: Tool 'batch_score' declares no input schema.
  - Suggested fix: Add an inputSchema to the tool listing each parameter and its type.
- The tool 'batch_score' accepts anything sent to it, with no checks or limits.
  - Evidence: Tool 'batch_score' has no input constraints or validation.
  - Suggested fix: Add validation to the schema: mark required fields and set limits (enum, maxLength, minimum/maximum, pattern).

**Network & Data Exposure: 85/100**
*How widely does it share data over the internet?*

- At career-intelligence/app/main.py:142, the code builds an internet address while running, so we can't confirm where it sends data — a person should check this.
  - Evidence: career-intelligence/app/main.py:142 — network call destination is not statically determinable ('evs = [_ingest(conn, job)[1] for job in MockProvider().fetch()]'); requires manual review against the disclosed endpoints.
  - Suggested fix: Use a fixed URL where possible; if the destination must be configurable, document the allowed endpoint(s) so a reviewer can check them.
- At career-intelligence/app/providers/http.py:22, the code builds an internet address while running, so we can't confirm where it sends data — a person should check this.
  - Evidence: career-intelligence/app/providers/http.py:22 — network call destination is not statically determinable ('with urllib.request.urlopen(req, timeout=timeout) as resp:'); requires manual review against the disclosed endpoints.
  - Suggested fix: Use a fixed URL where possible; if the destination must be configurable, document the allowed endpoint(s) so a reviewer can check them.
- At career-intelligence/app/providers/base.py:7, the code builds an internet address while running, so we can't confirm where it sends data — a person should check this.
  - Evidence: career-intelligence/app/providers/base.py:7 — network call destination is not statically determinable ('def fetch(self) -> list[NormalizedJob]: ...'); requires manual review against the disclosed endpoints.
  - Suggested fix: Use a fixed URL where possible; if the destination must be configurable, document the allowed endpoint(s) so a reviewer can check them.
- At career-intelligence/app/providers/mock.py:34, the code builds an internet address while running, so we can't confirm where it sends data — a person should check this.
  - Evidence: career-intelligence/app/providers/mock.py:34 — network call destination is not statically determinable ('def fetch(self) -> list[NormalizedJob]:'); requires manual review against the disclosed endpoints.
  - Suggested fix: Use a fixed URL where possible; if the destination must be configurable, document the allowed endpoint(s) so a reviewer can check them.

**Maintenance & Provenance: N/A — not independently verified**
*Who publishes it, and is it kept up to date?*

- It doesn't state its repository at all.
  - Evidence: Manifest field 'repository' missing — provenance not verified.
  - Suggested fix: Add the repository field to the manifest so it can be independently verified.
- It says its author is '{'name': 'augforce'}', but nothing confirms that claim.
  - Evidence: Manifest field 'author' claimed as '{'name': 'augforce'}' — not independently verified.
  - Suggested fix: Verify the claim independently — run the opt-in GitHub provenance check (set GITHUB_TOKEN) or review the author by hand.
- It says its version is '1.0.0', but nothing confirms that claim.
  - Evidence: Manifest field 'version' claimed as '1.0.0' — not independently verified.
  - Suggested fix: Verify the claim independently — run the opt-in GitHub provenance check (set GITHUB_TOKEN) or review the version by hand.
- It doesn't state its license at all.
  - Evidence: Manifest field 'license' missing — provenance not verified.
  - Suggested fix: Add the license field to the manifest so it can be independently verified.

## CLI: 

Point it at a directory path directly (optionally with a reviewer-authored intake manifest for a third-party server).

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
- **URLs in comments and config templates are not network calls.** The undisclosed-network gate
  strips comment text (`#`, `//`, `/* */`) and skips `.env.example`-style templates before URL
  detection — a signup link in a comment is guidance for a human, not an endpoint the program
  contacts. Comment stripping is line-based and best-effort; unmarked interior lines of a
  multi-line block comment can still be flagged (a false positive, never a missed real call).
- **Regex-based detection can be evaded** by deliberate obfuscation (string splitting, encoding).
  The scanner is a governance gate for honest-but-flawed servers and a tripwire for lazy
  malicious ones; it is not a substitute for sandboxing or runtime egress controls.

## Architecture

```
providers/local_dir      ingest a server directory (manifest discovery + config/doc sweep)
providers/folder         ingest an uploaded folder tree (browser folder picker); detects
                         whether the folder is an MCP server before scanning
scanning/gates           the four hard gates (regex/pattern static analysis)
scanning/rubric          scored categories -> weighted, normalized score + band
scanning/provenance      opt-in GitHub provenance check (Phase 3)
analysis/explainer       deterministic plain-language report: Bottom line summary, every finding
                         translated to plain English with the technical finding cited as evidence
analysis/claude_judge    optional Claude narrative layer (Phase 3; failures degrade to deterministic)
app/scan.py              orchestrator: ingest -> gates -> rubric -> verdict
```

MIT licensed. The reasoning behind the gate/category split, the weight choices, and the
provenance N/A-then-cap design is written up in [`docs/rubric-design.md`](docs/rubric-design.md).
