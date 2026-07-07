# Rubric Design Rationale

Why the scanner decides the way it does. Written for a reviewer reading this repo cold; the
implementation lives in `scanning/gates.py`, `scanning/rubric.py`, and `config/rubric.yaml`.

## Hard gates and scored categories are different kinds of question

The rubric splits every check into one of two classes, and the split is the design's spine:

- **Hard gates** answer *"is this server disqualified?"* — hardcoded credentials, unvalidated
  input reaching a shell/path/query, undisclosed network calls, credentials echoed to
  output/logs. Any single finding is an automatic **Fail**, and the weighted rubric is never
  even computed.
- **Scored categories** answer *"how good is this server's hygiene?"* — permission scoping,
  tool-definition quality, network exposure, maintenance signals. These trade off against each
  other and aggregate into a 0–100 score.

The reason for the split is that averaging is the wrong operation for disqualifying facts. A
server with a hardcoded API key and otherwise-perfect hygiene would score in the high 80s on any
purely weighted rubric — "Approved" — which is exactly the wrong answer: the key is a breach
waiting to happen regardless of how tidy the tool schemas are. Gates make disqualification
*incompressible*: no amount of excellence elsewhere can buy back a gate. This mirrors how human
review boards actually operate — some findings end the conversation — and it keeps the weighted
score honest, because the score never has to carry the burden of catastrophic findings; it only
ranks servers that have already cleared the floor.

The four gates were chosen because each one is (a) close to unambiguous when detected statically,
(b) high-severity regardless of context, and (c) common enough in the wild to be worth automating.
Broad-but-*disclosed* access deliberately did not make the list — it's a judgment call, so it's
scored and surfaced as a condition instead (see the fetch server case below).

## Weight choices (30 / 25 / 20 / 25)

Weights are fixed in `config/rubric.yaml` and validated to sum to 100 on load — a scanner whose
weights can drift silently is a scanner whose historical scores can't be compared.

| Category | Weight | Why this weight |
|---|---|---|
| Permission & Scope | 30 | The single best static predictor of blast radius. An MCP server's permissions are what an attacker inherits if anything else goes wrong, so the widest grant deserves the largest weight. It is also the category a submitter can most directly fix (scope the grant down). |
| Tool Definition Hygiene | 25 | Tool descriptions and input schemas are the *contract* the LLM sees. Vague descriptions and unconstrained inputs are how confused-deputy problems start — the model can't respect boundaries nobody declared. Weighted just below permissions because bad hygiene is an enabler of harm rather than harm itself. |
| Network & Data Exposure | 20 | Lowest weight because everything here is *disclosed* behavior — broad-but-declared scopes, many third-party flows, destinations that need manual review. Undisclosed traffic is a gate, not a deduction, so this category only prices legitimate-but-noteworthy exposure. |
| Maintenance & Provenance | 25 | Weighted like hygiene because an unmaintained or unverifiable server accrues risk over time even if today's code is clean. Scored only from independently verified facts — see below. |

Deduction sizes inside each category follow one rule: a wildcard/unbounded grant costs roughly
half the category (it defeats the category's purpose), a noteworthy-but-legitimate pattern costs
10–15 points (it needs review, not rejection).

### Bands

**85–100 Approved · 60–84 Approved with Conditions · <60 Review Required.** The middle band is
deliberately wide: most real servers land there, and the interesting output for a governance
process is not the number but the *conditions list* — every Approved-with-Conditions verdict
enumerates exactly what a reviewer must resolve (scope down this grant, verify that provenance,
manually check these runtime-built destinations). The bands gate the workflow; the conditions
carry the information.

## Provenance: N/A offline, and the cap

Maintenance & Provenance is the one category the manifest cannot be trusted to self-report.
Repository URL, author, version, license — a malicious server can claim all of it, so a
well-written manifest scoring full provenance marks would be the scanner laundering the server's
own assertions into apparent legitimacy.

Offline, the category is therefore **N/A**: score `None`, excluded from the weighted total
(which is renormalized over the 75/100 weight actually assessed and labeled as such), with the
claims enumerated as findings — `"repository claimed as X — not independently verified"` — so a
human can check them. Unknown is treated as *unknown*, not as zero (that would punish honest
servers for the scanner's own offline-ness) and not as full marks (the original sin).

Two design consequences:

1. **The verdict cap.** A server can never reach plain Approved offline: any unverified category
   caps the verdict at Approved with Conditions, the condition being "verify provenance." The
   deterministic offline scan is a *screening* verdict by construction.
2. **Verification lifts the cap mechanically.** The opt-in GitHub check (`GITHUB_TOKEN` set)
   replaces the N/A with a score derived from verified facts — the repo exists and matches the
   claim (20), push recency (40), open-issue load (25), license present (15) — restoring the full
   100 assessed weight and letting a healthy server reach Approved. Every failure path of that
   check degrades back to "not verified"; absence of a network check never silently passes.

## Soft flags: the boundary between detection and judgment

Static analysis has a hard boundary: a URL assembled at runtime from an environment variable
cannot be checked against the manifest without executing the server, which this tool never does.
Making that pattern a hard gate would fail every server that configures endpoints via env vars —
i.e., it would punish a best practice. So non-literal network destinations are a **soft flag**:
a Network & Data Exposure deduction marked "requires manual review," feeding the conditions list
rather than the fail path. The same philosophy governs vendored assets (scanned by every check
except the credential gate, which minified bundles would flood with secret-shaped noise) and the
scanner's posture generally: where detection is reliable, automate the verdict; where it isn't,
price the uncertainty and hand the reviewer a specific question.

## Calibration against real servers

The labeled corpus (`corpus/`, `tests/test_corpus.py`) is the rubric's regression harness:
Anthropic's reference `time` and `fetch` servers, real-world servers scanned in place, and
hand-built bad servers that each trip exactly one gate. Calibration on real code drove several
rules in this repo — test directories excluded from the sweep (dummy keys/URLs), a five-host
spec-namespace allowlist (`www.w3.org` is an identifier, not an endpoint), `setenv(` joining the
approved env-var family. The `fetch` server is the rubric's character witness: it *honestly
declares* wildcard network access, trips no gate, and scores 80 — Approved with Conditions, with
the condition naming the wildcard. Honesty about broad access is priced, not failed; concealing
that same traffic would have been a gate.
