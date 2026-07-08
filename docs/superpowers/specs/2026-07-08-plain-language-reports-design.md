# Plain-Language Scan Reports — Design

**Date:** 2026-07-08
**Status:** Approved (user selected "Summary + plain details" style and approved this design)

## Problem

The deterministic scan report leads with jargon ("scored on 75/100 assessed rubric
weight", "Wildcard or unbounded filesystem grant", "provenance") and never states in
plain terms *why* a server got its verdict. A non-expert reading a report cannot tell
what is wrong or what to do about it.

## Decision

Rewrite report **presentation only**, entirely inside `analysis/explainer.py`. The
scanning engine's finding strings are unchanged — they remain the technical evidence,
`_conditions()` pattern-matches on them, and engine tests assert on them. The report
stays deterministic, offline, and fully cited (CLAUDE.md hard constraints).

## Report shape (both Fail and scored verdicts)

1. **Bottom line** — opening paragraph, composed deterministically from the result,
   answering "what happened and why" in everyday words:
   - Fail: names the gate(s) in plain terms and says the fail is automatic
     ("contains a password/API key written directly in its code…").
   - Scored verdicts: rounded score, the band threshold it fell under/over, and the
     one or two worst-scoring categories phrased plainly.
   - The "assessed weight" caveat becomes: "We could not verify who publishes this
     server; that part is not counted in the score."
2. **Plain findings with evidence kept** — each engine finding is translated via a
   deterministic lookup over the closed set (~15) of finding patterns the engine can
   emit, rendered as a plain sentence; the original technical finding text and any
   snippet/location stay as an indented evidence line beneath it. A finding matching
   no pattern falls back to being rendered as-is — never dropped.
3. **Humanized scores** — `26.6667/100` → `27/100`; each category header carries a
   one-line plain description of what the category measures.

## Out of scope

- Web template changes (report renders in the same `<pre>` block).
- The optional Claude narrative layer (unchanged; sits on top as before).
- Any change to gates, rubric, scoring, or finding strings.

## Testing

Update `tests/test_explainer.py`:
- Every verdict type produces a Bottom line section.
- Each finding pattern translates to its plain sentence; evidence line preserved.
- Unknown finding strings fall back verbatim.
- Existing guarantees hold: offline, deterministic, every finding cited,
  conditions still tied to their causes.
