"""Optional Claude layer: a plain-English narrative on top of the
deterministic verdict.

Strictly additive. It activates only when ANTHROPIC_API_KEY is set, receives
the already-computed deterministic report, and is instructed to explain it —
never to re-score, soften a gate, or override the verdict. Every failure path
(SDK missing, network down, API error, empty response) returns None and the
deterministic result stands untouched.
"""

from __future__ import annotations

import os

from scanning.models import ScanResult

MODEL = "claude-opus-4-8"

SYSTEM_PROMPT = (
    "You are the explanation layer of an MCP-server security governance scanner. "
    "You receive a deterministic scan report whose verdict, score, and findings "
    "are already final. Write a short plain-English narrative (2-4 paragraphs) for "
    "a non-security stakeholder: what the verdict means, why the scanner reached "
    "it, and what to do next. Do not re-score, soften, or second-guess any "
    "finding, gate, or verdict — the deterministic result is authoritative. Cite "
    "specific findings from the report when explaining."
)


def narrative(result: ScanResult, server_name: str | None = None) -> str | None:
    """Return a plain-English narrative for the scan, or None (never raises)."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        import anthropic

        from analysis.explainer import explain

        report = explain(result)
        heading = f"Server under review: {server_name}\n\n" if server_name else ""
        client = anthropic.Anthropic()
        response = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            thinking={"type": "adaptive"},
            system=SYSTEM_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": f"{heading}Deterministic scan report:\n\n{report}",
                }
            ],
        )
        text = "".join(
            block.text for block in response.content if block.type == "text"
        ).strip()
        return text or None
    except Exception:
        return None  # the deterministic verdict stands
