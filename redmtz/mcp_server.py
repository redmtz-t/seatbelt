# Copyright 2026 Robert Benitez
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
redmtz.mcp_server — Seatbelt MCP Server (RDM-032)
REDMTZ Seatbelt

stdio transport for Claude Code, Claude Desktop, and Cline.
Every tool call is evaluated synchronously against the destructive
pattern library. Signed envelope written to SQLite before return.
No async. No background queue. Decision on the ledger before the
agent gets an answer.

First-run behavior (zero config):
  - Ed25519 keypair auto-generated to ~/.redmtz/keys/
  - SQLite database auto-initialized at ~/.redmtz/redmtz_audit.db
  - safe_defaults policy active immediately

Start via CLI:
    redmtz serve

Or directly:
    python -m redmtz.mcp_server

Known limitation (post-Wednesday):
  # TODO: Add WAL pre-signed stub buffer for async crash-gap resilience
  # on any future async allow path. Current synchronous design has no gap —
  # envelope is on the ledger before return. If async is introduced later,
  # implement write-ahead log: stub → queue → full sign + delete stub.

Founder: Robert Benitez
"""

import sqlite3
import sys
from typing import Optional

from mcp.server.fastmcp import FastMCP

from . import database
from . import sudo_signing
from .envelope import CanonicalEnvelope
from .patterns import PatternMatcher
from .policies import get_policy, policy_decision
from .whitelist import WhitelistMatcher

# ── Module-level singletons ───────────────────────────────────────────────────
mcp        = FastMCP("redmtz-seatbelt")
_matcher   = PatternMatcher()
_ce        = CanonicalEnvelope()
_whitelist = WhitelistMatcher()  # empty by default — loaded via --whitelist flag


def _initialize(policy_name: str = "safe_defaults", whitelist_path: str = "") -> None:
    """
    First-run setup: keypair, database, policy validation, optional whitelist.
    Called by CLI before mcp.run(). Safe to call multiple times.
    """
    global _whitelist
    sudo_signing.ensure_keypair()
    database.init_db()
    get_policy(policy_name)  # warns to stderr if unknown, falls back to safe_defaults

    if whitelist_path:
        _whitelist = WhitelistMatcher(whitelist_path)

    whitelist_status = (
        f"{_whitelist.get_role()} ({len(_whitelist.list_patterns())} patterns)"
        if _whitelist.is_loaded() else "none"
    )

    print(
        f"[redmtz][SEATBELT] v1.3.2 — MCP governance server ready.\n"
        f"  Transport:  stdio\n"
        f"  Policy:     {policy_name}\n"
        f"  Whitelist:  {whitelist_status}\n"
        f"  Keys:       {sudo_signing.PUBLIC_KEY_PATH}\n"
        f"  Audit DB:   {database.DB_NAME}\n"
        f"  Patterns:   13 active\n"
        f"  Mode:       deterministic (synchronous — all paths)\n"
        f"  Crash gap:  none (envelope written before return)",
        file=sys.stderr,
    )


# ── Tools ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def govern_action(
    action: str,
    intent: str = "",
    policy: str = "safe_defaults",
    environment: str = "",
) -> dict:
    """
    Evaluate an action against the REDMTZ destructive pattern library.

    Returns a governance decision (ALLOW or BLOCK) with a cryptographically
    signed envelope as proof. The envelope is written to the audit ledger
    before this function returns — every decision is on the record.

    Args:
        action:      The action string to evaluate. SQL query, shell command,
                     file path, or any string the agent is about to execute.
        intent:      Optional stated intent from the agent (for audit context).
        policy:      Policy template. Options: safe_defaults, read_only,
                     audit_mode, strict_prod. Default: safe_defaults.
        environment: Deployment context (prod/staging/dev). Overrides
                     REDMTZ_ENVIRONMENT env var for this call.

    Returns:
        dict with decision (ALLOW|BLOCK), reason, patterns_matched,
        envelope_hash, signature, governance_mode, sig_alg.
        Blocked responses also include remediation hints.
    """
    # ── Layer 1: Blocklist (immutable, always runs) ───────────────────────────
    matched = _matcher.match_all(action, "*")

    # ── Layer 2: Policy + Whitelist decision ──────────────────────────────────
    policy_data       = get_policy(policy)
    whitelist_mode    = policy_data.get("whitelist_mode", False)
    blocklist_hit     = any(
        policy_decision(policy_data, p.risk_level) == "block"
        for p in matched
    )

    if blocklist_hit:
        # Blocklist wins — always block regardless of whitelist
        should_block = True
        reason = " | ".join(p.pattern_id for p in matched)
    elif whitelist_mode and _whitelist.is_loaded():
        # Whitelist mode: only allow if action matches an approved pattern
        wl_match = _whitelist.match(action)
        if wl_match:
            should_block = False
            reason = f"whitelist match — {wl_match.pattern_id}"
        else:
            should_block = True
            reason = "implicit deny — action not in approved whitelist"
    elif not matched and policy_data.get("default_action") == "block":
        # strict_prod implicit deny (no whitelist loaded)
        should_block = True
        reason = "implicit deny — action not in approved pattern set"
    else:
        should_block = False
        reason = (
            " | ".join(p.pattern_id for p in matched)
            if matched else "no patterns matched"
        )

    decision = "BLOCK" if should_block else "ALLOW"
    patterns_list    = [p.pattern_id for p in matched]
    remediation_text = (
        "\n".join(f"[{p.pattern_id}] {p.remediation_hint}" for p in matched)
        if should_block else ""
    )

    # Step 3: Build signed envelope — synchronous, no exceptions
    envelope = _ce.build(
        actor={
            "type":              "agent",
            "identity":          "mcp-client",
            "credential_method": "mcp-stdio",
        },
        action={
            "verb":     "execute",
            "domain":   "*",
            "resource": action[:128],
        },
        gate_decisions=[{
            "gate":       "seatbelt",
            "decision":   decision.lower(),
            "reason":     reason,
            "latency_us": 0,
            "patterns":   patterns_list,
        }],
        policy={
            "name":    policy,
            "version": "1.0.0",
            "hash":    "",
            "whitelist_hash": _whitelist.get_file_hash() if _whitelist.is_loaded() else "",
            "whitelist_role": _whitelist.get_role() if _whitelist.is_loaded() else "",
        },
        execution_result={"status": decision.lower()},
        input_content=action,
        input_token_count=len(action.split()),
        input_classification="unknown",
        model={
            "name":    "redmtz-seatbelt",
            "version": "1.3.2",
            "runtime": "symbolic",
        },
        sign=True,
        governance_mode="deterministic",
    )

    envelope_hash_full = envelope["hash_chain"]["current_hash"]
    sigs               = envelope.get("signatures", [])
    sig_value          = sigs[0].get("signature", "") if sigs else ""

    # Step 4: Write to audit ledger — synchronous, on record before return
    database.log_audit(
        intent=intent or "mcp_govern",
        command=action[:256],
        verdict=decision,
        reason=reason,
        skill="seatbelt-mcp",
        agent_id="mcp-client",
        envelope=envelope,
        # v3 metadata
        sig_alg="sha256+ed25519",
        environment=environment or None,  # None → falls back to REDMTZ_ENVIRONMENT
        policy=policy,
        patterns_matched=patterns_list,
        envelope_hash=envelope_hash_full,
        remediation=remediation_text,
    )

    # Step 5: Build response
    result = {
        "decision":         decision,
        "reason":           reason,
        "patterns_matched": patterns_list,
        "envelope_hash":    envelope_hash_full[:16] + "...",
        "signature":        sig_value[:32] + "..." if sig_value else "",
        "governance_mode":  "deterministic",
        "sig_alg":          "sha256+ed25519",
    }

    if should_block:
        result["remediation"] = remediation_text

    return result


@mcp.tool()
def audit_trail(limit: int = 10) -> dict:
    """
    Query the most recent governance decisions from the audit ledger.

    Args:
        limit: Number of recent entries to return (max 100). Default: 10.

    Returns:
        dict with entries list and returned count. Each entry includes
        environment, policy, patterns_matched, and envelope_hash fields.
    """
    limit = min(max(1, limit), 100)

    try:
        conn   = sqlite3.connect(database.DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp_utc, environment, agent_id, intent,
                   command, verdict, reason, policy, patterns_matched,
                   envelope_hash, sig_alg
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        conn.close()

        entries = [
            {
                "id":               row[0],
                "timestamp":        row[1],
                "environment":      row[2] or "unknown",
                "agent_id":         row[3],
                "intent":           row[4],
                "command":          row[5][:64] + "..." if len(row[5]) > 64 else row[5],
                "verdict":          row[6],
                "reason":           row[7],
                "policy":           row[8] or "unknown",
                "patterns_matched": row[9].split("|") if row[9] else [],
                "envelope_hash":    (row[10][:16] + "...") if row[10] else "",
                "sig_alg":          row[11] or "sha256+ed25519",
            }
            for row in rows
        ]

        return {"entries": entries, "returned": len(entries)}

    except Exception as e:
        return {"error": str(e), "entries": [], "returned": 0}


@mcp.tool()
def verify_chain() -> dict:
    """
    Walk the entire audit ledger and verify every hash link.
    Returns chain validity, total entry count, and the first broken link if any.
    """
    return database.verify_chain()


@mcp.tool()
def export_audit_csv(output_path: str = "") -> dict:
    """
    Export the full audit ledger as a CISO-ready signed CSV.

    Every row is exported with environment, policy, patterns_matched,
    sig_alg, and envelope_hash columns. The CSV is hashed (SHA-256) and
    signed with the Ed25519 governance key — any auditor with the public
    key can verify the export was not tampered with after generation.

    Args:
        output_path: Optional file path to write the CSV (e.g. /tmp/audit.csv).
                     If empty, the CSV is returned as a string in the response.

    Returns:
        dict with csv_hash, signature, total_rows, public_key_path.
        If output_path is empty, also includes csv_content.
    """
    return database.export_csv(output_path or None)


if __name__ == "__main__":
    _initialize()
    mcp.run(transport="stdio")
