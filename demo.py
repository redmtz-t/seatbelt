#!/usr/bin/env python3
"""
demo.py — REDMTZ Seatbelt CLI Demo (RDM-025)

Shows Seatbelt in 60 seconds:
  1. Genesis block created on first run (Ed25519 keypair auto-generated)
  2. Safe action → ALLOWED + signed envelope
  3. Dangerous action → BLOCKED + signed envelope with remediation hint
  4. Audit trail query — cryptographic proof printed

Run:
    python demo.py

Founder: Robert Benitez
"""

import hashlib
import json
import sys
import time


def _header(text: str):
    width = 62
    print()
    print("─" * width)
    print(f"  {text}")
    print("─" * width)


def _step(n: int, text: str):
    print(f"\n[{n}] {text}")


def _ok(text: str):
    print(f"    ✅  {text}")


def _block(text: str):
    print(f"    🔴  {text}")


def _info(text: str):
    print(f"    ℹ️   {text}")


def _pause(ms: int = 400):
    time.sleep(ms / 1000)


def run_demo():
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║          REDMTZ Seatbelt — Governance Demo               ║")
    print("║   Cryptographic proof before AI agent actions execute    ║")
    print("╚══════════════════════════════════════════════════════════╝")

    # ── Step 1: Import and genesis ────────────────────────────────────────────
    _header("STEP 1 — Import Seatbelt (3 lines of code)")
    print("""
    from redmtz import govern, GovernanceBlocked

    @govern(rules="destructive_actions", policy="safe_defaults")
    def execute_sql(query: str):
        return f"DB: {query}"
""")
    _pause(600)

    from redmtz import govern, GovernanceBlocked
    from redmtz import sudo_signing
    sudo_signing.ensure_keypair()

    _ok("Seatbelt imported")
    _ok(f"Genesis keypair: ~/.redmtz/keys/sudo_signing.pub")
    _ok("Every decision from this point is signed and hash-chained")
    _pause(800)

    # Define the governed function
    @govern(rules="destructive_actions", policy="safe_defaults")
    def execute_sql(query: str):
        return f"DB result: {query}"

    # ── Step 2: Safe action ───────────────────────────────────────────────────
    _header("STEP 2 — Safe action (SELECT) → ALLOWED")
    safe_query = "SELECT * FROM users WHERE id = 42"
    print(f"\n    execute_sql(\"{safe_query}\")\n")
    _pause(500)

    t0 = time.perf_counter()
    result = execute_sql(safe_query)
    elapsed = (time.perf_counter() - t0) * 1000

    _ok(f"ALLOWED — {result}")
    _ok(f"Signed envelope logged to audit ledger ({elapsed:.1f}ms)")
    _ok("governance_mode: deterministic")
    _pause(800)

    # ── Step 3: Dangerous action blocked ─────────────────────────────────────
    _header("STEP 3 — Dangerous action (DROP TABLE) → BLOCKED")
    dangerous_query = "DROP TABLE users"
    print(f"\n    execute_sql(\"{dangerous_query}\")\n")
    _pause(500)

    blocked_envelope = None
    try:
        execute_sql(dangerous_query)
    except GovernanceBlocked as e:
        blocked_envelope = e.envelope
        _block(f"BLOCKED — Pattern: {e.pattern.pattern_id}")
        _block(f"Risk level: {e.pattern.risk_level}")
        print()
        print(f"    Remediation hint:")
        print(f"    {e.pattern.remediation_hint[:80]}...")
        _pause(800)

    # ── Step 4: Show the signed envelope ─────────────────────────────────────
    _header("STEP 4 — Cryptographic proof (signed envelope)")

    if blocked_envelope:
        event_id       = blocked_envelope.get("event_id", "")
        current_hash   = blocked_envelope.get("hash_chain", {}).get("current_hash", "")
        previous_hash  = blocked_envelope.get("hash_chain", {}).get("previous_hash", "")
        gov_mode       = blocked_envelope.get("governance_mode", "")
        sigs           = blocked_envelope.get("signatures", [])
        sig_val        = sigs[0].get("signature", "") if sigs else ""
        gate           = blocked_envelope.get("gate_decisions", [{}])[0]

        print(f"""
    event_id:         {event_id}
    governance_mode:  {gov_mode}
    gate:             {gate.get('gate')} → {gate.get('decision').upper()}
    reason:           {gate.get('reason')}

    hash_chain:
      previous_hash:  {previous_hash[:32]}...
      current_hash:   {current_hash[:32]}...

    signature (Ed25519):
      {sig_val[:48]}...
      type: self-signed
""")
        _ok("Tamper-evident — modify any field and the hash breaks")
        _ok("Ed25519 signed — verifiable by any auditor with the public key")
        _ok("Hash-chained — every decision anchors to the one before it")

    _pause(800)

    # ── Step 5: What this means ───────────────────────────────────────────────
    _header("STEP 5 — What your compliance team sees")
    print("""
    When a regulator asks: "What did your AI agent do?"

    You don't say "we think it was safe."
    You say: "Here is the signed, chained, cryptographic proof
              of every action it attempted — including the ones
              we blocked before they executed."

    That's not a dashboard. That's evidence.
""")

    _ok("pip install redmtz")
    _ok("3 lines of code")
    _ok("Zero cloud. Zero LLM. Zero infrastructure.")
    _ok("Cryptographic governance from line one.")

    print()
    print("─" * 62)
    print("  REDMTZ Seatbelt — redmtz.com")
    print("  Genesis block created. Audit trail active.")
    print("─" * 62)
    print()


if __name__ == "__main__":
    run_demo()
