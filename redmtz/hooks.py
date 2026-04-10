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
redmtz.hooks — Harness-level enforcement for agent platforms (RDM-045)
REDMTZ Seatbelt

PreToolUse gate for Claude Code. Reads tool call JSON from stdin,
evaluates against the destructive pattern library, returns a
permissionDecision to the harness. Every decision gets a signed
envelope on the audit ledger before the response is emitted.

This is ENFORCED governance — the agent cannot bypass it.

Usage (standalone):
    echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' | \\
        python -m redmtz.hooks

Usage (via CLI installer):
    redmtz hook install claude-code

Founder: Robert Benitez
"""

import json
import os
import sys

from . import database
from . import sudo_signing
from .envelope import CanonicalEnvelope
from .patterns import PatternMatcher
from .policies import get_policy, policy_decision
from .whitelist import WhitelistMatcher

# ── Singletons ───────────────────────────────────────────────────────────────

_matcher   = PatternMatcher()
_ce        = CanonicalEnvelope()
_whitelist = WhitelistMatcher()

# ── Configuration ────────────────────────────────────────────────────────────

POLICY = os.environ.get("REDMTZ_HOOK_POLICY", "safe_defaults")
WHITELIST_PATH = os.environ.get("REDMTZ_HOOK_WHITELIST", "")

# Tools that carry destructive potential — these get governed
GOVERNED_TOOLS = {"Bash", "Edit", "Write", "WebFetch", "Agent"}

# Tools that are read-only — allow by default
READONLY_TOOLS = {"Read", "Glob", "Grep", "WebSearch"}


def _extract_action(tool_name: str, tool_input: dict) -> str:
    """
    Convert a Claude Code tool call into an action string
    that the pattern matcher can evaluate.
    """
    if tool_name == "Bash":
        return tool_input.get("command", "")
    elif tool_name == "Write":
        return f"write_file {tool_input.get('file_path', '')}"
    elif tool_name == "Edit":
        return f"edit_file {tool_input.get('file_path', '')}"
    elif tool_name == "WebFetch":
        return f"fetch_url {tool_input.get('url', '')}"
    elif tool_name == "Agent":
        return f"spawn_agent {tool_input.get('description', '')}"
    else:
        return json.dumps(tool_input)[:256]


def gate(hook_input: dict, policy: str = "", whitelist_path: str = "") -> dict:
    """
    Evaluate a Claude Code tool call against Seatbelt governance.

    Args:
        hook_input: The JSON object Claude Code passes via stdin.
        policy: Policy name override. Falls back to REDMTZ_HOOK_POLICY env var.
        whitelist_path: Whitelist file override. Falls back to REDMTZ_HOOK_WHITELIST env var.

    Returns:
        dict suitable for Claude Code hookSpecificOutput.
    """
    global _whitelist

    policy = policy or POLICY
    wl_path = whitelist_path or WHITELIST_PATH

    # Initialize on first call
    sudo_signing.ensure_keypair()
    database.init_db()

    if wl_path and not _whitelist.is_loaded():
        _whitelist = WhitelistMatcher(wl_path)

    tool_name  = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    # Read-only tools pass through without governance
    if tool_name in READONLY_TOOLS:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
            }
        }

    # Non-governed tools that aren't in either list — allow but log
    if tool_name not in GOVERNED_TOOLS:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
            }
        }

    # ── Govern the action ────────────────────────────────────────────────────
    action = _extract_action(tool_name, tool_input)

    # Layer 1: Blocklist (immutable)
    matched = _matcher.match_all(action, "*")

    # Layer 2: Policy + Whitelist
    policy_data    = get_policy(policy)
    whitelist_mode = policy_data.get("whitelist_mode", False)
    blocklist_hit  = any(
        policy_decision(policy_data, p.risk_level) == "block"
        for p in matched
    )

    # Check for escalation patterns (RB Directive / AI Sudo)
    escalation_match = (
        _whitelist.match_escalation(action)
        if _whitelist.is_loaded() else None
    )

    if blocklist_hit:
        should_block = True
        should_escalate = False
        reason = " | ".join(p.pattern_id for p in matched)
    elif escalation_match:
        # Escalation always takes priority over whitelist allow
        should_block = False
        should_escalate = True
        reason = f"RB Directive required — {escalation_match.pattern_id}: {escalation_match.reason}"
    elif whitelist_mode and _whitelist.is_loaded():
        wl_match = _whitelist.match(action)
        if wl_match:
            should_block = False
            should_escalate = False
            reason = f"whitelist match — {wl_match.pattern_id}"
        else:
            should_block = True
            should_escalate = False
            reason = "implicit deny — action not in approved whitelist"
    elif not matched and policy_data.get("default_action") == "block":
        should_block = True
        should_escalate = False
        reason = "implicit deny — action not in approved pattern set"
    else:
        should_block = False
        should_escalate = False
        reason = (
            " | ".join(p.pattern_id for p in matched)
            if matched else "no patterns matched"
        )

    decision = "BLOCK" if should_block else ("ESCALATE" if should_escalate else "ALLOW")
    patterns_list  = [p.pattern_id for p in matched]
    remediation    = (
        "; ".join(f"[{p.pattern_id}] {p.remediation_hint}" for p in matched)
        if should_block else ""
    )

    # ── Build signed envelope ────────────────────────────────────────────────
    envelope = _ce.build(
        actor={
            "type":              "agent",
            "identity":          f"claude-code-hook",
            "credential_method": "pre-tool-use-hook",
        },
        action={
            "verb":     tool_name.lower(),
            "domain":   "claude-code",
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

    # ── Write to audit ledger ────────────────────────────────────────────────
    envelope_hash = envelope["hash_chain"]["current_hash"]
    sigs          = envelope.get("signatures", [])
    sig_value     = sigs[0].get("signature", "") if sigs else ""

    database.log_audit(
        intent=f"hook:{tool_name}",
        command=action[:256],
        verdict=decision,
        reason=reason,
        skill="seatbelt-hook",
        agent_id=os.environ.get("REDMTZ_AGENT_ID", "claude-code-hook"),
        envelope=envelope,
        sig_alg="sha256+ed25519",
        environment=os.environ.get("REDMTZ_ENVIRONMENT", ""),
        policy=policy,
        patterns_matched=patterns_list,
        envelope_hash=envelope_hash,
        remediation=remediation,
    )

    # ── Return decision to Claude Code ───────────────────────────────────────
    if should_block:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"[SEATBELT] {decision}: {reason}. {remediation}"
                ),
            }
        }
    elif should_escalate:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": (
                    f"[SEATBELT] {decision}: {reason}"
                ),
            }
        }
    else:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
            }
        }


# ── Standalone entry point ───────────────────────────────────────────────────

def main():
    """Read hook JSON from stdin, evaluate, print decision to stdout."""
    try:
        raw = sys.stdin.read()
        hook_input = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        # Fail-closed: if we can't parse input, deny
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"[SEATBELT] Hook input parse error: {e}",
            }
        }))
        sys.exit(0)

    result = gate(hook_input)
    print(json.dumps(result))
    sys.exit(0)


if __name__ == "__main__":
    main()
