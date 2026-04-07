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
redmtz.policies — Policy Templates (RDM-023)
REDMTZ Seatbelt

Four built-in policies mapping pattern risk levels to enforcement decisions.
Pass the policy name to @govern(policy="...") to select enforcement behavior.

Founder: Robert Benitez
"""

from typing import Literal

Decision = Literal["block", "allow"]

POLICIES: dict[str, dict] = {
    "safe_defaults": {
        "CRITICAL": "block",
        "HIGH":     "block",
        "MEDIUM":   "allow",
        "LOW":      "allow",
        "log_all":  True,
        "description": "Block CRITICAL/HIGH. Allow recoverable operations. Recommended starting point.",
    },
    "read_only": {
        "CRITICAL": "block",
        "HIGH":     "block",
        "MEDIUM":   "block",
        "LOW":      "allow",
        "log_all":  True,
        "description": "Allow only LOW-risk operations. Block everything else.",
    },
    "audit_mode": {
        "CRITICAL": "allow",
        "HIGH":     "allow",
        "MEDIUM":   "allow",
        "LOW":      "allow",
        "log_all":  True,
        "description": "Allow all operations. Log everything. No enforcement. Use for observability.",
    },
    "strict_prod": {
        "CRITICAL":       "block",
        "HIGH":           "block",
        "MEDIUM":         "block",
        "LOW":            "block",
        "default_action": "block",   # implicit deny — unmatched actions are blocked
        "log_all":        True,
        "description": "Implicit deny. Block all matched patterns AND anything unrecognized. Zero tolerance for production.",
    },
    "strict_whitelist": {
        "CRITICAL":       "block",
        "HIGH":           "block",
        "MEDIUM":         "block",
        "LOW":            "block",
        "default_action": "block",   # implicit deny — blocklist always runs first
        "whitelist_mode": True,      # whitelist defines ALLOW set; blocklist is immutable floor
        "log_all":        True,
        "description": "Two-layer defense. Blocklist blocks known bad (immutable). Whitelist defines known good. Everything else denied.",
    },
}

_DEFAULT_POLICY = "safe_defaults"


def get_policy(name: str) -> dict:
    """Return the policy dict for the given name. Falls back to safe_defaults."""
    if name not in POLICIES:
        import sys
        print(
            f"[redmtz][POLICY] Unknown policy '{name}' — falling back to safe_defaults.",
            file=sys.stderr,
        )
        return POLICIES[_DEFAULT_POLICY]
    return POLICIES[name]


def policy_decision(policy: dict, risk_level: str) -> Decision:
    """
    Return the enforcement decision for a given risk_level under a policy.
    Unknown risk levels default to block (fail-closed).
    """
    decision = policy.get(risk_level, "block")
    if decision == "conditional":
        return "block"  # Phase 2: defer to HITL. For now, block.
    return decision


def list_policies() -> list[str]:
    """Return sorted list of available policy names."""
    return sorted(POLICIES.keys())
