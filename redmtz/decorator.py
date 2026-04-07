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
redmtz.decorator — @govern Decorator (RDM-022)
REDMTZ Seatbelt

The 3-line integration:

    from redmtz import govern

    @govern(rules="destructive_actions", policy="safe_defaults")
    def execute_sql(query: str):
        db.execute(query)

Intercepts the function call, checks against the pattern library,
builds a signed envelope, logs to the audit ledger, and either
raises GovernanceBlocked or allows execution.

Founder: Robert Benitez
"""

import functools
import hashlib
import inspect
import json
import sys
from typing import Any, List, Optional

from . import database
from .envelope import CanonicalEnvelope
from .patterns import DestructivePattern, PatternMatcher
from .policies import get_policy, policy_decision

_matcher = PatternMatcher()
_ce      = CanonicalEnvelope()

_SQL_PARAMS     = frozenset(["query", "sql", "statement", "select", "insert", "update"])
_SHELL_PARAMS   = frozenset(["cmd", "command", "shell_cmd", "shell", "script", "bash"])
_FILE_PARAMS    = frozenset(["path", "filepath", "file_path", "filename"])
_GENERIC_PARAMS = frozenset(["action", "text"])
_ALL_ACTION_PARAMS = _SQL_PARAMS | _SHELL_PARAMS | _FILE_PARAMS | _GENERIC_PARAMS


def _infer_domain(param_name: str, func_name: str) -> str:
    combined = (param_name + " " + func_name).lower()
    if any(h in combined for h in _SQL_PARAMS):
        return "database"
    if any(h in combined for h in _SHELL_PARAMS):
        return "system"
    if any(h in combined for h in _FILE_PARAMS):
        return "file"
    return "*"


def _extract_action(func, args: tuple, kwargs: dict) -> tuple[Optional[str], str]:
    try:
        sig   = inspect.signature(func)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
    except TypeError:
        return None, "*"

    params = list(bound.arguments.items())
    if not params:
        return None, "*"

    first_name, first_val = params[0]

    if first_name in _ALL_ACTION_PARAMS and isinstance(first_val, str):
        return first_val, _infer_domain(first_name, func.__name__)

    if isinstance(first_val, str):
        return first_val, _infer_domain("", func.__name__)

    return None, "*"


def _sha256(content: Any) -> str:
    if isinstance(content, str):
        raw = content.encode("utf-8")
    else:
        raw = json.dumps(content, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class GovernanceBlocked(Exception):
    """
    Raised when @govern blocks a function call.

    Attributes:
        envelope:          The signed RDM-019 envelope (proof of governance).
        patterns:          All matched DestructivePatterns.
        pattern:           The first (highest-priority) matched pattern.
        remediation_hint:  Combined remediation hints from all matched patterns.
    """

    def __init__(
        self,
        message:          str,
        envelope:         dict,
        patterns:         List[DestructivePattern],
        remediation_hint: str,
    ):
        super().__init__(message)
        self.envelope         = envelope
        self.patterns         = patterns
        self.pattern          = patterns[0] if patterns else None
        self.remediation_hint = remediation_hint


def govern(rules: str = "destructive_actions", policy: str = "safe_defaults"):
    """
    Decorator that governs function execution against the REDMTZ pattern library.

    Args:
        rules:  Pattern ruleset. Currently only "destructive_actions".
        policy: Policy template. Options: safe_defaults, read_only,
                audit_mode, strict_prod. Default: safe_defaults.

    Usage:
        @govern(rules="destructive_actions", policy="safe_defaults")
        def execute_sql(query: str):
            db.execute(query)

    Raises:
        GovernanceBlocked: If a destructive pattern is matched and policy says block.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Step 1: Extract action string
            action, domain = _extract_action(func, args, kwargs)

            if action is None:
                print(
                    f"[redmtz][GOVERN] WARNING: Cannot extract action from "
                    f"{func.__module__}.{func.__name__}() — "
                    f"skipping pattern check (fail-open for unrecognized args).",
                    file=sys.stderr,
                )
                return func(*args, **kwargs)

            # Step 2: Pattern matching
            matched = _matcher.match_all(action, domain)

            # Step 3: Policy decision
            policy_data  = get_policy(policy)
            should_block = False
            if matched:
                for p in matched:
                    if policy_decision(policy_data, p.risk_level) == "block":
                        should_block = True
                        break

            decision_str = "BLOCK" if should_block else "ALLOW"
            gate_reason  = (
                " | ".join(p.pattern_id for p in matched)
                if matched else "no patterns matched"
            )

            # Step 4: Build signed envelope
            actor_identity = f"{func.__module__}.{func.__name__}"
            envelope = _ce.build(
                actor={
                    "type":              "application",
                    "identity":          actor_identity,
                    "credential_method": "decorator",
                },
                action={
                    "verb":     "execute",
                    "domain":   domain if domain != "*" else "system",
                    "resource": func.__name__,
                },
                gate_decisions=[{
                    "gate":       "resolver",
                    "decision":   decision_str.lower(),
                    "reason":     gate_reason,
                    "latency_us": 0,
                    "patterns":   [p.pattern_id for p in matched],
                }],
                policy={
                    "name":    policy,
                    "version": "1.0.0",
                    "hash":    _sha256(policy),
                },
                execution_result={"status": decision_str.lower()},
                input_content=action,
                input_token_count=len(action.split()),
                input_classification="unknown",
                model={
                    "name":    "redmtz-seatbelt",
                    "version": "1.0.0",
                    "runtime": "symbolic",
                },
                sign=True,
                governance_mode="deterministic",
            )

            for sig in envelope.get("signatures", []):
                sig["type"]       = "self"
                sig["key_source"] = "auto"
                sig["signer"]     = actor_identity

            # Step 5: Audit log
            try:
                database.log_audit(
                    intent="seatbelt_govern",
                    command=f"{func.__name__}(digest={_sha256(action)[:16]}...)",
                    verdict=decision_str,
                    reason=gate_reason,
                    skill="seatbelt",
                    agent_id=actor_identity,
                    envelope=envelope,
                )
            except Exception as e:
                print(
                    f"[redmtz][GOVERN] WARNING: Audit log failed: {e} — "
                    f"governance decision still enforced.",
                    file=sys.stderr,
                )

            # Step 6: Block or allow
            if should_block:
                remediation = "\n".join(
                    f"  [{p.pattern_id}] {p.remediation_hint}" for p in matched
                )
                raise GovernanceBlocked(
                    f"[redmtz][GOVERN] BLOCKED: {func.__name__}() — {gate_reason}",
                    envelope=envelope,
                    patterns=matched,
                    remediation_hint=remediation,
                )

            return func(*args, **kwargs)

        return wrapper
    return decorator
