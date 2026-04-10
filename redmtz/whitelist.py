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
redmtz.whitelist — Role-Based Action Whitelist (RDM-037)
REDMTZ Seatbelt

Defines what an agent IS allowed to do. Works alongside the blocklist —
the blocklist blocks known dangerous actions, the whitelist approves known
safe actions. Everything outside the whitelist is implicitly denied.

Two-layer defense (both run on every action):
  Layer 1: BlocklistMatcher (patterns.py) — immutable, engine-level, always runs
  Layer 2: WhitelistMatcher (this file)   — role-based, signed, version controlled

Decision matrix:
  Blocklist HIT  → BLOCK (always, regardless of whitelist)
  Blocklist MISS + Whitelist HIT  → ALLOW
  Blocklist MISS + Whitelist MISS → BLOCK (implicit deny)
  No whitelist loaded             → falls back to policy default_action

The whitelist file is SHA-256 hashed on load. That hash is recorded in every
envelope — proving which authorization was in effect at decision time.

Founder: Robert Benitez
"""

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass(frozen=True)
class AllowedPattern:
    """
    An approved action pattern. An agent matching this pattern is authorized
    to proceed — provided the blocklist doesn't override it.
    """
    pattern_id:   str
    description:  str
    regex:        str
    domain:       str        # database | system | network | file | *
    risk_level:   str        # LOW | MEDIUM | HIGH
    examples:     List[str] = field(default_factory=list)


@dataclass(frozen=True)
class EscalationPattern:
    """
    An action that requires human approval (RB Directive / AI Sudo).
    Not blocked, not allowed — escalated to HITL gate.
    """
    pattern_id:   str
    description:  str
    regex:        str
    domain:       str
    risk_level:   str
    reason:       str = ""


class WhitelistMatcher:
    """
    Loads a role-based whitelist from a JSON file and matches actions
    against approved patterns.

    Usage:
        matcher = WhitelistMatcher("redmtz/whitelists/role_devops_senior.json")
        result = matcher.match("kubectl get pods -A")
        # result.allowed == True if action matches an approved pattern

        # Check the whitelist hash for envelope integrity:
        print(matcher.file_hash)
    """

    def __init__(self, whitelist_path: Optional[str] = None):
        self._patterns: List[AllowedPattern] = []
        self._escalations: List[EscalationPattern] = []
        self._compiled: dict = {}
        self._compiled_escalations: dict = {}
        self.file_hash: str = ""
        self._loaded_bytes: bytes = b""   # RDM-078: hold bytes in memory, no re-read
        self.role: str = "none"
        self.whitelist_path: Optional[str] = whitelist_path

        if whitelist_path:
            self._load(whitelist_path)

    def _load(self, path: str) -> None:
        """Load and validate a whitelist JSON file. Hash it for envelope integrity."""
        resolved = Path(path)

        # If path is not absolute, check relative to package whitelists/ dir
        if not resolved.is_absolute():
            pkg_dir = Path(__file__).parent / "whitelists" / path
            if pkg_dir.exists():
                resolved = pkg_dir

        if not resolved.exists():
            print(
                f"[redmtz][WHITELIST] File not found: {path} — whitelist disabled.",
                file=sys.stderr,
            )
            return

        try:
            raw = resolved.read_bytes()
            self.file_hash = hashlib.sha256(raw).hexdigest()
            self._loaded_bytes = raw   # RDM-078: store for TOCTOU-safe verification
            data = json.loads(raw.decode("utf-8"))
        except Exception as e:
            print(
                f"[redmtz][WHITELIST] Failed to load {path}: {e} — whitelist disabled.",
                file=sys.stderr,
            )
            return

        self.role = data.get("role", "unknown")

        for entry in data.get("allowed_patterns", []):
            try:
                pattern = AllowedPattern(
                    pattern_id=entry["pattern_id"],
                    description=entry["description"],
                    regex=entry["regex"],
                    domain=entry.get("domain", "*"),
                    risk_level=entry.get("risk_level", "LOW"),
                    examples=entry.get("examples", []),
                )
                self._patterns.append(pattern)
                self._compiled[pattern.pattern_id] = re.compile(pattern.regex)
            except Exception as e:
                print(
                    f"[redmtz][WHITELIST] Skipping malformed pattern {entry}: {e}",
                    file=sys.stderr,
                )

        for entry in data.get("escalation_patterns", []):
            try:
                esc = EscalationPattern(
                    pattern_id=entry["pattern_id"],
                    description=entry["description"],
                    regex=entry["regex"],
                    domain=entry.get("domain", "*"),
                    risk_level=entry.get("risk_level", "HIGH"),
                    reason=entry.get("reason", "Requires human approval"),
                )
                self._escalations.append(esc)
                self._compiled_escalations[esc.pattern_id] = re.compile(esc.regex)
            except Exception as e:
                print(
                    f"[redmtz][WHITELIST] Skipping malformed escalation {entry}: {e}",
                    file=sys.stderr,
                )

        esc_count = len(self._escalations)
        esc_msg = f" escalations={esc_count}" if esc_count else ""

        print(
            f"[redmtz][WHITELIST] Loaded role='{self.role}' "
            f"patterns={len(self._patterns)}{esc_msg} hash={self.file_hash[:16]}...",
            file=sys.stderr,
        )

    def _verify_hash(self) -> bool:
        """
        RDM-073/078: Verify whitelist integrity using in-memory bytes captured
        at load time. No disk re-read — eliminates TOCTOU window.
        Also verify against disk to catch runtime file replacement.
        RDM-080: Tamper events logged to audit ledger, not just stderr.
        """
        if not self.whitelist_path or not self._loaded_bytes:
            return True  # No file loaded — nothing to verify

        # Primary check: re-hash disk file and compare to load-time hash
        resolved = Path(self.whitelist_path)
        if not resolved.is_absolute():
            pkg_dir = Path(__file__).parent / "whitelists" / self.whitelist_path
            if pkg_dir.exists():
                resolved = pkg_dir

        if not resolved.exists():
            self._log_tamper("file removed from disk after load")
            return False

        try:
            disk_bytes = resolved.read_bytes()
            disk_hash  = hashlib.sha256(disk_bytes).hexdigest()

            # Tamper check 1: disk file changed since load
            if disk_hash != self.file_hash:
                self._log_tamper(
                    f"disk hash mismatch — expected {self.file_hash[:16]}... "
                    f"got {disk_hash[:16]}..."
                )
                return False

            # Tamper check 2: in-memory bytes changed (memory corruption guard)
            mem_hash = hashlib.sha256(self._loaded_bytes).hexdigest()
            if mem_hash != self.file_hash:
                self._log_tamper(
                    f"memory hash mismatch — expected {self.file_hash[:16]}... "
                    f"got {mem_hash[:16]}..."
                )
                return False

            return True
        except Exception as e:
            self._log_tamper(f"hash verification error: {e}")
            return False

    def _log_tamper(self, reason: str) -> None:
        """
        RDM-080: Log tamper detection to stderr AND attempt to write a signed
        envelope to the audit ledger so the event is part of the immutable chain.
        """
        msg = (
            f"[redmtz][WHITELIST] TAMPER DETECTED — {reason} "
            f"for role='{self.role}' path='{self.whitelist_path}' — failing closed."
        )
        print(msg, file=sys.stderr)
        try:
            from . import database
            database.log_audit(
                intent="whitelist:tamper_detected",
                command=f"whitelist:{self.whitelist_path}",
                verdict="BLOCK",
                reason=f"TAMPER_DETECTED: {reason}",
                skill="seatbelt-whitelist",
                agent_id="redmtz-whitelist-engine",
                envelope={},
                sig_alg="sha256+ed25519",
                environment="",
                policy="tamper-detection",
                patterns_matched=["TAMPER_DETECTED"],
                envelope_hash="",
                remediation="Whitelist file was modified after load. Governance engine is failing closed.",
            )
        except Exception:
            pass  # Audit log failure must never suppress the tamper block

    def match(self, action: str) -> Optional[AllowedPattern]:
        """Return the first approved pattern that matches, or None.
        Fails closed if whitelist file has been modified since load (RDM-073)."""
        if not self._verify_hash():
            return None  # Fail closed — tampered config = no allowances
        for pattern in self._patterns:
            compiled = self._compiled.get(pattern.pattern_id)
            if compiled and compiled.search(action):
                return pattern
        return None

    def match_escalation(self, action: str) -> Optional[EscalationPattern]:
        """Return the first escalation pattern that matches, or None.
        Fails closed if whitelist file has been modified since load (RDM-073)."""
        if not self._verify_hash():
            return None
        for esc in self._escalations:
            compiled = self._compiled_escalations.get(esc.pattern_id)
            if compiled and compiled.search(action):
                return esc
        return None

    def is_loaded(self) -> bool:
        """Return True if a whitelist file was successfully loaded."""
        return len(self._patterns) > 0

    def get_role(self) -> str:
        return self.role

    def get_file_hash(self) -> str:
        """SHA-256 hash of the whitelist file — recorded in every envelope."""
        return self.file_hash

    def list_patterns(self) -> List[AllowedPattern]:
        return list(self._patterns)
