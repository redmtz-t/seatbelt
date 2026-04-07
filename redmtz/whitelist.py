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
        self._compiled: dict = {}
        self.file_hash: str = ""
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

        print(
            f"[redmtz][WHITELIST] Loaded role='{self.role}' "
            f"patterns={len(self._patterns)} hash={self.file_hash[:16]}...",
            file=sys.stderr,
        )

    def match(self, action: str) -> Optional[AllowedPattern]:
        """Return the first approved pattern that matches, or None."""
        for pattern in self._patterns:
            compiled = self._compiled.get(pattern.pattern_id)
            if compiled and compiled.search(action):
                return pattern
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
