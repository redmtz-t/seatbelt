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
redmtz.patterns — Destructive Action Pattern Library (RDM-021)
REDMTZ Seatbelt

Eight hardcoded patterns covering database, system, and credential threats.
The PatternMatcher checks any string input against these patterns before execution.

Founder: Robert Benitez
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class DestructivePattern:
    """
    Immutable pattern definition. Each pattern describes one category of
    destructive action, with regex matchers, domain scope, risk level,
    and remediation guidance.
    """
    pattern_id:       str
    description:      str
    regex_matchers:   List[str]
    domains:          List[str]
    risk_level:       str          # CRITICAL | HIGH | MEDIUM | LOW
    remediation_hint: str
    examples_blocked: List[str] = field(default_factory=list)
    examples_allowed: List[str] = field(default_factory=list)


# ── Pattern Definitions ───────────────────────────────────────────────────────

PATTERN_DROP_TABLE = DestructivePattern(
    pattern_id="BLOCK_DROP_TABLE",
    description="DROP TABLE — irreversible table deletion",
    regex_matchers=[r"(?i)\bDROP[\s_\-]+TABLE\b"],
    domains=["database", "*"],
    risk_level="CRITICAL",
    remediation_hint=(
        "Use a migration runner (Alembic, Flyway) with a rollback plan. "
        "Never issue DROP TABLE from an autonomous agent."
    ),
    examples_blocked=["DROP TABLE users", "drop table IF EXISTS logs", "DROP TABLE sessions CASCADE"],
    examples_allowed=["SELECT * FROM users", "CREATE TABLE new_table (id INT)"],
)

PATTERN_TRUNCATE = DestructivePattern(
    pattern_id="BLOCK_TRUNCATE",
    description="TRUNCATE — wipes all rows from a table without logging",
    regex_matchers=[r"(?i)\bTRUNCATE\b"],
    domains=["database", "*"],
    risk_level="CRITICAL",
    remediation_hint=(
        "Use DELETE with a WHERE clause for controlled removal. "
        "TRUNCATE is unrecoverable without a backup."
    ),
    examples_blocked=["TRUNCATE TABLE users", "TRUNCATE logs", "truncate sessions CASCADE"],
    examples_allowed=["DELETE FROM logs WHERE created_at < '2024-01-01'"],
)

PATTERN_DELETE_NO_WHERE = DestructivePattern(
    pattern_id="BLOCK_DELETE_NO_WHERE",
    description="DELETE without WHERE clause — deletes all rows",
    regex_matchers=[r"(?i)\bDELETE\s+FROM\s+\w+\s*(?:;|$)"],
    domains=["database", "*"],
    risk_level="CRITICAL",
    remediation_hint=(
        "Always include a WHERE clause. Verify the target row count "
        "with a SELECT before issuing DELETE."
    ),
    examples_blocked=["DELETE FROM users", "DELETE FROM logs;", "delete from sessions"],
    examples_allowed=["DELETE FROM users WHERE id = 42", "DELETE FROM logs WHERE created_at < '2024-01-01'"],
)

PATTERN_RM_RF_ROOT = DestructivePattern(
    pattern_id="BLOCK_RM_RF_ROOT",
    description="rm -rf targeting system root paths",
    regex_matchers=[
        r"(?i)\brm\s+(-\w+\s+)*-[^\s]*r[^\s]*f[^\s]*\s+"
        r"(/\s*(?:;|$)|(?:/(?:etc|bin|lib|lib64|usr|boot|sys|proc|dev|home|root|var|opt))\b)",
    ],
    domains=["system", "*"],
    risk_level="CRITICAL",
    remediation_hint=(
        "Never run rm -rf on system paths from an agent. "
        "Use targeted file removal with explicit paths and confirmation."
    ),
    examples_blocked=["rm -rf /", "rm -rf /etc", "rm -rf /usr/bin", "rm -rf /home"],
    examples_allowed=["rm -rf /tmp/cache", "rm -f /tmp/myfile.txt"],
)

PATTERN_CRED_THEFT = DestructivePattern(
    pattern_id="BLOCK_CRED_THEFT",
    description="Hardcoded credential literals in code or config",
    regex_matchers=[
        r"(?i)(?:password|passwd|api[_-]?key|secret[_-]?key|access[_-]?token|"
        r"aws[_-]?secret|private[_-]?key)\s*=\s*['\"][A-Za-z0-9+/=_\-\.]{8,}['\"]",
    ],
    domains=["*"],
    risk_level="HIGH",
    remediation_hint=(
        "Never hardcode credentials. Use environment variables, "
        "AWS Secrets Manager, HashiCorp Vault, or a .env file excluded from VCS."
    ),
    examples_blocked=[
        "api_key = 'sk-abc123defgh'",
        "password = 'SuperSecret99'",
        "aws_secret_key = 'wJalrXUtnFEMI/K7MDENG'",
    ],
    examples_allowed=[
        "api_key = os.getenv('API_KEY')",
        "password = load_from_vault('db/password')",
    ],
)

PATTERN_SQL_INJECTION_OBVIOUS = DestructivePattern(
    pattern_id="BLOCK_SQL_INJECTION_OBVIOUS",
    description="Obvious SQL injection patterns",
    regex_matchers=[
        r"(?i)('\s*OR\s*'?\d+'\s*=\s*'?\d+)",
        r"(?i)(;\s*DROP\s+TABLE)",
        r"(?i)(UNION\s+SELECT\s+NULL)",
        r"(?i)(';\s*--)",
    ],
    domains=["database", "*"],
    risk_level="CRITICAL",
    remediation_hint=(
        "Use parameterized queries or prepared statements. "
        "Never interpolate user input directly into SQL strings."
    ),
    examples_blocked=[
        "' OR '1'='1",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL, NULL--",
    ],
    examples_allowed=["SELECT * FROM users WHERE id = ?"],
)

PATTERN_SHELL_EXEC_DANGEROUS = DestructivePattern(
    pattern_id="BLOCK_SHELL_EXEC_DANGEROUS",
    description="Dangerous shell execution — eval/exec/os.system with external input",
    regex_matchers=[
        r"(?i)\beval\s*\(",
        r"(?i)\bexec\s*\(",
        r"(?i)\bos\.system\s*\(",
        r"(?i)\bsubprocess\.call\s*\(\s*['\"](?:bash|sh|cmd|powershell)\b",
        r"(?i)\b(?:bash|sh)\s+-c\b",
    ],
    domains=["system", "*"],
    risk_level="HIGH",
    remediation_hint=(
        "Use subprocess.run() with a list of arguments (not shell=True). "
        "Validate and sanitize all inputs before passing to shell."
    ),
    examples_blocked=[
        "eval('bash -c payload')",
        "exec(user_input)",
        "os.system(cmd)",
        "bash -c 'rm -rf /tmp'",
    ],
    examples_allowed=[
        "subprocess.run(['ls', '-la'], capture_output=True)",
        "subprocess.run(['git', 'status'])",
    ],
)

PATTERN_WILDCARD_RECURSIVE_DELETE = DestructivePattern(
    pattern_id="BLOCK_WILDCARD_RECURSIVE_DELETE",
    description="Wildcard or recursive delete patterns",
    regex_matchers=[
        r"(?i)\brm\s+(-\w+\s+)*-[^\s]*r[^\s]*\s+.*\*",
        r"(?i)\bfind\s+.{0,60}(?:-delete|-exec\s+rm)\b",
        r"(?i)\brmdir\s+/[sS]\b",
    ],
    domains=["system", "*"],
    risk_level="CRITICAL",
    remediation_hint=(
        "Replace wildcard deletes with explicit file lists. "
        "Preview with --dry-run or 'find ... -print' before destructive execution."
    ),
    examples_blocked=[
        "rm -rf /var/log/*",
        "find /tmp -name '*.log' -delete",
        "rm -r /data/*",
    ],
    examples_allowed=[
        "rm /tmp/specific_file.log",
        "find /tmp -name '*.log' -print",
    ],
)


# ── Pattern Registry ──────────────────────────────────────────────────────────

PATTERNS: tuple = (
    PATTERN_DROP_TABLE,
    PATTERN_TRUNCATE,
    PATTERN_DELETE_NO_WHERE,
    PATTERN_RM_RF_ROOT,
    PATTERN_CRED_THEFT,
    PATTERN_SQL_INJECTION_OBVIOUS,
    PATTERN_SHELL_EXEC_DANGEROUS,
    PATTERN_WILDCARD_RECURSIVE_DELETE,
)


# ── PatternMatcher ────────────────────────────────────────────────────────────

class PatternMatcher:
    """
    Matches an action string against the destructive pattern library.

    Usage:
        matcher = PatternMatcher()
        matched = matcher.match_all("DROP TABLE users", domain="database")
        # Returns list of DestructivePattern objects
    """

    def __init__(self):
        # Pre-compile all regexes for performance
        self._compiled: dict = {}
        for pattern in PATTERNS:
            self._compiled[pattern.pattern_id] = [
                re.compile(r) for r in pattern.regex_matchers
            ]

    def _domain_matches(self, pattern: DestructivePattern, domain: str) -> bool:
        """Return True if the pattern applies to the given domain."""
        if domain == "*":
            return True
        return domain in pattern.domains or "*" in pattern.domains

    def match(self, action: str, domain: str = "*") -> Optional[DestructivePattern]:
        """Return the first matching pattern, or None."""
        for pattern in PATTERNS:
            if not self._domain_matches(pattern, domain):
                continue
            for regex in self._compiled[pattern.pattern_id]:
                if regex.search(action):
                    return pattern
        return None

    def match_all(self, action: str, domain: str = "*") -> List[DestructivePattern]:
        """Return all matching patterns (no duplicates)."""
        results = []
        for pattern in PATTERNS:
            if not self._domain_matches(pattern, domain):
                continue
            for regex in self._compiled[pattern.pattern_id]:
                if regex.search(action):
                    results.append(pattern)
                    break  # one match per pattern is enough
        return results

    def get_all_patterns(self) -> List[DestructivePattern]:
        """Return all patterns in the library."""
        return list(PATTERNS)

    def get_patterns_for_domain(self, domain: str) -> List[DestructivePattern]:
        """Return patterns applicable to a specific domain."""
        return [p for p in PATTERNS if self._domain_matches(p, domain)]
