"""
Tests for RDM-072 (governance self-modification) and RDM-073 (runtime hash verification).
"""
import hashlib
import json
import os
import tempfile

import pytest

from redmtz.patterns import PatternMatcher
from redmtz.whitelist import WhitelistMatcher


# ── RDM-072: Governance Self-Modification Blocklist ──────────────────────────

class TestGovernanceSelfModify:

    def _m(self):
        return PatternMatcher()

    # Edit tool targeting whitelist files
    def test_edit_whitelist_file(self):
        assert self._m().match("edit_file /project/redmtz/whitelists/role_claudius.json") is not None

    def test_edit_role_devops(self):
        assert self._m().match("edit_file /project/redmtz/whitelists/role_devops_senior.json") is not None

    def test_write_whitelist_file(self):
        assert self._m().match("write_file /project/redmtz/whitelists/role_junior_admin.json") is not None

    def test_write_patterns_py(self):
        assert self._m().match("edit_file /project/redmtz/patterns.py") is not None

    def test_write_policies_py(self):
        assert self._m().match("edit_file /project/redmtz/policies.py") is not None

    # Bash-based writes
    def test_cp_to_whitelist(self):
        assert self._m().match("cp new_role.json redmtz/whitelists/role_claudius.json") is not None

    def test_mv_to_whitelist(self):
        assert self._m().match("mv patched.json redmtz/whitelists/role_devops_senior.json") is not None

    def test_tee_to_whitelist(self):
        assert self._m().match("tee redmtz/whitelists/role_junior_admin.json < changes.json") is not None

    # Redirect into whitelist
    def test_redirect_to_whitelist(self):
        assert self._m().match("echo '{}' > redmtz/whitelists/role_claudius.json") is not None

    # Python inline write — the exact attack vector from 2026-04-08
    def test_python_inline_json_dump_to_whitelist(self):
        assert self._m().match(
            "python3 -c \"import json; json.dump(data, open('whitelists/role_claudius.json','w'))\""
        ) is not None

    # Safe reads — must NOT be blocked
    def test_safe_cat_whitelist(self):
        assert self._m().match("cat redmtz/whitelists/role_devops_senior.json") is None

    def test_safe_read_whitelist(self):
        assert self._m().match("python3 -c \"import json; print(json.load(open('redmtz/whitelists/role_devops_senior.json')))\"") is None

    def test_safe_edit_other_py(self):
        assert self._m().match("edit_file /project/redmtz/cli.py") is None

    def test_safe_edit_tests(self):
        assert self._m().match("edit_file /project/tests/test_new.py") is None

    def test_safe_write_readme(self):
        assert self._m().match("write_file /project/README.md") is None


# ── RDM-073: Runtime Hash Verification ───────────────────────────────────────

class TestRuntimeHashVerification:

    def _make_whitelist_file(self, tmp_path):
        """Create a minimal valid whitelist JSON for testing."""
        data = {
            "role": "test_role",
            "description": "Test role for RDM-073",
            "version": "1.0.0",
            "allowed_patterns": [
                {
                    "pattern_id": "ALLOW_TEST",
                    "description": "Test pattern",
                    "regex": "(?i)^echo\\b",
                    "domain": "system",
                    "risk_level": "LOW",
                    "examples": ["echo hello"]
                }
            ]
        }
        wl_file = tmp_path / "role_test.json"
        wl_file.write_text(json.dumps(data))
        return str(wl_file)

    def test_match_allows_when_hash_valid(self, tmp_path):
        """Whitelist match works normally when file is unmodified."""
        path = self._make_whitelist_file(tmp_path)
        matcher = WhitelistMatcher(path)
        assert matcher.match("echo hello") is not None

    def test_match_blocks_when_file_tampered(self, tmp_path):
        """Whitelist returns None (fail closed) when file has been modified after load."""
        path = self._make_whitelist_file(tmp_path)
        matcher = WhitelistMatcher(path)

        # Tamper the file after load
        with open(path, "a") as f:
            f.write("\n// tampered")

        # match() should fail closed — return None even for a valid action
        result = matcher.match("echo hello")
        assert result is None

    def test_match_escalation_blocks_when_tampered(self, tmp_path):
        """match_escalation() also fails closed on tampered file."""
        data = {
            "role": "test_esc",
            "description": "Test",
            "version": "1.0.0",
            "allowed_patterns": [],
            "escalation_patterns": [
                {
                    "pattern_id": "ESC_TEST",
                    "description": "Test escalation",
                    "regex": "(?i)\\bdocker\\b",
                    "domain": "system",
                    "risk_level": "HIGH",
                    "reason": "Requires approval"
                }
            ]
        }
        wl_file = tmp_path / "role_esc_test.json"
        wl_file.write_text(json.dumps(data))
        matcher = WhitelistMatcher(str(wl_file))

        # Tamper
        with open(str(wl_file), "a") as f:
            f.write("\n// tampered")

        assert matcher.match_escalation("docker build .") is None

    def test_hash_stored_on_load(self, tmp_path):
        """WhitelistMatcher stores the file hash on load."""
        path = self._make_whitelist_file(tmp_path)
        matcher = WhitelistMatcher(path)
        raw = open(path, "rb").read()
        expected = hashlib.sha256(raw).hexdigest()
        assert matcher.file_hash == expected

    def test_no_file_verify_returns_true(self):
        """WhitelistMatcher with no file loaded skips hash check."""
        matcher = WhitelistMatcher()
        assert matcher._verify_hash() is True
