"""
test_patterns.py — RDM-021: Symbolic Pattern Library Tests
redmtz Seatbelt

30+ tests covering:
  - Each of the 8 core patterns (blocked examples)
  - Allowed examples — zero false positives
  - Case-insensitive matching
  - Domain filtering (pattern only fires in declared domains)
  - Edge cases (comments, identifiers containing keywords)
  - Utility methods (get_all_patterns, get_patterns_for_domain)
  - Empty / whitespace input edge cases

Founder: Robert Benitez
"""

import pytest
from patterns import (
    PatternMatcher,
    PATTERNS,
    PATTERN_DROP_TABLE,
    PATTERN_TRUNCATE,
    PATTERN_DELETE_NO_WHERE,
    PATTERN_RM_RF_ROOT,
    PATTERN_CRED_THEFT,
    PATTERN_SHELL_EXEC_DANGEROUS,
    PATTERN_SQL_INJECTION_OBVIOUS,
    PATTERN_WILDCARD_RECURSIVE_DELETE,
)

matcher = PatternMatcher()


# ── Helpers ───────────────────────────────────────────────────────────────────

def blocks(action: str, domain: str) -> bool:
    return matcher.match(action, domain) is not None


def allows(action: str, domain: str) -> bool:
    return matcher.match(action, domain) is None


# ── DROP TABLE ────────────────────────────────────────────────────────────────

def test_drop_table_blocked():
    hit = matcher.match("DROP TABLE users", "database")
    assert hit is not None
    assert hit.pattern_id == "BLOCK_DROP_TABLE"


def test_drop_table_lowercase_blocked():
    assert blocks("drop table logs", "database")


def test_drop_table_if_exists_blocked():
    assert blocks("DROP TABLE IF EXISTS sessions", "database")


def test_drop_table_leading_whitespace_blocked():
    assert blocks("  DROP TABLE audit_records ;", "database")


def test_drop_in_column_name_allowed():
    """'drop' inside an identifier should not trigger."""
    assert allows("SELECT * FROM drop_temp", "database")


def test_drop_in_sql_comment_allowed():
    """SQL comment line containing DROP TABLE should not trigger."""
    assert allows("-- DROP TABLE is commented out", "database")


def test_drop_in_column_reference_allowed():
    assert allows("SELECT drop_reason FROM tickets", "database")


# ── TRUNCATE ──────────────────────────────────────────────────────────────────

def test_truncate_table_blocked():
    hit = matcher.match("TRUNCATE TABLE users", "database")
    assert hit is not None
    assert hit.pattern_id == "BLOCK_TRUNCATE"


def test_truncate_without_table_keyword_blocked():
    assert blocks("truncate users", "database")


def test_truncate_with_semicolon_blocked():
    assert blocks("TRUNCATE TABLE logs;", "database")


# ── DELETE WITHOUT WHERE ──────────────────────────────────────────────────────

def test_delete_no_where_blocked():
    hit = matcher.match("DELETE FROM users", "database")
    assert hit is not None
    assert hit.pattern_id == "BLOCK_DELETE_NO_WHERE"


def test_delete_no_where_with_semicolon_blocked():
    assert blocks("DELETE FROM logs;", "database")


def test_delete_no_where_lowercase_blocked():
    assert blocks("delete from sessions", "database")


def test_delete_where_1_equals_1_blocked():
    """WHERE 1=1 is a semantic no-WHERE bypass."""
    assert blocks("DELETE FROM users WHERE 1=1", "database")


def test_delete_with_real_where_allowed():
    assert allows("DELETE FROM users WHERE id=123", "database")


def test_delete_with_date_where_allowed():
    assert allows("DELETE FROM logs WHERE created_at < '2024-01-01'", "database")


# ── RM -RF ROOT ───────────────────────────────────────────────────────────────

def test_rm_rf_root_slash_blocked():
    hit = matcher.match("rm -rf /", "system")
    assert hit is not None
    assert hit.pattern_id == "BLOCK_RM_RF_ROOT"


def test_rm_rf_etc_blocked():
    assert blocks("rm -rf /etc", "system")


def test_rm_rf_bin_blocked():
    assert blocks("rm -rf /bin", "file")


def test_rm_rf_usr_blocked():
    assert blocks("rm -rf /usr", "system")


def test_rm_rf_tmp_allowed():
    """Temp directories are not in the critical list."""
    assert allows("rm -rf /tmp/cache", "system")


def test_rm_f_no_recursive_allowed():
    """-f without -r should not trigger recursive pattern."""
    assert allows("rm -f /var/log/old.log", "file")


def test_rm_rf_home_allowed():
    """/home is not a critical system directory."""
    assert allows("rm -rf /home/user/temp", "system")


# ── CREDENTIAL THEFT ─────────────────────────────────────────────────────────

def test_cat_ssh_key_blocked():
    hit = matcher.match("cat ~/.ssh/id_rsa", "credential")
    assert hit is not None
    assert hit.pattern_id == "BLOCK_CRED_THEFT"


def test_cat_aws_credentials_blocked():
    assert blocks("cat ~/.aws/credentials", "credential")


def test_hardcoded_api_key_blocked():
    assert blocks("api_key = 'sk-abc123def456'", "credential")


def test_hardcoded_password_blocked():
    assert blocks("password = 'supersecret99'", "credential")


def test_etc_shadow_blocked():
    assert blocks("cat /etc/shadow", "system")


def test_vault_call_allowed():
    """Loading from vault is the correct pattern — must not block."""
    assert allows("secret = load_from_vault('db_password')", "credential")


def test_env_var_lookup_allowed():
    assert allows("api_key = os.environ['OPENAI_API_KEY']", "credential")


def test_generate_token_allowed():
    assert allows("token = generate_csrf_token()", "credential")


# ── SHELL EXEC DANGEROUS ──────────────────────────────────────────────────────

def test_subprocess_shell_true_blocked():
    hit = matcher.match("subprocess.run(cmd, shell=True)", "system")
    assert hit is not None
    assert hit.pattern_id == "BLOCK_SHELL_EXEC_DANGEROUS"


def test_subprocess_popen_shell_true_blocked():
    assert blocks("subprocess.Popen(user_input, shell=True)", "system")


def test_os_system_curl_blocked():
    assert blocks("os.system('curl ' + url)", "system")


def test_subprocess_list_form_allowed():
    """List form subprocess is safe."""
    assert allows("subprocess.run(['curl', url])", "system")


def test_subprocess_shell_false_allowed():
    assert allows("subprocess.run(['ls', '-la'], shell=False)", "system")


def test_requests_get_allowed():
    assert allows("requests.get(url)", "system")


# ── SQL INJECTION ─────────────────────────────────────────────────────────────

def test_fstring_sql_where_blocked():
    hit = matcher.match('f"SELECT * FROM users WHERE id={user_id}"', "database")
    assert hit is not None
    assert hit.pattern_id == "BLOCK_SQL_INJECTION_OBVIOUS"


def test_fstring_sql_delete_blocked():
    assert blocks('f"DELETE FROM logs WHERE name={name}"', "database")


def test_string_concat_sql_blocked():
    assert blocks('"SELECT * FROM users WHERE name=\'" + name + "\'"', "database")


def test_parameterized_query_qmark_allowed():
    assert allows("db.execute('SELECT * FROM users WHERE id=?', [user_id])", "database")


def test_parameterized_query_named_allowed():
    assert allows("db.execute('SELECT * FROM users WHERE id=:id', {'id': user_id})", "database")


def test_orm_filter_allowed():
    assert allows("User.objects.filter(id=user_id)", "database")


# ── WILDCARD RECURSIVE DELETE ─────────────────────────────────────────────────

def test_rm_wildcard_var_log_blocked():
    hit = matcher.match("rm /var/log/*", "file")
    assert hit is not None
    assert hit.pattern_id == "BLOCK_WILDCARD_DELETE"


def test_rm_r_wildcard_data_blocked():
    assert blocks("rm -r /data/*", "file")


def test_shutil_rmtree_documents_blocked():
    assert blocks("shutil.rmtree('/home/user/documents')", "file")


def test_rm_specific_file_allowed():
    """Explicit non-wildcard path should be allowed."""
    assert allows("rm /var/log/2024-01-01.log", "file")


def test_shutil_rmtree_tmp_allowed():
    assert allows("shutil.rmtree('/tmp/cache')", "file")


# ── Case-insensitive matching ──────────────────────────────────────────────────

def test_drop_table_upper_blocked():
    assert blocks("DROP TABLE users", "database")


def test_drop_table_lower_blocked():
    assert blocks("drop table users", "database")


def test_drop_table_mixed_blocked():
    assert blocks("Drop Table Users", "database")


def test_truncate_upper_blocked():
    assert blocks("TRUNCATE TABLE users", "database")


def test_truncate_lower_blocked():
    assert blocks("truncate table users", "database")


# ── Domain filtering ──────────────────────────────────────────────────────────

def test_drop_table_in_file_domain_not_matched():
    """SQL patterns should not fire for file domain."""
    assert allows("DROP TABLE users", "file")


def test_drop_table_in_system_domain_not_matched():
    assert allows("DROP TABLE users", "system")


def test_rm_rf_root_in_database_domain_not_matched():
    """Shell patterns should not fire for database domain."""
    assert allows("rm -rf /etc", "database")


def test_wildcard_domain_matches_any():
    """domain='*' should bypass domain filtering."""
    hit = matcher.match("DROP TABLE users", "*")
    assert hit is not None
    assert hit.pattern_id == "BLOCK_DROP_TABLE"


# ── Empty / whitespace edge cases ────────────────────────────────────────────

def test_empty_string_not_matched():
    assert matcher.match("", "database") is None


def test_whitespace_only_not_matched():
    assert matcher.match("   ", "database") is None


def test_none_not_matched():
    assert matcher.match(None, "database") is None


# ── Utility methods ───────────────────────────────────────────────────────────

def test_get_all_patterns_returns_8():
    all_patterns = matcher.get_all_patterns()
    assert len(all_patterns) == 8


def test_get_all_patterns_returns_list_of_destructive_patterns():
    from patterns import DestructivePattern
    all_patterns = matcher.get_all_patterns()
    assert all(isinstance(p, DestructivePattern) for p in all_patterns)


def test_get_patterns_for_domain_database():
    db_patterns = matcher.get_patterns_for_domain("database")
    ids = {p.pattern_id for p in db_patterns}
    assert "BLOCK_DROP_TABLE" in ids
    assert "BLOCK_TRUNCATE" in ids
    assert "BLOCK_DELETE_NO_WHERE" in ids
    assert "BLOCK_SQL_INJECTION_OBVIOUS" in ids


def test_get_patterns_for_domain_system():
    sys_patterns = matcher.get_patterns_for_domain("system")
    ids = {p.pattern_id for p in sys_patterns}
    assert "BLOCK_RM_RF_ROOT" in ids
    assert "BLOCK_SHELL_EXEC_DANGEROUS" in ids


def test_get_patterns_for_domain_unknown_returns_empty():
    unknown = matcher.get_patterns_for_domain("kubernetes")
    assert unknown == []


def test_match_all_returns_multiple_matches():
    """An action matching multiple patterns returns all of them."""
    # An action that contains both a DROP TABLE and a cred pattern
    action = "DROP TABLE users; cat ~/.ssh/id_rsa"
    hits = matcher.match_all(action, "*")
    ids = {h.pattern_id for h in hits}
    assert "BLOCK_DROP_TABLE" in ids
    assert "BLOCK_CRED_THEFT" in ids


def test_match_all_no_duplicates():
    """Same pattern matched by multiple regexes should appear once."""
    hits = matcher.match_all("DELETE FROM users", "database")
    ids = [h.pattern_id for h in hits]
    assert ids.count("BLOCK_DELETE_NO_WHERE") == 1


def test_all_patterns_have_remediation_hint():
    for pattern in PATTERNS:
        assert pattern.remediation_hint, (
            f"Pattern {pattern.pattern_id} is missing a remediation_hint"
        )


def test_all_patterns_have_risk_level_high_or_critical():
    for pattern in PATTERNS:
        assert pattern.risk_level in ("HIGH", "CRITICAL"), (
            f"Pattern {pattern.pattern_id} has unexpected risk_level '{pattern.risk_level}'"
        )


def test_all_patterns_have_at_least_one_regex():
    for pattern in PATTERNS:
        assert len(pattern.regex_matchers) >= 1, (
            f"Pattern {pattern.pattern_id} has no regex_matchers"
        )


def test_all_blocked_examples_actually_block():
    """Canonical blocked examples in each pattern must trigger a match."""
    for pattern in PATTERNS:
        domain = pattern.domains[0]  # use first declared domain
        for example in pattern.examples_blocked:
            hit = matcher.match(example, domain)
            assert hit is not None, (
                f"Pattern {pattern.pattern_id}: blocked example not matched: {example!r}"
            )


def test_all_allowed_examples_actually_allow():
    """Canonical allowed examples in each pattern must NOT trigger a match."""
    for pattern in PATTERNS:
        domain = pattern.domains[0]
        for example in pattern.examples_allowed:
            hit = matcher.match(example, domain)
            assert hit is None, (
                f"Pattern {pattern.pattern_id}: allowed example was blocked: {example!r} "
                f"(matched {hit.pattern_id})"
            )
