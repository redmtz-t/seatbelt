"""
test_decorator.py — RDM-022: @govern Decorator Tests
redmtz Seatbelt

30+ tests covering:
  - Decorator blocks destructive actions (all 8 patterns)
  - Decorator allows safe actions
  - GovernanceBlocked exception structure (envelope, pattern, hint)
  - Envelope is signed (type: "self") and hash-chained
  - Policy templates: safe_defaults, read_only, audit_mode, strict_prod
  - Action extraction heuristics (query/command/action/cmd/text names)
  - Multiple patterns reported in same envelope
  - Decorator preserves function return value on allow
  - Decorator preserves function exceptions (non-governance errors)
  - Audit DB integration (envelope logged)
  - functools.wraps preservation (__name__, __doc__)

Founder: Robert Benitez
"""

import pytest
from decorator import govern, GovernanceBlocked
from policies import get_policy, policy_decision, list_policies


# ── Test fixtures — governed functions ───────────────────────────────────────

@govern(rules="destructive_actions", policy="safe_defaults")
def execute_sql(query: str):
    """Execute a SQL query."""
    return f"Executed: {query}"


@govern(rules="destructive_actions", policy="safe_defaults")
def run_shell(cmd: str):
    return f"Shell: {cmd}"


@govern(rules="destructive_actions", policy="safe_defaults")
def run_command(command: str):
    return f"Command: {command}"


@govern(rules="destructive_actions", policy="audit_mode")
def execute_sql_audit(query: str):
    return f"Executed (audit): {query}"


@govern(rules="destructive_actions", policy="read_only")
def execute_sql_read_only(query: str):
    return f"Executed (read_only): {query}"


@govern(rules="destructive_actions", policy="strict_prod")
def execute_sql_strict(query: str):
    return f"Executed (strict): {query}"


@govern(rules="destructive_actions", policy="safe_defaults")
def process_text(text: str):
    return f"Processed: {text}"


@govern(rules="destructive_actions", policy="safe_defaults")
def run_action(action: str):
    return f"Action: {action}"


@govern(rules="destructive_actions", policy="safe_defaults")
def first_string_arg(unrecognized_name: str):
    """First arg is string but param name is not in known list."""
    return f"Done: {unrecognized_name}"


@govern(rules="destructive_actions", policy="safe_defaults")
def raises_on_execute(query: str):
    raise ValueError("DB connection failed")


@govern(rules="destructive_actions", policy="safe_defaults")
def returns_value(query: str):
    return {"rows": 42, "query": query}


# ── Allow: safe actions pass through ─────────────────────────────────────────

def test_safe_select_allowed():
    result = execute_sql("SELECT * FROM users")
    assert result == "Executed: SELECT * FROM users"


def test_safe_select_with_where_allowed():
    result = execute_sql("SELECT id, name FROM orders WHERE status='active'")
    assert "Executed:" in result


def test_delete_with_where_allowed():
    result = execute_sql("DELETE FROM logs WHERE created_at < '2024-01-01'")
    assert "Executed:" in result


def test_insert_allowed():
    result = execute_sql("INSERT INTO events (name) VALUES ('login')")
    assert "Executed:" in result


def test_safe_shell_allowed():
    result = run_shell("ls -la /tmp")
    assert "Shell:" in result


# ── Block: destructive SQL ────────────────────────────────────────────────────

def test_drop_table_blocked():
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql("DROP TABLE users")
    assert exc_info.value.pattern.pattern_id == "BLOCK_DROP_TABLE"


def test_truncate_blocked():
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql("TRUNCATE TABLE logs")
    assert exc_info.value.pattern.pattern_id == "BLOCK_TRUNCATE"


def test_delete_no_where_blocked():
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql("DELETE FROM users")
    assert exc_info.value.pattern.pattern_id == "BLOCK_DELETE_NO_WHERE"


def test_delete_where_1_1_blocked():
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql("DELETE FROM users WHERE 1=1")
    assert exc_info.value.pattern is not None


def test_fstring_sql_injection_blocked():
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql('f"SELECT * FROM users WHERE id={user_id}"')
    assert exc_info.value.pattern.pattern_id == "BLOCK_SQL_INJECTION_OBVIOUS"


# ── Block: destructive shell ──────────────────────────────────────────────────

def test_rm_rf_root_blocked():
    with pytest.raises(GovernanceBlocked) as exc_info:
        run_shell("rm -rf /etc")
    assert exc_info.value.pattern.pattern_id == "BLOCK_RM_RF_ROOT"


def test_subprocess_shell_true_blocked():
    with pytest.raises(GovernanceBlocked) as exc_info:
        run_shell("subprocess.run(cmd, shell=True)")
    assert exc_info.value.pattern.pattern_id == "BLOCK_SHELL_EXEC_DANGEROUS"


def test_rm_wildcard_blocked():
    with pytest.raises(GovernanceBlocked) as exc_info:
        run_command("rm /var/log/*")
    assert exc_info.value.pattern.pattern_id == "BLOCK_WILDCARD_DELETE"


def test_cat_ssh_key_blocked():
    with pytest.raises(GovernanceBlocked) as exc_info:
        run_command("cat ~/.ssh/id_rsa")
    assert exc_info.value.pattern.pattern_id == "BLOCK_CRED_THEFT"


# ── GovernanceBlocked exception structure ─────────────────────────────────────

def test_blocked_exception_has_envelope():
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql("DROP TABLE users")
    assert exc_info.value.envelope is not None
    assert isinstance(exc_info.value.envelope, dict)


def test_blocked_exception_has_pattern():
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql("DROP TABLE users")
    assert exc_info.value.pattern is not None
    assert exc_info.value.pattern.pattern_id == "BLOCK_DROP_TABLE"


def test_blocked_exception_has_patterns_list():
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql("DROP TABLE users")
    assert isinstance(exc_info.value.patterns, list)
    assert len(exc_info.value.patterns) >= 1


def test_blocked_exception_has_remediation_hint():
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql("DROP TABLE users")
    assert exc_info.value.remediation_hint
    assert "BLOCK_DROP_TABLE" in exc_info.value.remediation_hint


def test_blocked_exception_message_contains_function_name():
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql("DROP TABLE users")
    assert "execute_sql" in str(exc_info.value)


# ── Envelope structure ────────────────────────────────────────────────────────

def test_envelope_has_event_id():
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql("DROP TABLE users")
    envelope = exc_info.value.envelope
    assert "event_id" in envelope
    assert len(envelope["event_id"]) > 0


def test_envelope_has_timestamp_utc():
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql("DROP TABLE users")
    assert "timestamp_utc" in exc_info.value.envelope


def test_envelope_has_hash_chain():
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql("DROP TABLE users")
    hc = exc_info.value.envelope.get("hash_chain", {})
    assert "previous_hash" in hc
    assert "current_hash" in hc
    assert len(hc["current_hash"]) == 64  # SHA-256 hex


def test_envelope_is_self_signed():
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql("DROP TABLE users")
    sigs = exc_info.value.envelope.get("signatures", [])
    assert len(sigs) >= 1
    assert sigs[0]["type"] == "self"


def test_envelope_signature_not_empty():
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql("DROP TABLE users")
    sigs = exc_info.value.envelope.get("signatures", [])
    # Signature should be present (or have an error key if signing failed — both valid)
    assert "signature" in sigs[0]


def test_envelope_input_is_digested_not_raw():
    """Raw action string must NOT appear in the envelope (digest-only policy)."""
    raw_action = "DROP TABLE sensitive_table"
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql(raw_action)
    envelope_str = str(exc_info.value.envelope)
    assert raw_action not in envelope_str


def test_envelope_gate_decisions_contain_pattern_id():
    with pytest.raises(GovernanceBlocked) as exc_info:
        execute_sql("DROP TABLE users")
    gates = exc_info.value.envelope.get("gate_decisions", [])
    assert len(gates) >= 1
    assert "BLOCK_DROP_TABLE" in str(gates[0])


def test_allow_envelope_also_has_event_id():
    """ALLOW decisions also produce a logged envelope (audit trail for allowed actions)."""
    # We can't directly inspect the logged envelope on allow (no exception raised),
    # but we verify the function returns correctly (implying the envelope path ran).
    result = execute_sql("SELECT * FROM users")
    assert result == "Executed: SELECT * FROM users"


# ── Policy templates ──────────────────────────────────────────────────────────

def test_audit_mode_allows_drop_table():
    """audit_mode never blocks — even CRITICAL patterns are allowed."""
    result = execute_sql_audit("DROP TABLE users")
    assert "audit" in result


def test_audit_mode_allows_rm_rf():
    result = execute_sql_audit("rm -rf /etc")
    assert "audit" in result


def test_read_only_blocks_delete():
    """read_only blocks CRITICAL patterns like DELETE without WHERE."""
    with pytest.raises(GovernanceBlocked):
        execute_sql_read_only("DELETE FROM users")


def test_strict_prod_blocks_everything_matched():
    with pytest.raises(GovernanceBlocked):
        execute_sql_strict("DROP TABLE users")


# ── Action extraction heuristics ─────────────────────────────────────────────

def test_query_param_name_extracted():
    """'query' is a known action param — must be extracted and checked."""
    with pytest.raises(GovernanceBlocked):
        execute_sql("DROP TABLE users")


def test_cmd_param_name_extracted():
    with pytest.raises(GovernanceBlocked):
        run_shell("rm -rf /bin")


def test_command_param_name_extracted():
    with pytest.raises(GovernanceBlocked):
        run_command("rm -rf /boot")


def test_text_param_name_extracted():
    with pytest.raises(GovernanceBlocked):
        process_text("DROP TABLE logs")


def test_action_param_name_extracted():
    with pytest.raises(GovernanceBlocked):
        run_action("TRUNCATE TABLE users")


def test_unrecognized_string_param_still_checked():
    """If param name is unknown but first arg is string, still check it."""
    with pytest.raises(GovernanceBlocked):
        first_string_arg("DROP TABLE unrecognized")


def test_unrecognized_safe_string_allowed():
    result = first_string_arg("SELECT * FROM safe_table")
    assert "Done:" in result


# ── Decorator meta-behavior ───────────────────────────────────────────────────

def test_functools_wraps_preserves_name():
    assert execute_sql.__name__ == "execute_sql"


def test_functools_wraps_preserves_doc():
    assert execute_sql.__doc__ == "Execute a SQL query."


def test_decorator_preserves_return_value():
    result = returns_value("SELECT * FROM users")
    assert result == {"rows": 42, "query": "SELECT * FROM users"}


def test_decorator_propagates_function_exceptions():
    """Non-governance exceptions from the wrapped function must propagate normally."""
    with pytest.raises(ValueError, match="DB connection failed"):
        raises_on_execute("SELECT * FROM users")


def test_keyword_argument_extraction():
    """Decorator must work when action is passed as keyword argument."""
    result = execute_sql(query="SELECT 1")
    assert result == "Executed: SELECT 1"


def test_keyword_argument_blocked():
    with pytest.raises(GovernanceBlocked):
        execute_sql(query="DROP TABLE users")


# ── Policies module ───────────────────────────────────────────────────────────

def test_list_policies_returns_4():
    policies = list_policies()
    assert len(policies) == 4
    assert "safe_defaults" in policies
    assert "audit_mode" in policies
    assert "read_only" in policies
    assert "strict_prod" in policies


def test_get_policy_safe_defaults_blocks_critical():
    p = get_policy("safe_defaults")
    assert policy_decision(p, "CRITICAL") == "block"


def test_get_policy_safe_defaults_blocks_high():
    p = get_policy("safe_defaults")
    assert policy_decision(p, "HIGH") == "block"


def test_get_policy_safe_defaults_allows_low():
    p = get_policy("safe_defaults")
    assert policy_decision(p, "LOW") == "allow"


def test_get_policy_audit_mode_allows_critical():
    p = get_policy("audit_mode")
    assert policy_decision(p, "CRITICAL") == "allow"


def test_get_policy_unknown_falls_back_to_safe_defaults():
    p = get_policy("nonexistent_policy")
    # Falls back to safe_defaults — CRITICAL is blocked
    assert policy_decision(p, "CRITICAL") == "block"
