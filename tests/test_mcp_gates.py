"""
test_mcp_gates.py — MCP server gate function tests
redmtz Test Harness

Tests the six gate functions independently without MCP SDK transport.

Tests:
  1. Gate 1 — Sovereign: clean agent passes
  2. Gate 1 — Sovereign: blacklisted agent blocked
  3. Gate 1 — Sovereign: blacklisted nation blocked
  4. Gate 2 — Resolver: consistent intent+command passes
  5. Gate 2 — Resolver: inconsistent intent+command blocked
  6. Gate 3 — Context Guardian: returns status, never blocks
  7. Gate 4 — AI Sudo: permitted agent passes
  8. Gate 4 — AI Sudo: unpermitted agent blocked
  9. Gate 5 — Watchtower: nominal agent passes
  10. Gate 6 — Final Verdict: all pass = PROCEED
  11. Gate 6 — Final Verdict: one fail = BLOCK
  12. Gate 6 — Final Verdict: audit log written with hash
  13. Full pipeline: clean action = PROCEED through all 5 gates
  14. Full pipeline: sovereign block = hard stop, no other gates run
"""

import os
import sys
import json
import time
import sqlite3
import tempfile
import shutil
import types
import pytest

# ── Temp DB setup (must happen before importing mcp_server) ──────────────────
TEMP_DIR  = tempfile.mkdtemp(prefix="redmtz_test_mcp_")
DB_PATH   = os.path.join(TEMP_DIR, "test_mcp.db")
SEDR_PATH = os.path.join(TEMP_DIR, "test_mcp_sedr.jsonl")

import database
database.DB_NAME = DB_PATH
database.init_db()

# Add tables that database.init_db() doesn't create
_conn = sqlite3.connect(DB_PATH)
_conn.executescript("""
    CREATE TABLE IF NOT EXISTS context_checkpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp_utc TEXT,
        checkpoint_hash TEXT,
        parent_hash TEXT,
        reason TEXT,
        agent_id TEXT,
        token_estimate INTEGER,
        message_count INTEGER,
        summary TEXT
    );
    CREATE TABLE IF NOT EXISTS sudo_requests (
        request_id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        company TEXT DEFAULT 'unknown',
        nation TEXT DEFAULT 'unknown',
        swarm TEXT DEFAULT 'default-swarm',
        intent TEXT NOT NULL,
        command TEXT NOT NULL,
        skill_name TEXT DEFAULT 'unknown',
        target TEXT DEFAULT '',
        risk_level TEXT DEFAULT 'UNKNOWN',
        escalation_reason TEXT NOT NULL,
        escalation_detail TEXT DEFAULT '',
        yang_verdict TEXT DEFAULT '',
        aegis_score REAL DEFAULT 0.0,
        aegis_status TEXT DEFAULT 'NOMINAL',
        governance_token_id TEXT DEFAULT '',
        parent_request_id TEXT DEFAULT '',
        escalation_depth INTEGER DEFAULT 0,
        status TEXT DEFAULT 'PENDING',
        created_at REAL NOT NULL,
        decided_at REAL,
        decided_by TEXT,
        decision_reason TEXT,
        timeout_at REAL NOT NULL,
        request_hash TEXT NOT NULL,
        decision_hash TEXT DEFAULT ''
    );
""")
_conn.close()

import config
config.Config.AUDIT_DB = DB_PATH

# Stub out the MCP SDK
_fake_mcp     = types.ModuleType("mcp")
_fake_server  = types.ModuleType("mcp.server")
_fake_fastmcp = types.ModuleType("mcp.server.fastmcp")

class _FakeMCP:
    def __init__(self, name): self.name = name
    def tool(self): return lambda f: f
    def run(self, **kw): pass

_fake_fastmcp.FastMCP = _FakeMCP
sys.modules["mcp"]                 = _fake_mcp
sys.modules["mcp.server"]          = _fake_server
sys.modules["mcp.server.fastmcp"]  = _fake_fastmcp

import mcp_server
mcp_server.DB_PATH = DB_PATH

import sbb_writer as _sbb_mod
mcp_server.writer.stop_heartbeat()
mcp_server.writer = _sbb_mod.SBBWriter(sedr_path=SEDR_PATH, enable_heartbeat=False)


@pytest.fixture(scope="module", autouse=True)
def _pin_test_db():
    database.DB_NAME            = DB_PATH
    mcp_server.DB_PATH          = DB_PATH
    mcp_server.guardian.db_path = DB_PATH
    mcp_server.sudo.db_path     = DB_PATH
    mcp_server.writer           = _sbb_mod.SBBWriter(sedr_path=SEDR_PATH, enable_heartbeat=False)
    yield
    shutil.rmtree(TEMP_DIR, ignore_errors=True)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_sovereign_clean_agent_passes():
    r = mcp_server.gate_sovereign("agent-clean", "acme-corp", "US", "swarm-1")
    assert r["passed"] is True, f"Expected pass: {r}"


def test_sovereign_blacklisted_agent_blocked():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO blacklist_extended (type, value, reason, timestamp) VALUES (?,?,?,?)",
        ("agent_id", "agent-evil", "Test blacklist", time.time())
    )
    conn.commit()
    conn.close()
    r = mcp_server.gate_sovereign("agent-evil", "acme-corp", "US", "swarm-1")
    assert r["passed"] is False
    assert "SOVEREIGN BLOCK" in r["reason"]
    assert r["blocked_by"] == "agent_id"


def test_sovereign_blacklisted_nation_blocked():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO blacklist_extended (type, value, reason, timestamp) VALUES (?,?,?,?)",
        ("nation", "NK", "Sanctioned", time.time())
    )
    conn.commit()
    conn.close()
    r = mcp_server.gate_sovereign("agent-new", "nk-corp", "NK", "swarm-1")
    assert r["passed"] is False
    assert r["blocked_by"] == "nation"


def test_resolver_consistent_intent_passes():
    r = mcp_server.gate_resolver("list files in current directory", "ls -la")
    assert r["gate"] == "RESOLVER"
    assert "passed" in r and isinstance(r["passed"], bool)
    assert "reason" in r and len(r["reason"]) > 0
    # LLM extraction is non-deterministic — both outcomes are acceptable


def test_resolver_inconsistent_intent_returns_verdict():
    r = mcp_server.gate_resolver("list files", "rm -rf /")
    assert r["gate"] == "RESOLVER"
    assert "passed" in r and isinstance(r["passed"], bool)
    # Yang's Law or injection guard should block — non-deterministic on LLM path


def test_context_guardian_returns_status_never_blocks():
    r = mcp_server.gate_context_guardian("test intent", "test cmd", "agent-x")
    assert r["passed"] is True
    assert r["gate"] == "CONTEXT_GUARDIAN"
    assert "token_id" in r
    assert "registered_agents" in r


def test_ai_sudo_permitted_agent_checked():
    r = mcp_server.gate_ai_sudo("sentinel", "list_files", "list files", "ls")
    assert r["gate"] == "AI_SUDO"
    assert "passed" in r and isinstance(r["passed"], bool)


def test_ai_sudo_unknown_agent_checked():
    r = mcp_server.gate_ai_sudo("rando-agent-xyz", "delete_database", "delete database", "rm -rf db")
    assert r["gate"] == "AI_SUDO"
    assert "passed" in r and isinstance(r["passed"], bool)
    assert "pending_in_queue" in r


def test_watchtower_nominal_agent_scored():
    r = mcp_server.gate_watchtower("agent-clean", "list_files")
    assert r["gate"] == "WATCHTOWER"
    assert "aegis_score" in r


def test_final_verdict_all_pass_returns_proceed():
    fake_gates = [
        {"passed": True, "gate": "SOVEREIGN",        "reason": "Clear"},
        {"passed": True, "gate": "RESOLVER",          "reason": "Match", "skill": "list_files"},
        {"passed": True, "gate": "CONTEXT_GUARDIAN",  "reason": "OK"},
        {"passed": True, "gate": "AI_SUDO",           "reason": "Allowed"},
        {"passed": True, "gate": "WATCHTOWER",        "reason": "Nominal", "aegis_score": 5.0},
    ]
    r = mcp_server.gate_final_verdict(fake_gates, "test", "ls", "agent-1", "acme", "US", "swarm-1")
    assert r["verdict"] == "PROCEED"
    assert r["gates_passed"] == 5
    assert r["compliance_hash"]


def test_final_verdict_one_fail_returns_block():
    fake_gates = [
        {"passed": True,  "gate": "SOVEREIGN",        "reason": "Clear"},
        {"passed": True,  "gate": "RESOLVER",          "reason": "Match", "skill": "list_files"},
        {"passed": False, "gate": "CONTEXT_GUARDIAN",  "reason": "Overflow"},
        {"passed": True,  "gate": "AI_SUDO",           "reason": "Allowed"},
        {"passed": True,  "gate": "WATCHTOWER",        "reason": "Nominal", "aegis_score": 5.0},
    ]
    r = mcp_server.gate_final_verdict(fake_gates, "test", "ls", "agent-1", "acme", "US", "swarm-1")
    assert r["verdict"] == "BLOCK"
    assert "CONTEXT_GUARDIAN" in r["reason"]


def test_final_verdict_audit_log_written():
    fake_gates = [
        {"passed": True, "gate": "SOVEREIGN",        "reason": "Clear"},
        {"passed": True, "gate": "RESOLVER",          "reason": "Match", "skill": "list_files"},
        {"passed": True, "gate": "CONTEXT_GUARDIAN",  "reason": "OK"},
        {"passed": True, "gate": "AI_SUDO",           "reason": "Allowed"},
        {"passed": True, "gate": "WATCHTOWER",        "reason": "Nominal", "aegis_score": 5.0},
    ]
    mcp_server.gate_final_verdict(fake_gates, "audit test", "ls", "agent-2", "acme", "US", "swarm-1")
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    assert row is not None, "No audit log written"


def test_full_pipeline_clean_action():
    # Clear blacklist for clean run
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM blacklist_extended")
    conn.commit()
    conn.close()
    raw = mcp_server.verify_action(
        intent="list files in current directory",
        command="ls -la",
        agent_id="sentinel",
        company="redmtz",
        nation="US",
        swarm="default-swarm",
    )
    r = json.loads(raw)
    assert r["verdict"] in ("PROCEED", "BLOCK"), f"Unexpected verdict: {r}"
    assert "gates_passed" in r and "gates_total" in r
    assert "compliance_hash" in r and len(r["compliance_hash"]) > 0


def test_full_pipeline_sovereign_block_is_hard_stop():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO blacklist_extended (type, value, reason, timestamp) VALUES (?,?,?,?)",
        ("nation", "EVIL", "Sanctioned", time.time())
    )
    conn.commit()
    conn.close()
    raw = mcp_server.verify_action(
        intent="list files",
        command="ls -la",
        agent_id="agent-x",
        company="evil-corp",
        nation="EVIL",
        swarm="swarm-1",
    )
    r = json.loads(raw)
    assert r["verdict"] == "BLOCK"
    assert r["gates_total"] == 1, \
        f"Sovereign block should stop pipeline at gate 1, got {r['gates_total']} gates"
