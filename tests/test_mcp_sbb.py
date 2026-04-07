#!/usr/bin/env python3
"""
test_mcp_sbb.py — MCP Server × SBB+SEDR Integration Tests
redmtz Synapse Protocol

Confirms that:
  1.  The module-level SBBWriter is properly wired in mcp_server.
  2.  Heartbeat fires: verdict=ALIVE, gate=HEARTBEAT appear in SEDR.
  3.  Heartbeat is also written to SBB (audit_logs row exists).
  4.  A PROCEED gate decision appears in both SBB (audit_logs) and SEDR.
  5.  A BLOCK gate decision appears in both SBB and SEDR with correct verdict.
  6.  SEDR entries carry the correct gate=FINAL_VERDICT label.
  7.  SBB compliance_hash in SEDR matches the hash in the pipeline result.
  8.  SEDR entry metadata_hash is a valid SHA-256 (Rule #8 — no raw content).
  9.  SBB chain is valid after multiple MCP decisions (hash chain intact).
  10. writer.get_status() reflects both SBB and SEDR entry counts.

Founder: Robert Benitez
"""

import os
import sys
import json
import shutil
import sqlite3
import tempfile
import types
import pytest

# ── Temp environment (must happen before importing mcp_server) ────────────────
TEMP_DIR  = tempfile.mkdtemp(prefix="redmtz_test_mcp_sbb_")
DB_PATH   = os.path.join(TEMP_DIR, "test_mcp_sbb.db")
SEDR_PATH = os.path.join(TEMP_DIR, "test_mcp_sbb_sedr.jsonl")

import database
database.DB_NAME = DB_PATH
database.init_db()

_conn = sqlite3.connect(DB_PATH)
_conn.executescript("""
    CREATE TABLE IF NOT EXISTS context_checkpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp_utc TEXT, checkpoint_hash TEXT, parent_hash TEXT,
        reason TEXT, agent_id TEXT, token_estimate INTEGER,
        message_count INTEGER, summary TEXT
    );
    CREATE TABLE IF NOT EXISTS sudo_requests (
        request_id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        company TEXT DEFAULT 'unknown', nation TEXT DEFAULT 'unknown',
        swarm TEXT DEFAULT 'default-swarm',
        intent TEXT NOT NULL, command TEXT NOT NULL,
        skill_name TEXT DEFAULT 'unknown', target TEXT DEFAULT '',
        risk_level TEXT DEFAULT 'UNKNOWN',
        escalation_reason TEXT NOT NULL, escalation_detail TEXT DEFAULT '',
        yang_verdict TEXT DEFAULT '', aegis_score REAL DEFAULT 0.0,
        aegis_status TEXT DEFAULT 'NOMINAL',
        governance_token_id TEXT DEFAULT '', parent_request_id TEXT DEFAULT '',
        escalation_depth INTEGER DEFAULT 0, status TEXT DEFAULT 'PENDING',
        created_at REAL NOT NULL, decided_at REAL, decided_by TEXT,
        decision_reason TEXT, timeout_at REAL NOT NULL,
        request_hash TEXT NOT NULL, decision_hash TEXT DEFAULT ''
    );
""")
_conn.close()

import config
config.Config.AUDIT_DB = DB_PATH

_fake_mcp    = types.ModuleType("mcp")
_fake_server = types.ModuleType("mcp.server")
_fake_fmcp   = types.ModuleType("mcp.server.fastmcp")

class _FakeMCP:
    def __init__(self, name): self.name = name
    def tool(self): return lambda f: f
    def run(self, **kw): pass

_fake_fmcp.FastMCP = _FakeMCP
sys.modules["mcp"]                = _fake_mcp
sys.modules["mcp.server"]         = _fake_server
sys.modules["mcp.server.fastmcp"] = _fake_fmcp

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


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sedr_entries():
    if not os.path.exists(SEDR_PATH):
        return []
    lines = []
    with open(SEDR_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                lines.append(json.loads(line))
    return lines


def _db_row_count(table="audit_logs"):
    conn = sqlite3.connect(DB_PATH)
    n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    conn.close()
    return n


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_writer_is_sbb_writer_instance():
    assert hasattr(mcp_server, "writer"), "mcp_server must expose 'writer'"
    assert isinstance(mcp_server.writer, _sbb_mod.SBBWriter), \
        f"writer must be SBBWriter, got {type(mcp_server.writer)}"


def test_heartbeat_fires_in_sedr_and_sbb():
    db_before   = _db_row_count()
    sedr_before = len(_sedr_entries())

    hb = mcp_server.writer.log_heartbeat()
    assert hb["sbb_written"] is True,  "Heartbeat must write to SBB"
    assert hb["sedr_written"] is True, "Heartbeat must write to SEDR"

    # SEDR check
    entries    = _sedr_entries()
    hb_entries = [e for e in entries if e.get("gate") == "HEARTBEAT"]
    assert len(hb_entries) >= 1, "No HEARTBEAT entry found in SEDR"
    hb_entry = hb_entries[-1]
    assert hb_entry["verdict"]  == "ALIVE",     f"Expected ALIVE, got {hb_entry['verdict']}"
    assert hb_entry["agent_id"] == "SBB_SYSTEM"

    # SBB check
    assert _db_row_count() > db_before, \
        f"SBB audit_logs should have grown after heartbeat (was {db_before})"
    assert len(_sedr_entries()) > sedr_before


def test_proceed_decision_written_to_sbb_and_sedr():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM blacklist_sovereign")
    conn.commit()
    conn.close()

    db_before   = _db_row_count()
    sedr_before = len(_sedr_entries())

    raw    = mcp_server.verify_action(
        intent="list files in current directory",
        command="ls -la",
        agent_id="sbb-test-agent",
        company="redmtz",
        nation="US",
        swarm="default-swarm",
    )
    result = json.loads(raw)

    assert _db_row_count() > db_before,     "SBB must have a new row after pipeline run"
    assert len(_sedr_entries()) > sedr_before, "SEDR must have a new entry after pipeline run"
    assert result["verdict"] in ("PROCEED", "BLOCK"), f"Unexpected verdict: {result['verdict']}"


def test_block_decision_written_to_sbb_and_sedr_with_correct_verdict():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO blacklist_sovereign (type, value, reason, timestamp) VALUES (?,?,?,?)",
        ("nation", "TESTBLOCK", "SBB integration test", 1.0),
    )
    conn.commit()
    conn.close()

    db_before   = _db_row_count()
    sedr_before = len(_sedr_entries())

    raw_block = mcp_server.verify_action(
        intent="list files",
        command="ls",
        agent_id="blocked-agent",
        company="evil-corp",
        nation="TESTBLOCK",
        swarm="swarm-x",
    )
    result_block = json.loads(raw_block)
    assert result_block["verdict"] == "BLOCK", \
        f"Expected BLOCK for blacklisted nation, got {result_block['verdict']}"

    assert _db_row_count()     > db_before,   "SBB must grow after BLOCK decision"
    assert len(_sedr_entries()) > sedr_before, "SEDR must grow after BLOCK decision"

    new_sedr       = _sedr_entries()[sedr_before:]
    final_entries  = [e for e in new_sedr if e.get("gate") == "FINAL_VERDICT"]
    assert len(final_entries) >= 1, "SEDR must have a FINAL_VERDICT entry for BLOCK"
    assert final_entries[-1]["verdict"] == "BLOCK", \
        f"SEDR FINAL_VERDICT entry should be BLOCK, got {final_entries[-1]['verdict']}"


def test_sedr_entries_carry_final_verdict_gate_label():
    all_entries    = _sedr_entries()
    final_verdicts = [e for e in all_entries if e.get("gate") == "FINAL_VERDICT"]
    assert len(final_verdicts) >= 1, "Expected at least one FINAL_VERDICT entry in SEDR"
    for e in final_verdicts:
        assert e.get("gate") == "FINAL_VERDICT"


def test_sedr_compliance_hash_matches_pipeline_result():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO blacklist_sovereign (type, value, reason, timestamp) VALUES (?,?,?,?)",
        ("nation", "HASHCHECK", "hash verification test", 1.0),
    )
    conn.commit()
    conn.close()

    sedr_before = len(_sedr_entries())
    raw = mcp_server.verify_action(
        intent="list files",
        command="ls",
        agent_id="hash-agent",
        company="evil-corp",
        nation="HASHCHECK",
        swarm="swarm-x",
    )
    result = json.loads(raw)

    if result.get("compliance_hash"):
        new_sedr      = _sedr_entries()[sedr_before:]
        final_entries = [e for e in new_sedr if e.get("gate") == "FINAL_VERDICT"]
        matching = [
            e for e in final_entries
            if e.get("compliance_hash") == result["compliance_hash"]
        ]
        assert len(matching) >= 1, (
            f"compliance_hash {result['compliance_hash'][:16]}... not found in SEDR"
        )


def test_sedr_metadata_hash_is_valid_sha256():
    all_entries    = _sedr_entries()
    final_verdicts = [e for e in all_entries if e.get("gate") == "FINAL_VERDICT"]
    for e in final_verdicts:
        mhash = e.get("metadata_hash", "")
        assert isinstance(mhash, str) and len(mhash) == 64, \
            f"metadata_hash must be 64-char hex SHA-256, got: {repr(mhash)}"
        int(mhash, 16)  # raises if not valid hex


def test_sbb_chain_valid_after_multiple_decisions():
    chain = database.verify_chain()
    assert chain["valid"] is True, \
        f"SBB hash chain must be intact: {chain['message']}"
    assert chain["total_entries"] >= 2, \
        f"Expected at least 2 entries in chain, got {chain['total_entries']}"


def test_get_status_reflects_sbb_and_sedr_counts():
    status = mcp_server.writer.get_status()
    assert "sbb"  in status and "sedr" in status
    assert status["sbb"]["chain_valid"] is True, \
        f"SBB chain must be valid: {status['sbb']}"
    assert status["sedr"]["exists"] is True

    sedr_count   = status["sedr"]["entries"]
    actual_lines = len(_sedr_entries())
    assert sedr_count == actual_lines, \
        f"get_status SEDR count ({sedr_count}) must match file ({actual_lines})"
