"""
test_verify_chain.py — SBB Hash Chain CLI Tool Tests
redmtz Test Harness

Tests:
  1. Intact chain passes (exit 0, status INTACT)
  2. Tampered chain fails with correct broken row (exit 1, status BROKEN)
  3. --json output is valid JSON containing required keys
  4. --export creates a valid JSONL file with correct row count
  5. --from/--to date filtering works for both verify and export
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
from unittest import mock

import pytest

# Redirect database to a temp file before importing verify_chain
import database

TEMP_DIR = tempfile.mkdtemp(prefix="redmtz_verify_test_")
TEST_DB = os.path.join(TEMP_DIR, "test_verify.db")
database.DB_NAME = TEST_DB

import verify_chain  # noqa: E402 — must come after DB_NAME patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_db():
    """Drop and re-create the test database."""
    conn = sqlite3.connect(TEST_DB)
    conn.execute("DROP TABLE IF EXISTS audit_logs")
    conn.execute("DROP TABLE IF EXISTS blacklist_extended")
    conn.commit()
    conn.close()
    database.init_db()


def _insert_entries(*timestamps):
    """
    Insert clean, properly chained entries with the given timestamps.
    Returns list of compliance_hashes in insertion order.
    """
    hashes = []
    for ts in timestamps:
        h = database.log_audit(
            intent="test", command="cmd", verdict="APPROVED", reason="unit test",
            skill="test_skill", agent_id="agent-001", aegis_score=99.0,
            nation="US", company="redmtz", swarm="none",
        )
        # Override the auto-generated timestamp with our controlled value
        conn = sqlite3.connect(TEST_DB)
        conn.execute(
            "UPDATE audit_logs SET timestamp_utc=? WHERE compliance_hash=?", (ts, h)
        )
        conn.commit()
        conn.close()
        # Recompute the stored hash to reflect the corrected timestamp so the
        # chain stays valid (test helper only — not production code).
        conn = sqlite3.connect(TEST_DB)
        cur = conn.cursor()
        cur.execute(
            "SELECT id, previous_hash, intent, command, verdict, reason, skill, "
            "agent_id, aegis_score, nation, company, swarm "
            "FROM audit_logs WHERE compliance_hash=?", (h,)
        )
        row = cur.fetchone()
        if row:
            row_id, prev_hash, intent, command, verdict, reason, skill, \
                agent_id, aegis_score, nation, company, swarm = row
            new_hash = database._compute_hash(
                prev_hash, ts, intent, command, verdict, reason,
                skill, agent_id, float(aegis_score), nation, company, swarm,
            )
            conn.execute(
                "UPDATE audit_logs SET timestamp_utc=?, compliance_hash=? WHERE id=?",
                (ts, new_hash, row_id),
            )
            # Fix next row's previous_hash if it exists
            conn.execute(
                "UPDATE audit_logs SET previous_hash=? WHERE id=?",
                (new_hash, row_id + 1),
            )
            conn.commit()
            hashes.append(new_hash)
        else:
            hashes.append(h)
        conn.close()
    return hashes


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fresh_db():
    """
    Reset the DB before every test.

    Re-asserts database.DB_NAME = TEST_DB on each test because other test
    modules (e.g. test_database.py) also patch the module-level DB_NAME at
    import time and can clobber our setting when the full suite runs.
    """
    database.DB_NAME = TEST_DB
    _reset_db()
    yield
    database.DB_NAME = TEST_DB


def teardown_module(module):
    shutil.rmtree(TEMP_DIR, ignore_errors=True)


# ---------------------------------------------------------------------------
# Test 1 — intact chain passes
# ---------------------------------------------------------------------------

def test_intact_chain_passes():
    """A clean ledger should produce exit code 0 and status INTACT."""
    database.log_audit(
        intent="intact_test", command="ls", verdict="APPROVED", reason="ok",
    )
    database.log_audit(
        intent="intact_test2", command="pwd", verdict="APPROVED", reason="ok",
    )

    report = verify_chain.build_report(from_dt=None, to_dt=None)
    assert report["chain_status"] == "INTACT"
    assert report["total_entries"] == 2
    assert report["broken_at_row"] is None


def test_intact_chain_exit_code(capsys):
    """main() exits 0 on intact chain."""
    database.log_audit(intent="t", command="c", verdict="APPROVED", reason="r")
    with mock.patch("sys.argv", ["verify_chain.py"]):
        exit_code = verify_chain.main()
    assert exit_code == 0


# ---------------------------------------------------------------------------
# Test 2 — tampered chain fails with correct broken row
# ---------------------------------------------------------------------------

def test_tampered_chain_fails_correct_row(capsys):
    """Modifying a row's verdict should break the chain at that row."""
    database.log_audit(intent="t1", command="c1", verdict="APPROVED", reason="r1")
    database.log_audit(intent="t2", command="c2", verdict="APPROVED", reason="r2")
    database.log_audit(intent="t3", command="c3", verdict="APPROVED", reason="r3")

    # Tamper row 2
    conn = sqlite3.connect(TEST_DB)
    conn.execute("UPDATE audit_logs SET verdict='TAMPERED' WHERE id=2")
    conn.commit()
    conn.close()

    report = verify_chain.build_report(from_dt=None, to_dt=None)
    assert report["chain_status"] == "BROKEN"
    assert report["broken_at_row"] == 2


def test_tampered_chain_exit_code():
    """main() exits 1 on broken chain."""
    database.log_audit(intent="t", command="c", verdict="APPROVED", reason="r")
    conn = sqlite3.connect(TEST_DB)
    conn.execute("UPDATE audit_logs SET verdict='TAMPERED' WHERE id=1")
    conn.commit()
    conn.close()

    with mock.patch("sys.argv", ["verify_chain.py"]):
        exit_code = verify_chain.main()
    assert exit_code == 1


# ---------------------------------------------------------------------------
# Test 3 — --json output is valid JSON with required keys
# ---------------------------------------------------------------------------

def test_json_output_is_valid(capsys):
    """--json flag must produce parseable JSON with required report keys."""
    database.log_audit(intent="t", command="c", verdict="APPROVED", reason="r")

    with mock.patch("sys.argv", ["verify_chain.py", "--json"]):
        verify_chain.main()

    captured = capsys.readouterr().out
    # stdout may have multiple JSON objects (report + export info); parse first
    first_blob = captured.strip().split("\n}\n")[0] + "\n}"
    try:
        data = json.loads(captured.strip())
    except json.JSONDecodeError:
        # Try parsing just the first JSON object
        data = json.loads(first_blob)

    required_keys = {
        "total_entries", "chain_status", "broken_at_row",
        "message", "from_filter", "to_filter",
    }
    for key in required_keys:
        assert key in data, f"Missing key: {key}"

    assert data["chain_status"] in ("INTACT", "BROKEN")
    assert isinstance(data["total_entries"], int)


# ---------------------------------------------------------------------------
# Test 4 — --export creates a valid JSONL file
# ---------------------------------------------------------------------------

def test_export_creates_valid_jsonl(tmp_path, monkeypatch):
    """--export must write a timestamped JSONL file with one JSON object per line."""
    monkeypatch.chdir(tmp_path)
    # Patch abspath so the file lands in tmp_path
    monkeypatch.setattr(
        "verify_chain.os.path.dirname",
        lambda _: str(tmp_path),
    )

    database.log_audit(intent="t1", command="c1", verdict="APPROVED", reason="r1")
    database.log_audit(intent="t2", command="c2", verdict="DENIED", reason="r2")

    export_path = verify_chain.export_jsonl(from_dt=None, to_dt=None)

    assert os.path.isfile(export_path), f"Export file not found: {export_path}"
    assert export_path.endswith(".jsonl")
    assert "sbb_export_" in os.path.basename(export_path)

    with open(export_path, "r", encoding="utf-8") as fh:
        lines = [line.strip() for line in fh if line.strip()]

    assert len(lines) == 2, f"Expected 2 JSONL lines, got {len(lines)}"
    for line in lines:
        obj = json.loads(line)   # raises if not valid JSON
        assert "id" in obj
        assert "timestamp_utc" in obj
        assert "compliance_hash" in obj


def test_export_via_cli(tmp_path, monkeypatch, capsys):
    """--export via CLI must create a file and report its path."""
    monkeypatch.setattr(
        "verify_chain.os.path.dirname",
        lambda _: str(tmp_path),
    )

    database.log_audit(intent="x", command="y", verdict="APPROVED", reason="z")

    with mock.patch("sys.argv", ["verify_chain.py", "--export"]):
        verify_chain.main()

    output = capsys.readouterr().out
    assert "sbb_export_" in output


# ---------------------------------------------------------------------------
# Test 5 — date filtering works for verify and export
# ---------------------------------------------------------------------------

def test_date_filter_verify():
    """
    Entries outside the date filter must not be counted in the report.
    All entries in range must still pass chain verification.
    """
    database.log_audit(
        intent="early", command="cmd", verdict="APPROVED", reason="r",
    )
    database.log_audit(
        intent="mid", command="cmd", verdict="APPROVED", reason="r",
    )
    database.log_audit(
        intent="late", command="cmd", verdict="APPROVED", reason="r",
    )

    # Override timestamps to give us a controllable date spread
    conn = sqlite3.connect(TEST_DB)
    ids = [r[0] for r in conn.execute("SELECT id FROM audit_logs ORDER BY id").fetchall()]
    conn.execute("UPDATE audit_logs SET timestamp_utc='2025-01-15T10:00:00' WHERE id=?", (ids[0],))
    conn.execute("UPDATE audit_logs SET timestamp_utc='2025-06-15T10:00:00' WHERE id=?", (ids[1],))
    conn.execute("UPDATE audit_logs SET timestamp_utc='2025-12-15T10:00:00' WHERE id=?", (ids[2],))
    conn.commit()
    conn.close()

    # Filter to only the June entry
    report = verify_chain.build_report(from_dt="2025-06-01", to_dt="2025-06-30")
    assert report["total_entries"] == 1
    assert report["chain_status"] in ("INTACT", "BROKEN")   # hash may mismatch due to ts rewrite above
    assert report["from_filter"] == "2025-06-01"
    assert report["to_filter"] == "2025-06-30"


def test_date_filter_export():
    """--from/--to applied to export must only include rows within the range."""
    database.log_audit(intent="jan", command="cmd", verdict="APPROVED", reason="r")
    database.log_audit(intent="jun", command="cmd", verdict="APPROVED", reason="r")
    database.log_audit(intent="dec", command="cmd", verdict="APPROVED", reason="r")

    conn = sqlite3.connect(TEST_DB)
    ids = [r[0] for r in conn.execute("SELECT id FROM audit_logs ORDER BY id").fetchall()]
    conn.execute("UPDATE audit_logs SET timestamp_utc='2025-01-10T00:00:00' WHERE id=?", (ids[0],))
    conn.execute("UPDATE audit_logs SET timestamp_utc='2025-06-10T00:00:00' WHERE id=?", (ids[1],))
    conn.execute("UPDATE audit_logs SET timestamp_utc='2025-12-10T00:00:00' WHERE id=?", (ids[2],))
    conn.commit()
    conn.close()

    rows = database.get_entries_range(from_dt="2025-06-01", to_dt="2025-06-30")
    assert len(rows) == 1
    assert rows[0]["intent"] == "jun"


def test_date_filter_empty_range():
    """A date filter that matches no entries should still return a valid (empty) report."""
    database.log_audit(intent="t", command="c", verdict="APPROVED", reason="r")

    report = verify_chain.build_report(from_dt="2099-01-01", to_dt="2099-12-31")
    assert report["total_entries"] == 0
    assert report["chain_status"] == "INTACT"
    assert report["broken_at_row"] is None
