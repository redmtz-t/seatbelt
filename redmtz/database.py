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
redmtz.database — SHA-256 Hash-Chained Audit Ledger
REDMTZ Seatbelt

The Black Box. Every governance decision is written here.
Tamper-evident: modify any row and the hash chain breaks.

Schema v3 additions (Seatbelt final):
  sig_alg         — signature algorithm label (PQC-ready: sha256+ed25519 today)
  environment     — deployment context (prod/staging/dev). Set via REDMTZ_ENVIRONMENT.
  policy          — policy template active at decision time
  patterns_matched — pipe-separated list of matched pattern IDs
  envelope_hash   — canonical Ed25519-signed envelope hash (single integrity proof)
  remediation     — remediation hint, populated on BLOCKs only

Hash function unchanged from v2. New columns are metadata, not part of the chain.
envelope_hash is the canonical integrity proof going forward.

Authored by: Yang (v0.4.3 original), Nexus (v0.5.0/v0.6.0 upgrade)
Founder: Robert Benitez
"""

import csv
import hashlib
import io
import os
import sqlite3
import sys
from datetime import datetime, timezone
from typing import Optional

# Default DB location: ~/.redmtz/redmtz_audit.db
# Override with REDMTZ_DB_PATH environment variable
_DEFAULT_DB_DIR = os.path.join(os.path.expanduser("~"), ".redmtz")
DB_NAME = os.getenv(
    "REDMTZ_DB_PATH",
    os.path.join(_DEFAULT_DB_DIR, "redmtz_audit.db"),
)

# Deployment environment — set REDMTZ_ENVIRONMENT=prod|staging|dev
# Defaults to "unknown" so CISOs know it needs to be configured.
_DEFAULT_ENVIRONMENT = os.getenv("REDMTZ_ENVIRONMENT", "unknown")

GENESIS_HASH = "GENESIS_BLOCK"

# CSV export column order (CISO-friendly)
_CSV_COLUMNS = [
    "id", "timestamp_utc", "environment", "agent_id", "intent",
    "command", "verdict", "reason", "policy", "patterns_matched",
    "remediation", "sig_alg", "envelope_hash",
    "previous_hash", "compliance_hash", "schema_version",
]


def _ensure_db_dir():
    """Create ~/.redmtz/ if it doesn't exist."""
    db_dir = os.path.dirname(DB_NAME)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)


def _add_column_if_missing(cursor, table: str, column_def: str) -> bool:
    try:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column_def}")
        return True
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            return False
        raise


def init_db():
    """Initialize or migrate the audit database. Safe to call multiple times."""
    try:
        _ensure_db_dir()
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc    TEXT    NOT NULL,
                intent           TEXT    NOT NULL,
                command          TEXT    NOT NULL,
                verdict          TEXT    NOT NULL,
                reason           TEXT    NOT NULL,
                skill            TEXT    DEFAULT 'unknown',
                agent_id         TEXT    DEFAULT 'unknown',
                aegis_score      REAL    DEFAULT 0.0,
                nation           TEXT    DEFAULT 'unknown',
                company          TEXT    DEFAULT 'unknown',
                swarm            TEXT    DEFAULT 'unknown',
                previous_hash    TEXT    NOT NULL,
                compliance_hash  TEXT    NOT NULL,
                schema_version   INTEGER DEFAULT 1,
                sig_alg          TEXT    DEFAULT 'sha256+ed25519',
                environment      TEXT    DEFAULT 'unknown',
                policy           TEXT    DEFAULT 'unknown',
                patterns_matched TEXT    DEFAULT '',
                envelope_hash    TEXT    DEFAULT '',
                remediation      TEXT    DEFAULT ''
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blacklist_sovereign (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                type      TEXT    NOT NULL,
                value     TEXT    NOT NULL,
                reason    TEXT    NOT NULL,
                timestamp REAL    NOT NULL,
                UNIQUE(type, value)
            )
        """)

        # Migrate older schemas — additive only, never destructive
        skill_was_missing = _add_column_if_missing(
            cursor, "audit_logs", "skill TEXT DEFAULT 'unknown'"
        )
        _add_column_if_missing(cursor, "audit_logs", "schema_version INTEGER DEFAULT 1")
        _add_column_if_missing(cursor, "audit_logs", "sig_alg TEXT DEFAULT 'sha256+ed25519'")
        _add_column_if_missing(cursor, "audit_logs", "environment TEXT DEFAULT 'unknown'")
        _add_column_if_missing(cursor, "audit_logs", "policy TEXT DEFAULT 'unknown'")
        _add_column_if_missing(cursor, "audit_logs", "patterns_matched TEXT DEFAULT ''")
        _add_column_if_missing(cursor, "audit_logs", "envelope_hash TEXT DEFAULT ''")
        _add_column_if_missing(cursor, "audit_logs", "remediation TEXT DEFAULT ''")

        if not skill_was_missing:
            # Existing v1 rows → bump to v2
            cursor.execute(
                "UPDATE audit_logs SET schema_version=2 WHERE schema_version=1"
            )

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[redmtz][FATAL] init_db failed: {e}", file=sys.stderr)
        raise


def _compute_hash(prev_hash: str, timestamp: str, intent: str, command: str,
                  verdict: str, reason: str, skill: str, agent_id: str,
                  aegis_score: float, nation: str, company: str, swarm: str) -> str:
    """v2/v3 hash function. New metadata columns are NOT part of the chain —
    envelope_hash is the canonical integrity proof for v3 rows."""
    payload = (
        f"{prev_hash}|{timestamp}|{intent}|{command}|{verdict}|{reason}|"
        f"{skill}|{agent_id}|{aegis_score}|{nation}|{company}|{swarm}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _compute_hash_v1(prev_hash: str, timestamp: str, intent: str,
                     command: str, verdict: str, reason: str) -> str:
    payload = f"{prev_hash}|{timestamp}|{intent}|{command}|{verdict}|{reason}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_last_hash() -> str:
    """Return the compliance_hash of the most recent entry, or GENESIS_BLOCK."""
    try:
        _ensure_db_dir()
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_utc    TEXT    NOT NULL,
                intent           TEXT    NOT NULL,
                command          TEXT    NOT NULL,
                verdict          TEXT    NOT NULL,
                reason           TEXT    NOT NULL,
                skill            TEXT    DEFAULT 'unknown',
                agent_id         TEXT    DEFAULT 'unknown',
                aegis_score      REAL    DEFAULT 0.0,
                nation           TEXT    DEFAULT 'unknown',
                company          TEXT    DEFAULT 'unknown',
                swarm            TEXT    DEFAULT 'unknown',
                previous_hash    TEXT    NOT NULL,
                compliance_hash  TEXT    NOT NULL,
                schema_version   INTEGER DEFAULT 1,
                sig_alg          TEXT    DEFAULT 'sha256+ed25519',
                environment      TEXT    DEFAULT 'unknown',
                policy           TEXT    DEFAULT 'unknown',
                patterns_matched TEXT    DEFAULT '',
                envelope_hash    TEXT    DEFAULT '',
                remediation      TEXT    DEFAULT ''
            )
        """)
        cursor.execute(
            "SELECT compliance_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
        )
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else GENESIS_HASH
    except Exception as e:
        print(f"[redmtz][ERROR] get_last_hash failed: {e}", file=sys.stderr)
        return "ERROR_RETRIEVING_HASH"


def log_audit(
    intent: str,
    command: str,
    verdict: str,
    reason: str,
    skill: str = "unknown",
    agent_id: str = "unknown",
    aegis_score: float = 0.0,
    nation: str = "unknown",
    company: str = "unknown",
    swarm: str = "unknown",
    envelope=None,
    # v3 metadata fields
    sig_alg: str = "sha256+ed25519",
    environment: Optional[str] = None,
    policy: str = "unknown",
    patterns_matched: Optional[list] = None,
    envelope_hash: str = "",
    remediation: str = "",
) -> str:
    """
    Write a tamper-evident audit entry. Returns compliance_hash.
    Raises on failure (fail-closed).

    v3 fields (all optional, backward compatible):
        sig_alg         — signature algorithm. Default: 'sha256+ed25519'.
        environment     — deployment env. Default: REDMTZ_ENVIRONMENT env var or 'unknown'.
        policy          — active policy template name.
        patterns_matched — list of matched pattern IDs (stored as pipe-separated string).
        envelope_hash   — canonical signed envelope hash (single integrity proof).
        remediation     — remediation hint for BLOCKs. Empty string for ALLOWs.
    """
    try:
        _ensure_db_dir()
        init_db()
        prev_hash = get_last_hash()
        timestamp = datetime.now(timezone.utc).isoformat()

        env = environment if environment is not None else _DEFAULT_ENVIRONMENT
        patterns_str = "|".join(patterns_matched) if patterns_matched else ""

        comp_hash = _compute_hash(
            prev_hash, timestamp, intent, command, verdict, reason,
            skill, agent_id, aegis_score, nation, company, swarm
        )

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs (
                timestamp_utc, intent, command, verdict, reason, skill,
                agent_id, aegis_score, nation, company, swarm,
                previous_hash, compliance_hash, schema_version,
                sig_alg, environment, policy, patterns_matched,
                envelope_hash, remediation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 3,
                      ?, ?, ?, ?, ?, ?)
        """, (
            timestamp, intent, command, verdict, reason, skill,
            agent_id, aegis_score, nation, company, swarm,
            prev_hash, comp_hash,
            sig_alg, env, policy, patterns_str,
            envelope_hash, remediation,
        ))
        conn.commit()
        conn.close()
        return comp_hash

    except Exception as e:
        print(f"[redmtz][FATAL] log_audit failed: {e}", file=sys.stderr)
        raise


def verify_chain() -> dict:
    """Walk the entire audit ledger and verify every hash link."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp_utc, intent, command, verdict, reason,
                   skill, agent_id, aegis_score, nation, company, swarm,
                   previous_hash, compliance_hash, schema_version
            FROM audit_logs ORDER BY id ASC
        """)
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            return {"valid": True, "total_entries": 0, "first_break": None,
                    "message": "Ledger is empty."}

        expected_prev = GENESIS_HASH
        for row in rows:
            row_id        = row[0]
            stored_prev   = row[12]
            stored_hash   = row[13]
            schema_version = row[14] if row[14] is not None else 1

            if stored_prev != expected_prev:
                return {"valid": False, "total_entries": len(rows),
                        "first_break": row_id,
                        "message": f"CHAIN BROKEN at row {row_id}"}

            if schema_version == 1:
                recomputed = _compute_hash_v1(
                    stored_prev, row[1], row[2], row[3], row[4], row[5])
            else:
                # v2 and v3 use the same hash function
                recomputed = _compute_hash(
                    stored_prev, row[1], row[2], row[3], row[4], row[5],
                    row[6], row[7], float(row[8]), row[9], row[10], row[11])

            if recomputed != stored_hash:
                return {"valid": False, "total_entries": len(rows),
                        "first_break": row_id,
                        "message": f"HASH MISMATCH at row {row_id} — DATA TAMPERED"}

            expected_prev = stored_hash

        return {"valid": True, "total_entries": len(rows), "first_break": None,
                "message": f"CHAIN INTACT. All {len(rows)} entries verified."}

    except Exception as e:
        return {"valid": False, "total_entries": 0, "first_break": None,
                "message": f"VERIFICATION ERROR: {e}"}


def get_chain_status() -> dict:
    """Quick health check. Returns chain validity + entry count + last hash."""
    chain = verify_chain()
    last  = get_last_hash()
    return {
        "chain_valid":    chain["valid"],
        "total_entries":  chain["total_entries"],
        "last_hash":      last,
        "message":        chain["message"],
    }


def export_csv(output_path: Optional[str] = None) -> dict:
    """
    Export the full audit ledger as a CISO-ready CSV with an Ed25519 signature.

    The CSV content is hashed (SHA-256) and signed with the governance key,
    so any auditor with the public key can verify the export hasn't been
    tampered with after generation.

    Args:
        output_path: Optional file path to write the CSV. If None, returns
                     the CSV as a string in the result dict.

    Returns:
        dict with keys:
            csv_hash      — SHA-256 of the CSV content
            signature     — base64 Ed25519 signature over csv_hash
            total_rows    — number of data rows exported
            output_path   — path written (or None if returned as string)
            csv_content   — CSV string (only present if output_path is None)
            public_key_path — path to public key for verification
    """
    from . import sudo_signing  # local import to avoid circular at module load

    try:
        conn   = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT {', '.join(_CSV_COLUMNS)}
            FROM audit_logs
            ORDER BY id ASC
        """)
        rows = cursor.fetchall()
        conn.close()
    except Exception as e:
        return {"error": f"Database read failed: {e}", "total_rows": 0}

    # Build CSV in memory
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerow(_CSV_COLUMNS)  # header
    for row in rows:
        writer.writerow(row)

    # Append export metadata as a comment line (auditors can strip, it's informational)
    export_ts = datetime.now(timezone.utc).isoformat()
    buf.write(f"# REDMTZ Seatbelt export — {export_ts}\n")
    buf.write(f"# Rows: {len(rows)} | Verify with: redmtz verify-export\n")

    csv_content = buf.getvalue()

    # Hash + sign
    csv_hash  = hashlib.sha256(csv_content.encode("utf-8")).hexdigest()
    try:
        signature = sudo_signing.sign_decision(csv_hash)
    except Exception as e:
        return {"error": f"Signing failed: {e}", "total_rows": len(rows)}

    result = {
        "csv_hash":        csv_hash,
        "signature":       signature,
        "total_rows":      len(rows),
        "output_path":     output_path,
        "public_key_path": sudo_signing.PUBLIC_KEY_PATH,
    }

    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(csv_content)
                f.write(f"# csv_hash: {csv_hash}\n")
                f.write(f"# signature: {signature}\n")
        except Exception as e:
            return {"error": f"File write failed: {e}", "total_rows": len(rows)}
    else:
        # Append hash + sig as trailing comment lines in the returned string
        csv_content += f"# csv_hash: {csv_hash}\n"
        csv_content += f"# signature: {signature}\n"
        result["csv_content"] = csv_content

    return result
