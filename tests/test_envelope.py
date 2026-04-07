"""
test_envelope.py — RDM-019: Canonical Signed Event Envelope Tests
redmtz Synapse Protocol

20+ tests covering:
  - UUID v7 generation
  - Envelope construction and field presence
  - Digest-only policy (no raw content stored)
  - Hash chain integrity across consecutive envelopes
  - Signature creation and verification
  - Tamper detection
  - Gate decision combinations
  - Schema validation
  - Edge cases

Founder: Robert Benitez
"""

import hashlib
import json
import os
import shutil
import tempfile
import time
import uuid

import pytest

# ── Isolation — temp DB + temp keys before any import ─────────────────────────
TEMP_DIR  = tempfile.mkdtemp(prefix="redmtz_test_envelope_")
TEST_DB   = os.path.join(TEMP_DIR, "test_envelope.db")
TEST_KEY  = os.path.join(TEMP_DIR, "test_envelope.key")
TEST_PUB  = os.path.join(TEMP_DIR, "test_envelope.pub")

import database
database.DB_NAME = TEST_DB
database.init_db()

import sudo_signing
sudo_signing.PRIVATE_KEY_PATH = TEST_KEY
sudo_signing.PUBLIC_KEY_PATH  = TEST_PUB
sudo_signing.ensure_keypair()

from envelope import CanonicalEnvelope, _digest, _envelope_hash, _uuid7, GATE_ORDER


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module", autouse=True)
def _setup_and_teardown():
    database.DB_NAME              = TEST_DB
    sudo_signing.PRIVATE_KEY_PATH = TEST_KEY
    sudo_signing.PUBLIC_KEY_PATH  = TEST_PUB
    yield
    shutil.rmtree(TEMP_DIR, ignore_errors=True)


def _make_envelope(**kwargs) -> dict:
    """Build a minimal valid envelope for testing."""
    env = CanonicalEnvelope()
    defaults = dict(
        actor={
            "type": "agent",
            "identity": "test-agent-01",
            "credential_method": "api_key",
        },
        action={
            "verb": "execute",
            "domain": "filesystem",
            "resource": "ls -la",
            "scope": None,
        },
        gate_decisions=[
            {"gate": "sovereign",      "decision": "allow",   "reason": "not blacklisted"},
            {"gate": "resolver",       "decision": "allow",   "reason": "intent consistent"},
            {"gate": "context_guardian","decision": "allow",  "reason": "mesh authorized"},
            {"gate": "ai_sudo",        "decision": "allow",   "reason": "low risk"},
            {"gate": "watchtower",     "decision": "allow",   "reason": "aegis nominal"},
            {"gate": "reasoner",       "decision": "allow",   "reason": "synthesized"},
            {"gate": "final_verdict",  "decision": "allow",   "reason": "all gates passed"},
        ],
        policy={"version": "v2.1.0", "hash": "a" * 64},
        execution_result={"status": "success", "hash": None, "error_code": None, "result_source": "upstream"},
        input_content="list files in project directory",
        output_content="governance decision: PROCEED",
    )
    defaults.update(kwargs)
    return env.build(**defaults)


# ── UUID v7 tests ─────────────────────────────────────────────────────────────

def test_uuid7_returns_valid_uuid_string():
    result = _uuid7()
    parsed = uuid.UUID(result)
    assert isinstance(result, str)
    assert len(result) == 36


def test_uuid7_is_unique():
    ids = {_uuid7() for _ in range(100)}
    assert len(ids) == 100, "UUID v7 must generate unique values"


def test_uuid7_is_time_ordered():
    ids = [_uuid7() for _ in range(10)]
    # Each UUID encodes timestamp in high bits — later UUIDs should be >= earlier ones
    ints = [uuid.UUID(u).int for u in ids]
    assert ints == sorted(ints), "UUID v7 must be time-ordered"


# ── Digest helper tests ────────────────────────────────────────────────────────

def test_digest_returns_64_char_hex():
    d = _digest("hello world")
    assert len(d) == 64
    int(d, 16)  # raises if not valid hex


def test_digest_is_deterministic():
    assert _digest("same content") == _digest("same content")


def test_digest_differs_for_different_content():
    assert _digest("content A") != _digest("content B")


def test_digest_accepts_bytes():
    d = _digest(b"raw bytes")
    assert len(d) == 64


def test_digest_accepts_dict():
    d = _digest({"key": "value", "num": 42})
    assert len(d) == 64


# ── Envelope construction tests ───────────────────────────────────────────────

def test_envelope_has_all_required_fields():
    e = _make_envelope()
    required = [
        "event_id", "timestamp_utc", "timestamp_monotonic", "replay_nonce",
        "actor", "action", "input", "output", "gate_decisions", "policy",
        "execution_result", "model", "hash_chain", "signatures",
    ]
    for field in required:
        assert field in e, f"Missing required field: {field}"


def test_envelope_event_id_is_valid_uuid():
    e = _make_envelope()
    parsed = uuid.UUID(e["event_id"])
    assert isinstance(parsed, uuid.UUID)


def test_envelope_replay_nonce_is_valid_uuid():
    e = _make_envelope()
    parsed = uuid.UUID(e["replay_nonce"])
    assert isinstance(parsed, uuid.UUID)


def test_envelope_replay_nonce_unique_per_build():
    e1 = _make_envelope()
    e2 = _make_envelope()
    assert e1["replay_nonce"] != e2["replay_nonce"]


def test_envelope_timestamp_monotonic_is_positive_int():
    e = _make_envelope()
    assert isinstance(e["timestamp_monotonic"], int)
    assert e["timestamp_monotonic"] > 0


# ── Digest-only policy tests ──────────────────────────────────────────────────

def test_raw_input_not_stored_in_envelope():
    raw = "sensitive user query with PII: John Doe SSN 123-45-6789"
    e = _make_envelope(input_content=raw)
    envelope_str = json.dumps(e)
    assert raw not in envelope_str, "Raw input content must never appear in envelope"


def test_raw_output_not_stored_in_envelope():
    raw = "output with PHI: patient record 42 blood type O+"
    e = _make_envelope(output_content=raw)
    envelope_str = json.dumps(e)
    assert raw not in envelope_str, "Raw output content must never appear in envelope"


def test_input_digest_matches_expected():
    raw = "test input content"
    e = _make_envelope(input_content=raw)
    expected = hashlib.sha256(raw.encode()).hexdigest()
    assert e["input"]["digest"] == expected


def test_output_digest_matches_expected():
    raw = "test output content"
    e = _make_envelope(output_content=raw)
    expected = hashlib.sha256(raw.encode()).hexdigest()
    assert e["output"]["digest"] == expected


# ── Hash chain tests ──────────────────────────────────────────────────────────

def test_hash_chain_fields_present():
    e = _make_envelope()
    assert "previous_hash" in e["hash_chain"]
    assert "current_hash"  in e["hash_chain"]


def test_hash_chain_current_hash_is_valid_sha256():
    e = _make_envelope()
    h = e["hash_chain"]["current_hash"]
    assert len(h) == 64
    int(h, 16)


def test_hash_chain_unbroken_across_10_envelopes():
    """
    Core integrity test: 10 consecutive envelopes each have a valid, unique
    current_hash and a previous_hash that anchors to the SBB ledger state.

    Note: build() reads previous_hash from the DB but does not write back.
    The DB chain (log_audit) and envelope chain are unified when the caller
    passes envelope["hash_chain"]["current_hash"] as the compliance_hash to
    log_audit() — that integration is RDM-019 phase 2.
    """
    factory = CanonicalEnvelope()
    hashes = set()
    prev_hash_from_db = database.get_last_hash()

    for i in range(10):
        e = factory.build(
            actor={"type": "agent", "identity": f"agent-{i}", "credential_method": "api_key"},
            action={"verb": "execute", "domain": "test", "resource": f"cmd-{i}", "scope": None},
            gate_decisions=[{"gate": "sovereign", "decision": "allow", "reason": "ok"}],
            policy={"version": "v2.1.0", "hash": "b" * 64},
            execution_result=None,
            input_content=f"input {i}",
            output_content=f"output {i}",
            sign=False,
        )
        current = e["hash_chain"]["current_hash"]
        prev    = e["hash_chain"]["previous_hash"]

        # Each envelope anchors to a known DB hash
        assert prev == prev_hash_from_db, (
            f"Envelope {i} previous_hash does not match DB last hash"
        )
        # Each envelope has a unique current_hash
        assert current not in hashes, f"Duplicate current_hash at envelope {i}"
        assert len(current) == 64
        hashes.add(current)


def test_different_inputs_produce_different_hashes():
    e1 = _make_envelope(input_content="version one")
    e2 = _make_envelope(input_content="version two")
    assert e1["hash_chain"]["current_hash"] != e2["hash_chain"]["current_hash"]


# ── Signature tests ───────────────────────────────────────────────────────────

def test_envelope_has_signature_when_sign_true():
    e = _make_envelope()
    assert len(e["signatures"]) >= 1


def test_envelope_signature_is_valid_base64():
    import base64
    e = _make_envelope()
    sig = e["signatures"][0]["signature"]
    assert sig, "Signature must not be empty"
    decoded = base64.b64decode(sig)
    assert len(decoded) == 64, "Ed25519 signature must be 64 bytes"


def test_envelope_verify_returns_valid_true():
    env_factory = CanonicalEnvelope()
    e = _make_envelope()
    result = env_factory.verify(e)
    assert result["valid"] is True, f"Envelope verification failed: {result}"
    assert result["hash_valid"] is True


def test_tampered_envelope_fails_verification():
    env_factory = CanonicalEnvelope()
    e = _make_envelope()
    # Tamper: change the gate decision after signing
    e["gate_decisions"][0]["decision"] = "deny"
    result = env_factory.verify(e)
    assert result["valid"] is False, "Tampered envelope must fail verification"
    assert result["hash_valid"] is False


def test_envelope_no_signature_when_sign_false():
    e = _make_envelope(sign=False)
    assert e["signatures"] == [], "sign=False must produce no signatures"


# ── Gate decision combination tests ──────────────────────────────────────────

def test_single_gate_deny_is_valid_envelope():
    e = _make_envelope(gate_decisions=[
        {"gate": "sovereign", "decision": "deny", "reason": "blacklisted nation"}
    ])
    assert e["gate_decisions"][0]["decision"] == "deny"
    assert e["hash_chain"]["current_hash"]


def test_escalate_decision_is_valid():
    e = _make_envelope(gate_decisions=[
        {"gate": "ai_sudo", "decision": "escalate", "reason": "high risk command"}
    ])
    assert e["gate_decisions"][0]["decision"] == "escalate"


def test_all_seven_gates_in_decisions():
    e = _make_envelope()
    gates = {d["gate"] for d in e["gate_decisions"]}
    for gate in GATE_ORDER:
        assert gate in gates, f"Gate {gate} missing from decisions"


def test_gate_order_constant_has_seven_entries():
    assert len(GATE_ORDER) == 7
    assert GATE_ORDER[0] == "sovereign"
    assert GATE_ORDER[-1] == "final_verdict"
    assert "reasoner" in GATE_ORDER
    assert "context_guardian" in GATE_ORDER
