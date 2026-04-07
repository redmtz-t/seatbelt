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
redmtz.envelope — Canonical Signed Event Envelope (RDM-019)
REDMTZ Seatbelt

Every governance decision becomes a CanonicalEnvelope:
a cryptographically signed, hash-chained, digest-only record.

No raw PII/PHI is stored. All content is SHA-256 digested before recording.

Founder: Robert Benitez
"""

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import database
from . import sudo_signing


def _uuid7() -> str:
    """Generate a UUID v7 (time-ordered) without external dependencies."""
    ts_ns   = time.time_ns()
    ts_ms   = ts_ns // 1_000_000
    sub_ms  = (ts_ns % 1_000_000) >> 8
    rand_62 = uuid.uuid4().int & ((1 << 62) - 1)
    val = (
        (ts_ms  & 0xFFFFFFFFFFFF) << 80 |
        (0x7                     << 76) |
        (sub_ms & 0xFFF)         << 64 |
        (0b10                    << 62) |
        rand_62
    )
    return str(uuid.UUID(int=val))


def _digest(content: Any) -> str:
    """SHA-256 hex digest. Accepts str, bytes, or JSON-serialisable object."""
    if isinstance(content, bytes):
        raw = content
    elif isinstance(content, str):
        raw = content.encode("utf-8")
    else:
        raw = json.dumps(content, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _envelope_hash(envelope: Dict[str, Any]) -> str:
    """SHA-256 over the canonical envelope, excluding 'signatures'."""
    hashable  = {k: v for k, v in envelope.items() if k != "signatures"}
    canonical = json.dumps(hashable, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class CanonicalEnvelope:
    """
    Builds the canonical signed event envelope for every governance decision.

    Usage:
        env = CanonicalEnvelope()
        envelope = env.build(
            actor={...}, action={...}, gate_decisions=[...],
            policy={...}, execution_result={...},
            input_content="raw input", model={...},
        )
    """

    def build(
        self,
        actor:               Dict[str, Any],
        action:              Dict[str, Any],
        gate_decisions:      List[Dict[str, Any]],
        policy:              Dict[str, Any],
        execution_result:    Optional[Dict[str, Any]],
        input_content:       Any = "",
        output_content:      Any = "",
        input_token_count:   int = 0,
        output_token_count:  int = 0,
        input_classification:  str = "unknown",
        output_classification: str = "unknown",
        model:               Optional[Dict[str, Any]] = None,
        sign:                bool = True,
        governance_mode:     str = "deterministic",
    ) -> Dict[str, Any]:
        """
        Build a canonical envelope from gate decisions.

        Returns:
            Signed envelope dict. hash_chain.current_hash is the compliance_hash.
        """
        now_utc   = datetime.now(timezone.utc).isoformat()
        prev_hash = database.get_last_hash()

        envelope: Dict[str, Any] = {
            "event_id":            _uuid7(),
            "timestamp_utc":       now_utc,
            "governance_mode":     governance_mode,
            "timestamp_monotonic": time.monotonic_ns(),
            "replay_nonce":        str(uuid.uuid4()),
            "actor":               actor,
            "action":              action,
            "input": {
                "digest":         _digest(input_content),
                "token_count":    input_token_count,
                "classification": input_classification,
            },
            "output": {
                "digest":         _digest(output_content),
                "token_count":    output_token_count,
                "classification": output_classification,
            },
            "gate_decisions":    gate_decisions,
            "policy":            policy,
            "execution_result":  execution_result,
            "model":             model or {
                "name":    "redmtz-seatbelt",
                "version": "1.0.0",
                "runtime": "symbolic",
            },
            "hash_chain": {
                "previous_hash": prev_hash,
                "current_hash":  "",
            },
            "signatures": [],
        }

        current_hash = _envelope_hash(envelope)
        envelope["hash_chain"]["current_hash"] = current_hash

        if sign:
            try:
                sudo_signing.ensure_keypair()
                sig = sudo_signing.sign_decision(current_hash)
                envelope["signatures"].append({
                    "signer":    "redmtz-seatbelt",
                    "signature": sig,
                    "order":     6,
                })
            except Exception as e:
                envelope["signatures"].append({
                    "signer":    "redmtz-seatbelt",
                    "signature": "",
                    "order":     6,
                    "error":     str(e),
                })

        return envelope

    def verify(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Verify the envelope's hash and signatures."""
        result: Dict[str, Any] = {
            "valid":            False,
            "hash_valid":       False,
            "signatures_valid": [],
            "message":          "",
        }

        stored_hash = envelope.get("hash_chain", {}).get("current_hash", "")
        probe = {k: v for k, v in envelope.items() if k != "signatures"}
        probe["hash_chain"] = dict(probe["hash_chain"])
        probe["hash_chain"]["current_hash"] = ""
        canonical     = json.dumps(probe, sort_keys=True, default=str)
        expected_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        result["hash_valid"] = (expected_hash == stored_hash)

        if not result["hash_valid"]:
            result["message"] = (
                f"Hash mismatch: expected {expected_hash[:16]}... "
                f"got {stored_hash[:16]}..."
            )
            return result

        all_sigs_valid = True
        for sig_entry in envelope.get("signatures", []):
            sig = sig_entry.get("signature", "")
            ok  = sudo_signing.verify_signature(stored_hash, sig) if sig else False
            result["signatures_valid"].append({
                "signer": sig_entry.get("signer"),
                "order":  sig_entry.get("order"),
                "valid":  ok,
            })
            if not ok:
                all_sigs_valid = False

        result["valid"]   = all_sigs_valid
        result["message"] = "VALID" if all_sigs_valid else "SIGNATURE_INVALID"
        return result
