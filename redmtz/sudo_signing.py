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
redmtz.sudo_signing — Ed25519 Decision Signing (Patent Claim 28)
REDMTZ Seatbelt

Auto-generates an Ed25519 keypair on first use.
Signs every governance decision. Verifiable by any auditor with the public key.

Key locations (override with env vars):
  REDMTZ_SUDO_KEY_PATH    — private key (default: ~/.redmtz/keys/sudo_signing.key)
  REDMTZ_SUDO_PUBKEY_PATH — public key  (default: ~/.redmtz/keys/sudo_signing.pub)

Founder: Robert Benitez
"""

import base64
import os
import sys
import platform
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

# Default key location: ~/.redmtz/keys/
_DEFAULT_KEY_DIR = os.path.join(os.path.expanduser("~"), ".redmtz", "keys")

PRIVATE_KEY_PATH: str = os.getenv(
    "REDMTZ_SUDO_KEY_PATH",
    os.path.join(_DEFAULT_KEY_DIR, "sudo_signing.key"),
)
PUBLIC_KEY_PATH: str = os.getenv(
    "REDMTZ_SUDO_PUBKEY_PATH",
    os.path.join(_DEFAULT_KEY_DIR, "sudo_signing.pub"),
)


def ensure_keypair() -> None:
    """
    Generate an Ed25519 keypair on first run if not already present.
    Idempotent — safe to call at every startup.
    """
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        return

    key_dir = os.path.dirname(PRIVATE_KEY_PATH)
    if key_dir:
        os.makedirs(key_dir, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    pub_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    pem_public = pub_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(pem_private)

    # Set 0600 permissions on Unix/Mac. Windows does not support chmod —
    # key security on Windows is the responsibility of the filesystem ACLs.
    if platform.system() != "Windows":
        os.chmod(PRIVATE_KEY_PATH, 0o600)

    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(pem_public)

    print(
        f"[redmtz] Ed25519 keypair generated.\n"
        f"  Private: {PRIVATE_KEY_PATH}\n"
        f"  Public:  {PUBLIC_KEY_PATH}",
        file=sys.stderr,
    )


def _load_private_key() -> Ed25519PrivateKey:
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return load_pem_private_key(f.read(), password=None)


def get_public_key_pem() -> bytes:
    """Return the public key PEM bytes for external verification."""
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return f.read()


def get_public_key_path() -> str:
    """Return the path to the public key file."""
    return PUBLIC_KEY_PATH


def sign_decision(decision_hash: str) -> str:
    """
    Sign a decision_hash with the Ed25519 private key.
    Returns base64-encoded signature. Raises RuntimeError on failure (fail-closed).
    """
    try:
        ensure_keypair()
    except Exception as e:
        raise RuntimeError(
            f"[FATAL] Keypair generation failed: {e}. Fail-closed."
        ) from e

    if not os.path.exists(PRIVATE_KEY_PATH):
        raise RuntimeError(
            f"[FATAL] Private key not found at {PRIVATE_KEY_PATH}. Fail-closed."
        )

    try:
        private_key = _load_private_key()
        raw_sig = private_key.sign(decision_hash.encode("utf-8"))
        return base64.b64encode(raw_sig).decode("ascii")
    except Exception as e:
        raise RuntimeError(f"[FATAL] Signing failed: {e}. Fail-closed.") from e


def verify_signature(
    decision_hash: str,
    signature_b64: str,
    public_key_pem: Optional[bytes] = None,
) -> bool:
    """
    Verify an Ed25519 signature against a decision_hash.

    Args:
        decision_hash:  The SHA-256 hex digest that was signed.
        signature_b64:  Base64-encoded signature from sign_decision().
        public_key_pem: Optional PEM bytes. If None, loads the system public key.

    Returns:
        True if valid. False if invalid, malformed, or key unavailable.
    """
    if not signature_b64:
        return False
    try:
        if public_key_pem is None:
            public_key_pem = get_public_key_pem()
        pub_key = load_pem_public_key(public_key_pem)
        raw_sig = base64.b64decode(signature_b64)
        pub_key.verify(raw_sig, decision_hash.encode("utf-8"))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
