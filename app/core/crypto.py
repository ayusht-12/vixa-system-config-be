"""ECDSA P-384 signing for the immutable audit log.

A real keypair is generated on first boot and persisted to disk (or loaded
from there on subsequent boots). Every audit log entry's hash is signed with
the private key; `verify_chain` re-derives each hash and checks both the
hash-chain linkage *and* the signature, so tampering with either the content
or a stored signature is independently detectable.
"""

import base64
import hashlib
from functools import lru_cache
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.core.config import settings

_CURVE = ec.SECP384R1()


def _key_path() -> Path:
    path = Path(settings.AUDIT_SIGNING_KEY_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


@lru_cache
def get_signing_key() -> ec.EllipticCurvePrivateKey:
    path = _key_path()
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)

    key = ec.generate_private_key(_CURVE)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    path.chmod(0o600)
    return key


@lru_cache
def get_signing_key_id() -> str:
    """Short, stable fingerprint of the public key — safe to log/display."""
    public_bytes = (
        get_signing_key()
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    digest = hashlib.sha256(public_bytes).hexdigest()
    return f"nexus-signing-key-v4:{digest[:8]}"


def sign_hex_digest(hex_digest: str) -> str:
    signature = get_signing_key().sign(
        bytes.fromhex(hex_digest), ec.ECDSA(hashes.SHA384())
    )
    return base64.b64encode(signature).decode("ascii")


def verify_hex_digest(hex_digest: str, signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64)
        get_signing_key().public_key().verify(
            signature, bytes.fromhex(hex_digest), ec.ECDSA(hashes.SHA384())
        )
        return True
    except Exception:
        return False
