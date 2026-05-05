"""
Heimdall IDS Dashboard — Shared Password Utilities
Single source of truth for PBKDF2-SHA256 hashing and verification.

Previously the identical implementation was duplicated across
auth.py and users.py.  Both now import from here instead.
"""

import hashlib
import hmac
import secrets

from config import PBKDF2_ITERS


def hash_password(password: str) -> str:
    """
    Hash a plaintext password with a random salt.
    Returns a string of the form  'salt$hex_digest'
    suitable for storing directly in the database.
    """
    salt = secrets.token_hex(16)
    h    = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), PBKDF2_ITERS
    )
    return f"{salt}${h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """
    Verify a plaintext password against a stored 'salt$hex_digest' hash.
    Uses hmac.compare_digest to prevent timing attacks.
    Returns True on match, False on any failure.
    """
    try:
        salt, h = stored.split("$", 1)
        check   = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), PBKDF2_ITERS
        )
        return hmac.compare_digest(check.hex(), h)
    except Exception:
        return False
