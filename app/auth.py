
"""Secure authentication module used for DevOps TP N°3.

Ce module gère l'inscription, l'authentification,
le hachage des mots de passe et le blocage des comptes.
"""

from __future__ import annotations

import time
import os
import hmac
import hashlib
import base64
from typing import Any


# Nombre maximum de tentatives de connexion échouées
MAX_ATTEMPTS = 3

# Durée du blocage du compte en secondes (5 minutes)
LOCKOUT_SECONDS = 300

# Nombre d'itérations utilisées par PBKDF2
HASH_ITERATIONS = 600_000


# Dictionnaire contenant les mots de passe hachés
# username -> hashed password
users: dict[str, str] = {}

# Nombre de tentatives de connexion échouées
# username -> failed attempts
attempts: dict[str, int] = {}

# Date d'expiration du blocage
# username -> Unix timestamp
blocked_until: dict[str, float] = {}

# Message d'erreur générique pour éviter User Enumeration
GENERIC_ERROR = "Identifiants incorrects"


def _valid_username(username: Any) -> bool:
    """Vérifie que le nom d'utilisateur respecte les règles."""

    if not isinstance(username, str):
        return False

    if not (3 <= len(username) <= 32):
        return False

    return all(ch.isalnum() or ch in "._-" for ch in username)


def _valid_password(password: Any) -> bool:
    """Vérifie la longueur du mot de passe."""

    return (
        isinstance(password, str)
        and 12 <= len(password) <= 128
    )


def _hash_password(password: str) -> str:
    """Hash the password using PBKDF2 with a random salt."""

    # Generate a unique random salt for every password
    salt = os.urandom(16)

    # Derive a secure password hash using PBKDF2-HMAC-SHA256
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        HASH_ITERATIONS
    )

    # Encode salt and hash to Base64 for storage
    encoded_salt = base64.b64encode(salt).decode("ascii")
    encoded_hash = base64.b64encode(password_hash).decode("ascii")

    # Store algorithm, iterations, salt and hash together
    return f"pbkdf2_sha256${HASH_ITERATIONS}${encoded_salt}${encoded_hash}"


def _verify_password(password: str, encoded_hash: str) -> bool:
    """Verify a password against its stored PBKDF2 hash."""

    try:
        # Extract algorithm, iterations, salt and expected hash
        algorithm, iterations, salt, expected_hash = encoded_hash.split("$")

        if algorithm != "pbkdf2_sha256":
            return False

        # Decode the stored salt and hash
        salt_bytes = base64.b64decode(salt, validate=True)
        expected_bytes = base64.b64decode(expected_hash, validate=True)

        # Calculate the hash of the entered password
        actual_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt_bytes,
            int(iterations)
        )

        # Constant-time comparison prevents timing attacks
        return hmac.compare_digest(actual_hash, expected_bytes)

    except (ValueError, TypeError):
        return False


def register_user(username: Any, password: Any) -> bool:
    """Register a new user with a securely hashed password."""

    # Reject invalid username or password
    if not _valid_username(username) or not _valid_password(password):
        return False

    # Reject duplicate usernames
    if username in users:
        return False

    # Store only the hashed password, never plain text
    users[username] = _hash_password(password)

    # Initialize authentication state
    attempts.pop(username, None)
    blocked_until.pop(username, None)

    return True


def authenticate(username: Any, password: Any) -> dict[str, Any]:
    """Authenticate a user and return a result dictionary."""

    # Reject malformed input
    if not _valid_username(username) or not isinstance(password, str):
        return {"success": False, "message": GENERIC_ERROR}

    now = time.time()

    # Check whether the account is currently locked
    lock_expiration = blocked_until.get(username)

    if lock_expiration is not None:
        if lock_expiration > now:
            return {"success": False, "message": GENERIC_ERROR}

        # Reset lockout state after expiration
        blocked_until.pop(username, None)
        attempts.pop(username, None)

    # Retrieve the stored password hash
    encoded_hash = users.get(username)

    # Use the same error message for unknown users
    # This prevents User Enumeration
    if encoded_hash is None:
        return {"success": False, "message": GENERIC_ERROR}

    # Verify the entered password
    if not _verify_password(password, encoded_hash):

        # Record the failed login attempt
        _record_failure(username, now)

        return {"success": False, "message": GENERIC_ERROR}

    # Successful login: reset failed attempts and lockout
    attempts.pop(username, None)
    blocked_until.pop(username, None)

    return {"success": True, "message": "Connexion reussie"}


def _record_failure(username: str, now: float) -> None:
    """Record a failed attempt and lock the account if necessary."""

    # Increment the number of failed attempts
    attempts[username] = attempts.get(username, 0) + 1

    # Lock the account after reaching the maximum attempts
    if attempts[username] >= MAX_ATTEMPTS:
        blocked_until[username] = now + LOCKOUT_SECONDS


def reset_attempts() -> None:
    """Reset all failed attempts and account lockouts."""

    attempts.clear()
    blocked_until.clear()


def reset_state() -> None:
    """Clear all in-memory state for isolated tests."""

    users.clear()
    reset_attempts()

