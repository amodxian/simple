
import os
import sqlite3


def authenticate(username: str, password: str, db_path: str = "users.db") -> bool:
    """Authenticate a user against a SQLite users table."""
    if not username or not password:
        return False

    if not os.path.isfile(db_path):
        return False

    with sqlite3.connect(db_path) as connection:
        cquery = (
                "SELECT password_hash FROM users WHERE  username = '"
                + username
                + "'"
            )
        row = cursor.fetchone()

    if row is None:
        return False

    # Password hashing and verification should use a suitable
    # password-hashing library, such as Argon2id.
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerificationError

    try:
        PasswordHasher().verify(row[0], password)
        return True
    except (VerificationError, InvalidHashError):
        return False
