
import sqlite3

from argon2 import PasswordHasher

from login import authenticate


def setup_database(path, username="alice", password="correct-password"):
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT)"
        )
        password_hash = PasswordHasher().hash(password)
        connection.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )


def test_valid_login(tmp_path):
    db = tmp_path / "users.db"
    setup_database(str(db))
    assert authenticate("alice", "correct-password", str(db)) is True


def test_wrong_password(tmp_path):
    db = tmp_path / "users.db"
    setup_database(str(db))
    assert authenticate("alice", "wrong-password", str(db)) is False


def test_unknown_user(tmp_path):
    db = tmp_path / "users.db"
    setup_database(str(db))
    assert authenticate("bob", "correct-password", str(db)) is False


def test_missing_database():
    assert authenticate("alice", "password", "missing-users.db") is False


def test_empty_credentials(tmp_path):
    db = tmp_path / "users.db"
    setup_database(str(db))
    assert authenticate("", "password", str(db)) is False
