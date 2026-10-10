
import os
import sqlite3
import subprocess
from pathlib import Path

from flask import Flask, Response, request

app = Flask(__name__)

DB_PATH = "demo.db"
UPLOAD_DIR = Path("demo_files")


def init_db():
    """Create a small database containing fake lab data."""
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS users "
            "(username TEXT, role TEXT)"
        )
        connection.execute(
            "INSERT INTO users (username, role) "
            "SELECT 'alice', 'student' "
            "WHERE NOT EXISTS "
            "(SELECT 1 FROM users WHERE username = 'alice')"
        )


# VULNERABILITY 1: SQL injection
@app.route("/user")
def get_user():
    username = request.args.get("username", "")

    # UNSAFE: user input is concatenated directly into SQL.
    query = (
        "SELECT username, role FROM users "
        + "WHERE username = '"
        + username
        + "'"
    )

    with sqlite3.connect(DB_PATH) as connection:
        rows = connection.execute(query).fetchall()

    return {"results": rows}


# VULNERABILITY 2: Command injection
@app.route("/hello")
def hello():
    name = request.args.get("name", "student")

    # UNSAFE: untrusted input is passed to a shell.
    result = subprocess.run(
        f"echo Hello {name}",
        shell=True,
        capture_output=True,
        text=True,
    )

    return {"message": result.stdout}


# VULNERABILITY 3: Path traversal
@app.route("/file")
def read_file():
    filename = request.args.get("name", "welcome.txt")

    # UNSAFE: the requested path is not confined to UPLOAD_DIR.
    path = os.path.join(str(UPLOAD_DIR), filename)

    with open(path, encoding="utf-8") as file:
        return {"content": file.read()}


# VULNERABILITY 4: Reflected cross-site scripting (XSS)
@app.route("/greet")
def greet():
    name = request.args.get("name", "student")

    # UNSAFE: user-controlled text is inserted into HTML without escaping.
    return Response(
        f"<h1>Hello, {name}!</h1>",
        mimetype="text/html",
    )


if __name__ == "__main__":
    init_db()
    UPLOAD_DIR.mkdir(exist_ok=True)
    (UPLOAD_DIR / "welcome.txt").write_text(
        "This is a fake lab file.",
        encoding="utf-8",
    )

    # Local machine only; debug mode is disabled.
    app.run(host="127.0.0.1", port=5000, debug=False)
