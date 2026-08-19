"""Small file-backed store for the single-user OAuth state.

The Railway deployment is intentionally single-user and runs one replica, so a
locked JSON file is sufficient. The directory should be backed by a Railway
volume in production. Without one, this still survives within a container but
will be lost when Railway replaces that container.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any


def _state_path() -> Path:
    session_dir = Path(
        os.getenv("MONARCH_MCP_SESSION_DIR", str(Path.home() / ".monarch-mcp-server"))
    )
    return session_dir / "oauth-state.json"


def load_oauth_state() -> dict[str, Any]:
    """Load OAuth clients, authorization codes, and bearer tokens."""
    path = _state_path()
    try:
        raw = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {"clients": {}, "codes": {}, "tokens": {}}
    if not isinstance(raw, dict):
        return {"clients": {}, "codes": {}, "tokens": {}}
    return {
        "clients": raw.get("clients", {}) if isinstance(raw.get("clients"), dict) else {},
        "codes": raw.get("codes", {}) if isinstance(raw.get("codes"), dict) else {},
        "tokens": raw.get("tokens", {}) if isinstance(raw.get("tokens"), dict) else {},
    }


def save_oauth_state(state: dict[str, Any]) -> None:
    """Atomically save OAuth state with owner-only permissions."""
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(stat.S_IRWXU)

    fd, temporary_name = tempfile.mkstemp(
        prefix="oauth-state.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "w") as temporary:
            json.dump(state, temporary, separators=(",", ":"))
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(temporary_name, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
