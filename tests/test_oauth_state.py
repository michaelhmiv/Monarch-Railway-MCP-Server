import json

from monarch_mcp_server import oauth_state


def test_oauth_state_round_trips_atomically(tmp_path, monkeypatch):
    monkeypatch.setenv("MONARCH_MCP_SESSION_DIR", str(tmp_path))
    state = {
        "clients": {"client-1": ["https://chatgpt.com/connector/oauth/test"]},
        "codes": {"code-1": {"expires_at": 123.0}},
        "tokens": {"token-1": 456.0},
    }

    oauth_state.save_oauth_state(state)

    assert oauth_state.load_oauth_state() == state
    assert json.loads((tmp_path / "oauth-state.json").read_text()) == state
    assert oct((tmp_path / "oauth-state.json").stat().st_mode & 0o777) == "0o600"
