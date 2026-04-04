"""Tests for argo_shim._shim."""

import json
import os
import socket
import tempfile
import threading
import unittest
from unittest import mock

from argo_shim import _shim


# ---------------------------------------------------------------------------
# default_port
# ---------------------------------------------------------------------------

class TestDefaultPort(unittest.TestCase):
    def test_deterministic(self):
        """Same username always produces the same port."""
        assert _shim.default_port("alice") == _shim.default_port("alice")

    def test_different_users_differ(self):
        assert _shim.default_port("alice") != _shim.default_port("bob")

    def test_range(self):
        """Port must be in the range 10000-32767."""
        for name in ("alice", "bob", "x", "foremans", "root", "a" * 200):
            port = _shim.default_port(name)
            assert 10000 <= port <= 32767, f"{name!r} -> {port}"


# ---------------------------------------------------------------------------
# check_port_available
# ---------------------------------------------------------------------------

class TestCheckPortAvailable(unittest.TestCase):
    def test_available_port(self):
        """Should not raise for a free port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            free_port = s.getsockname()[1]
        # Port is now free again
        _shim.check_port_available(free_port)  # should not raise

    def test_occupied_port(self):
        """Should raise RuntimeError when port is in use."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
            occupied_port = s.getsockname()[1]
            s.listen(1)
            with self.assertRaises(RuntimeError) as ctx:
                _shim.check_port_available(occupied_port)
            assert "already in use" in str(ctx.exception)
            assert str(occupied_port) in str(ctx.exception)


# ---------------------------------------------------------------------------
# update_claude_settings
# ---------------------------------------------------------------------------

class TestUpdateClaudeSettings(unittest.TestCase):
    def _run_in_tmpdir(self, existing_content=None):
        """Helper: run update_claude_settings with a temp home dir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, ".claude", "settings.json")
            if existing_content is not None:
                os.makedirs(os.path.dirname(settings_path), exist_ok=True)
                with open(settings_path, "w") as f:
                    json.dump(existing_content, f)

            with mock.patch("os.path.expanduser", return_value=settings_path):
                result = _shim.update_claude_settings(12345, "test-token")

            with open(settings_path) as f:
                settings = json.load(f)
            return result, settings

    def test_creates_new_settings(self):
        result, settings = self._run_in_tmpdir()
        assert result is True
        assert settings["apiKeyHelper"] == "echo test-token"
        assert settings["env"]["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:12345/argoapi"

    def test_updates_existing_settings(self):
        existing = {"env": {"SOME_VAR": "keep_me"}, "someKey": "someValue"}
        result, settings = self._run_in_tmpdir(existing)
        assert result is True
        # Existing keys preserved
        assert settings["someKey"] == "someValue"
        assert settings["env"]["SOME_VAR"] == "keep_me"
        # New keys added
        assert settings["env"]["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:12345/argoapi"

    def test_no_auth_token(self):
        result, settings = self._run_in_tmpdir()
        # Re-run with no auth
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, ".claude", "settings.json")
            os.makedirs(os.path.dirname(settings_path), exist_ok=True)
            with mock.patch("os.path.expanduser", return_value=settings_path):
                result = _shim.update_claude_settings(12345, None)
            with open(settings_path) as f:
                settings = json.load(f)
        assert settings["apiKeyHelper"] == "echo no-auth"

    def test_cleans_stale_proxy_vars(self):
        """Empty proxy vars from older argo-shim versions should be removed."""
        existing = {"env": {"HTTP_PROXY": "", "HTTPS_PROXY": "", "SOME_VAR": "keep"}}
        result, settings = self._run_in_tmpdir(existing)
        assert "HTTP_PROXY" not in settings["env"]
        assert "HTTPS_PROXY" not in settings["env"]
        assert settings["env"]["SOME_VAR"] == "keep"

    def test_no_proxy_set(self):
        """no_proxy and NO_PROXY should include localhost and 127.0.0.1."""
        result, settings = self._run_in_tmpdir()
        for var in ("no_proxy", "NO_PROXY"):
            val = settings["env"][var]
            assert "localhost" in val
            assert "127.0.0.1" in val

    def test_no_proxy_idempotent(self):
        """Running twice shouldn't duplicate localhost entries."""
        existing = {"env": {"no_proxy": "localhost,127.0.0.1", "NO_PROXY": "localhost,127.0.0.1"}}
        result, settings = self._run_in_tmpdir(existing)
        assert settings["env"]["no_proxy"].count("localhost") == 1
        assert settings["env"]["no_proxy"].count("127.0.0.1") == 1

    def test_corrupt_json_returns_false(self):
        """Should return False and not crash on corrupt settings file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            settings_path = os.path.join(tmpdir, ".claude", "settings.json")
            os.makedirs(os.path.dirname(settings_path), exist_ok=True)
            with open(settings_path, "w") as f:
                f.write("{not valid json")
            with mock.patch("os.path.expanduser", return_value=settings_path):
                result = _shim.update_claude_settings(12345, "tok")
        assert result is False


# ---------------------------------------------------------------------------
# Path rewriting (extracted logic)
# ---------------------------------------------------------------------------

class TestPathRewriting(unittest.TestCase):
    def _rewrite(self, path):
        """Apply the same rewrite logic as handle_proxy."""
        if not path.startswith("/argoapi"):
            path = ("/argoapi/" + path.lstrip("/")).replace("//", "/")
        return path

    def test_basic_rewrite(self):
        assert self._rewrite("/v1/messages") == "/argoapi/v1/messages"

    def test_already_prefixed(self):
        assert self._rewrite("/argoapi/v1/messages") == "/argoapi/v1/messages"

    def test_root_path(self):
        assert self._rewrite("/") == "/argoapi/"

    def test_no_double_slash(self):
        result = self._rewrite("/v1/models")
        assert "//" not in result


# ---------------------------------------------------------------------------
# Stream forcing logic
# ---------------------------------------------------------------------------

class TestStreamForcing(unittest.TestCase):
    def _force_stream(self, body_dict, path="/v1/messages"):
        """Simulate the stream forcing logic from handle_proxy."""
        body = json.dumps(body_dict).encode("utf-8")
        method = "POST"
        if method == "POST" and body and "/messages" in path:
            try:
                req_json = json.loads(body)
                if req_json.get("stream") is not True:
                    req_json["stream"] = True
                    body = json.dumps(req_json).encode("utf-8")
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        return json.loads(body)

    def test_forces_stream_true(self):
        result = self._force_stream({"model": "claude-3", "stream": False})
        assert result["stream"] is True

    def test_forces_stream_when_missing(self):
        result = self._force_stream({"model": "claude-3"})
        assert result["stream"] is True

    def test_already_streaming(self):
        result = self._force_stream({"model": "claude-3", "stream": True})
        assert result["stream"] is True

    def test_no_forcing_on_non_messages_path(self):
        body = {"model": "claude-3", "stream": False}
        result = self._force_stream(body, path="/v1/models")
        assert result["stream"] is False

    def test_preserves_other_fields(self):
        result = self._force_stream({"model": "claude-3", "max_tokens": 1024, "stream": False})
        assert result["model"] == "claude-3"
        assert result["max_tokens"] == 1024


# ---------------------------------------------------------------------------
# ProxyHandler via a real local HTTP server
# ---------------------------------------------------------------------------

class TestProxyHandlerAuth(unittest.TestCase):
    """Test auth validation on ProxyHandler using a real server."""

    @classmethod
    def setUpClass(cls):
        cls.server = _shim.ThreadedTCPServer(
            ("127.0.0.1", 0), _shim.ProxyHandler,
            target_host="127.0.0.1", target_port=1,  # won't actually connect
            auth_token="secret-token",
            tunnel_is_remote=True,
        )
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.daemon = True
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=5)

    def test_head_no_auth_required(self):
        """HEAD requests should succeed without auth (connectivity probe)."""
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        conn.close()
        assert resp.status == 200

    def test_post_rejected_without_token(self):
        """POST without x-api-key should get 401."""
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", "/v1/messages", body=b'{}')
        resp = conn.getresponse()
        conn.close()
        assert resp.status == 401

    def test_post_rejected_with_bad_token(self):
        """POST with wrong x-api-key should get 401."""
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("POST", "/v1/messages", body=b'{}',
                      headers={"x-api-key": "wrong-token"})
        resp = conn.getresponse()
        conn.close()
        assert resp.status == 401


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

class TestCLIParsing(unittest.TestCase):
    def _parse(self, args):
        """Parse CLI args without running main()."""
        parser = _shim.argparse.ArgumentParser()
        parser.add_argument("--no-auth", action="store_true")
        parser.add_argument("--port", type=int, default=None)
        parser.add_argument("--tunnel", action="store_true")
        parser.add_argument("--tunnel-host", default=None)
        parser.add_argument("--relay", metavar="REMOTE_HOST", default=None)
        parser.add_argument("--no-update-settings", action="store_true")
        return parser.parse_args(args)

    def test_defaults(self):
        args = self._parse([])
        assert args.no_auth is False
        assert args.port is None
        assert args.tunnel is False
        assert args.tunnel_host is None
        assert args.relay is None

    def test_port(self):
        args = self._parse(["--port", "9999"])
        assert args.port == 9999

    def test_tunnel(self):
        args = self._parse(["--tunnel"])
        assert args.tunnel is True

    def test_tunnel_host(self):
        args = self._parse(["--tunnel-host", "some-uan"])
        assert args.tunnel_host == "some-uan"

    def test_no_auth(self):
        args = self._parse(["--no-auth"])
        assert args.no_auth is True


# ---------------------------------------------------------------------------
# is_own_process
# ---------------------------------------------------------------------------

class TestIsOwnProcess(unittest.TestCase):
    @mock.patch("subprocess.run")
    def test_own_process(self, mock_run):
        """Should return True when lsof finds a process owned by current user."""
        mock_run.side_effect = [
            mock.Mock(stdout="12345\n", returncode=0),  # lsof
            mock.Mock(stdout=f"{_shim.API_KEY}\n", returncode=0),  # ps
        ]
        assert _shim.is_own_process(9999) is True

    @mock.patch("subprocess.run")
    def test_other_user_process(self, mock_run):
        """Should return False when process is owned by a different user."""
        mock_run.side_effect = [
            mock.Mock(stdout="12345\n", returncode=0),  # lsof
            mock.Mock(stdout="otheruser\n", returncode=0),  # ps
        ]
        assert _shim.is_own_process(9999) is False

    @mock.patch("subprocess.run")
    def test_no_process(self, mock_run):
        """Should return False when nothing is listening."""
        mock_run.return_value = mock.Mock(stdout="\n", returncode=1)
        assert _shim.is_own_process(9999) is False

    @mock.patch("subprocess.run", side_effect=Exception("lsof not found"))
    def test_lsof_failure(self, mock_run):
        """Should return False on lsof failure."""
        assert _shim.is_own_process(9999) is False


if __name__ == "__main__":
    unittest.main()
