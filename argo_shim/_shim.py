import argparse
import getpass
import hashlib
import http.server
import http.client
import json
import os
import secrets
import signal
import socket
import socketserver
import ssl
import subprocess
import threading
import time

TARGET_HOST = "127.0.0.1"
REAL_HOST = "apps.inside.anl.gov"
API_KEY = os.environ.get("CELS_USERNAME", getpass.getuser())
OPENCODE_CONFIG = os.path.expanduser("~/.config/opencode/opencode.json")


def default_port(username):
    """Derive a deterministic listen port from the username."""
    h = hashlib.sha256(username.encode()).hexdigest()
    return 10000 + (int(h[:8], 16) % 22768)  # range 10000-32767 (below ephemeral range)

SSH_JUMP_HOST = "homes.cels.anl.gov"
SSH_PROXY_JUMP = "logins.cels.anl.gov"

MAX_SSH_FAILURES = 3


class SSHAuthError(RuntimeError):
    """Raised when an SSH command fails due to a likely authentication error."""
    pass


class SSHAttemptTracker:
    """Track consecutive SSH failures to avoid triggering CSPO IP blocks.

    CSPO monitors failed SSH auth attempts to CELS hosts and will block the
    source IP after too many failures. This tracker stops retrying after
    MAX_SSH_FAILURES consecutive failures so a single user with broken auth
    (e.g., closed laptop killing agent forwarding) can't get an entire ALCF
    login node blocked.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._consecutive_failures = 0
        self._blocked = False

    def record_success(self):
        with self._lock:
            self._consecutive_failures = 0
            self._blocked = False

    def record_failure(self):
        with self._lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= MAX_SSH_FAILURES:
                self._blocked = True
                print(f"\n⚠ SSH has failed {self._consecutive_failures} consecutive "
                      f"times. Disabling further SSH attempts to prevent IP blocks.")
                print(f"  Fix your SSH authentication (ssh-add, reconnect agent "
                      f"forwarding, etc.) and restart argo-shim.\n")
            else:
                remaining = MAX_SSH_FAILURES - self._consecutive_failures
                print(f"  SSH failure {self._consecutive_failures}/{MAX_SSH_FAILURES} "
                      f"({remaining} attempt(s) remaining before lockout)")

    def is_blocked(self):
        with self._lock:
            return self._blocked

    def check_allowed(self):
        """Raise SSHAuthError if further SSH attempts are blocked."""
        if self.is_blocked():
            raise SSHAuthError(
                f"SSH retry limit reached ({MAX_SSH_FAILURES} consecutive failures). "
                f"Fix SSH authentication and restart argo-shim."
            )


_ssh_tracker = SSHAttemptTracker()


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        self.handle_proxy("GET")

    def do_HEAD(self):
        # Claude Code sends HEAD to the base URL as a connectivity probe.
        # Reply directly instead of proxying to avoid a 404 from upstream.
        self.send_response(200)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_POST(self):
        self.handle_proxy("POST")

    def _send_error(self, code, message):
        """Send an HTTP error response to the client."""
        try:
            body = message.encode()
            self.send_response(code)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _reassemble_sse_to_message(self, response):
        """Read a streaming SSE response and reassemble into a single message JSON.

        Used when the shim forced stream=true on a request that was originally
        non-streaming.  The client expects a single JSON object, not SSE events.
        """
        message = None
        content_blocks = {}
        input_json_parts = {}  # idx -> accumulated partial_json strings for tool_use blocks
        final_usage = {}

        buf = b""
        while True:
            chunk = response.read(4096)
            if not chunk:
                break
            buf += chunk

        text = buf.decode("utf-8", errors="replace")
        for line in text.split("\n"):
            line = line.strip()
            if not line.startswith("data: "):
                continue
            data_str = line[6:]
            if data_str == "[DONE]":
                break
            try:
                event = json.loads(data_str)
            except json.JSONDecodeError:
                continue

            etype = event.get("type")
            if etype == "message_start":
                message = event.get("message", {})
            elif etype == "content_block_start":
                idx = event.get("index", 0)
                content_blocks[idx] = event.get("content_block", {})
            elif etype == "content_block_delta":
                idx = event.get("index", 0)
                delta = event.get("delta", {})
                if idx in content_blocks:
                    if delta.get("type") == "text_delta":
                        content_blocks[idx]["text"] = (
                            content_blocks[idx].get("text", "") + delta.get("text", "")
                        )
                    elif delta.get("type") == "input_json_delta":
                        input_json_parts.setdefault(idx, [])
                        input_json_parts[idx].append(delta.get("partial_json", ""))
            elif etype == "message_delta":
                delta = event.get("delta", {})
                if message:
                    for k in ("stop_reason", "stop_sequence"):
                        if k in delta:
                            message[k] = delta[k]
                usage = event.get("usage", {})
                if usage:
                    final_usage.update(usage)
            elif etype == "error":
                return event  # SSE error event — return to caller for proper HTTP status

        for idx, parts in input_json_parts.items():
            if idx in content_blocks:
                try:
                    content_blocks[idx]["input"] = json.loads("".join(parts))
                except json.JSONDecodeError:
                    content_blocks[idx]["input"] = {}

        if message is None:
            print(f"  SSE reassembly: no message_start found in {len(text)} bytes")
            if text:
                print(f"  SSE raw (first 500 chars): {text[:500]}")
            return None

        if content_blocks:
            message["content"] = [content_blocks[i] for i in sorted(content_blocks)]

        msg_usage = message.get("usage", {})
        msg_usage.update(final_usage)
        # Argo's Vertex AI backend may omit input_tokens from SSE events.
        # Claude Code's model validation checks usage.input_tokens explicitly,
        # so ensure it's always present.
        msg_usage.setdefault("input_tokens", 0)
        msg_usage.setdefault("output_tokens", 0)
        message["usage"] = msg_usage
        print(f"  SSE reassembly: usage={msg_usage}")

        return message

    def handle_proxy(self, method):
        # Validate auth token (HEAD is exempt — used by Claude Code as a connectivity probe)
        if self.server.auth_token:
            client_key = self.headers.get('x-api-key', '')
            if method != "HEAD" and client_key != self.server.auth_token:
                self.send_response(401)
                self.send_header('Content-Type', 'text/plain')
                msg = b'Unauthorized: invalid or missing x-api-key'
                self.send_header('Content-Length', str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)
                print(f"[{method}] Rejected request (bad token)")
                return

        body = None
        if method == "POST":
            try:
                content_length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(content_length)
            except ConnectionResetError:
                print("Client closed connection before sending body.")
                return

        print(f"[{method}] Intercepted Request: {self.path}")

        # Force stream=true on /messages requests to avoid Vertex AI 500 errors.
        # Vertex rejects non-streaming requests it estimates will exceed 10 minutes.
        # When we force streaming, we reassemble the SSE response back into a
        # single JSON object so the client gets the format it originally expected.
        forced_stream = False
        if method == "POST" and body and "/messages" in self.path and "/messages/" not in self.path:
            try:
                req_json = json.loads(body)
                stream_val = req_json.get("stream", "<not set>")
                model_val = req_json.get("model", "<not set>")

                # Vertex AI rejects thinking blocks with empty content. This happens
                # when Argo redacts/strips thinking from cached turns but keeps the
                # block structure. Remove them before forwarding.
                body_modified = False
                for msg in req_json.get("messages", []):
                    content = msg.get("content")
                    if isinstance(content, list):
                        cleaned = [b for b in content
                                   if not (b.get("type") == "thinking" and not b.get("thinking"))]
                        if len(cleaned) != len(content):
                            msg["content"] = cleaned
                            body_modified = True
                if body_modified:
                    print(f"[{method}] Stripped empty thinking blocks from request history")

                if req_json.get("stream") is not True:
                    forced_stream = True
                    print(f"[{method}] /messages: stream={stream_val} -> forcing stream=true (model={model_val})")
                    req_json["stream"] = True
                    body = json.dumps(req_json).encode("utf-8")
                else:
                    print(f"[{method}] /messages: stream={stream_val}, model={model_val}")
                    if body_modified:
                        body = json.dumps(req_json).encode("utf-8")
            except (json.JSONDecodeError, UnicodeDecodeError):
                print(f"[{method}] /messages: could not parse body, forwarding as-is")

        # Path rewrite logic
        path = self.path
        if not path.startswith("/argoapi"):
            path = ("/argoapi/" + path.lstrip("/")).replace("//", "/")

        context = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(self.server.target_host, self.server.target_port, context=context, timeout=300)

        # Build headers. Strip case variants of headers we set ourselves —
        # Python dicts are case-sensitive, so a client sending "X-Api-Key"
        # would otherwise leak its own token alongside our injected one.
        _strip = {'host', 'content-length', 'authorization', 'accept-encoding', 'x-api-key', 'connection'}
        headers = {k: v for k, v in self.headers.items() if k.lower() not in _strip}
        headers['Host'] = REAL_HOST
        headers['x-api-key'] = API_KEY
        headers['Connection'] = 'close'

        for attempt in range(2):
            try:
                conn.request(method, path, body=body, headers=headers)
                response = conn.getresponse()
                break
            except ConnectionRefusedError:
                conn.close()
                if attempt == 0 and self.server.recover_tunnel():
                    print(f"[{method}] Retrying after tunnel recovery...")
                    conn = http.client.HTTPSConnection(self.server.target_host, self.server.target_port, context=context, timeout=300)
                    continue
                if _ssh_tracker.is_blocked():
                    print(f"[{method}] SSH retry limit reached — not attempting recovery")
                    self._send_error(503, "SSH tunnel recovery disabled after repeated auth failures. "
                                          "Fix SSH authentication and restart argo-shim.")
                else:
                    print(f"[{method}] Upstream connection refused (tunnel is down)")
                    self._send_error(502, "Bad Gateway: SSH tunnel is down. Restart argo-shim.")
                return
            except Exception as e:
                conn.close()
                print(f"[{method}] Upstream error: {e}")
                self._send_error(502, f"Bad Gateway: {e}")
                return

        try:
            # For forced-stream requests, reassemble the SSE body BEFORE sending
            # any response headers so we can set the correct HTTP status code.
            # Upstream may return HTTP 200 with an SSE error event (e.g. 429
            # quota exceeded), which requires a non-200 status to the client.
            if forced_stream and response.status == 200:
                message = self._reassemble_sse_to_message(response)
                if message and message.get("type") != "error":
                    response_body = json.dumps(message).encode("utf-8")
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(response_body)))
                    self.end_headers()
                    self.wfile.write(response_body)
                    print(f"[{method}] Reassembled streaming response into non-streaming JSON")
                else:
                    if message:  # SSE error event
                        error_body = json.dumps(message).encode("utf-8")
                        err_type = message.get("error", {}).get("type", "")
                        err_msg = message.get("error", {}).get("message", "")
                        if "429" in err_msg or "RESOURCE_EXHAUSTED" in err_msg or "Quota exceeded" in err_msg:
                            http_status = 429
                        elif err_type == "overloaded_error" or "overloaded_error" in err_msg:
                            http_status = 529
                        elif err_type == "invalid_request_error" or "invalid_request_error" in err_msg or "Error code: 400" in err_msg:
                            http_status = 400
                        elif "401" in err_msg or "403" in err_msg or "unauthorized" in err_msg.lower():
                            http_status = 401
                        else:
                            http_status = 503
                        print(f"[{method}] SSE error (HTTP {http_status}): {err_msg[:200]}")
                    else:
                        error_body = json.dumps({"type": "error", "error": {"type": "api_error",
                            "message": "Shim failed to reassemble streaming response"}}).encode()
                        http_status = 502
                        print(f"[{method}] SSE reassembly failed, could not parse upstream response")
                    self.send_response(http_status)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(error_body)))
                    self.end_headers()
                    self.wfile.write(error_body)
                conn.close()
                return

            self.send_response(response.status)
            if response.status >= 400:
                error_body = response.read()
                print(f"[{method}] Upstream {response.status}: {error_body[:500]}")
                for k, v in response.getheaders():
                    if k.lower() not in ('transfer-encoding',):
                        self.send_header(k, v)
                self.send_header('Content-Length', str(len(error_body)))
                self.end_headers()
                self.wfile.write(error_body)
                return

            for k, v in response.getheaders():
                if k.lower() != 'transfer-encoding':
                    self.send_header(k, v)
            self.end_headers()

            # Streaming response (Critical for Claude's SSE)
            while True:
                chunk = response.read(4096)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()

        except (BrokenPipeError, ConnectionResetError):
            print(f"[{method}] Client disconnected during streaming")
        except Exception as e:
            print(f"[{method}] Error during response: {e}")
        finally:
            conn.close()

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        import sys
        # ConnectionResetError before the request line is read is benign:
        # Claude Code's HTTP/1.1 connection pool opens connections speculatively
        # and resets them without sending a request. Suppress the traceback.
        if sys.exc_info()[0] is ConnectionResetError:
            return
        super().handle_error(request, client_address)

    def __init__(self, server_address, handler, target_host, target_port, auth_token, tunnel_is_remote=False):
        self.target_host = target_host
        self.target_port = target_port
        self.auth_token = auth_token
        self.tunnel_is_remote = tunnel_is_remote
        self._tunnel_lock = threading.Lock()
        super().__init__(server_address, handler)

    def recover_tunnel(self):
        """Attempt to recreate the SSH tunnel. Returns True if recovery succeeded."""
        if self.tunnel_is_remote:
            # Remote tunnel (--tunnel-host): can't recreate from here
            print("Tunnel is remote — cannot recover locally. Check the relay or UAN.")
            return False
        with self._tunnel_lock:
            # Re-check under lock — another thread may have already recovered
            if find_existing_tunnel(self.target_port):
                return True
            print("Tunnel is dead, attempting recovery...")
            try:
                create_tunnel(self.target_port)
                print("Tunnel recovered successfully")
                return True
            except SSHAuthError as e:
                print(f"Tunnel recovery failed: {e}")
                return False
            except Exception as e:
                print(f"Tunnel recovery failed: {e}")
                return False


def _port_in_use_info(port):
    """Return a short description of what's using a port, or None."""
    try:
        result = subprocess.run(
            ["lsof", "-ti", f"TCP:{port}", "-sTCP:LISTEN"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5
        )
        for pid in result.stdout.strip().split('\n'):
            if not pid:
                continue
            ps = subprocess.run(
                ["ps", "-o", "pid=,user=,comm=", "-p", pid],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5
            )
            return ps.stdout.strip()
    except Exception:
        pass
    return None


def check_port_available(port, host="127.0.0.1"):
    """Check that a port is available, or raise with a helpful message."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
        except OSError:
            info = _port_in_use_info(port)
            detail = f"\n  In use by: {info}" if info else \
                     f"\n  Try: lsof -iTCP:{port} -sTCP:LISTEN"
            raise RuntimeError(
                f"Port {port} on {host} is already in use.{detail}\n"
                f"  Use --port <PORT> to specify a different port."
            )


def _kill_stale_tunnel(port, bind_address="127.0.0.1"):
    """Kill a stale SSH tunnel process on the given port. Returns True if port is freed."""
    try:
        result = subprocess.run(
            ["lsof", "-ti", f"TCP:{port}", "-sTCP:LISTEN"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5
        )
        for pid in result.stdout.strip().split('\n'):
            if not pid:
                continue
            # Verify it's OUR argo-shim tunnel before killing:
            # must be owned by us, be an ssh process, and have the expected -L forward
            ps = subprocess.run(
                ["ps", "-o", "user=,comm=,args=", "-p", pid],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5
            )
            output = ps.stdout.strip()
            fields = output.split(None, 2)  # user, comm, args
            if len(fields) >= 3 and fields[0] == API_KEY and "ssh" in fields[1] \
                    and f"{REAL_HOST}:443" in fields[2]:
                print(f"  Killing stale SSH tunnel (PID {pid})...")
                os.kill(int(pid), signal.SIGTERM)
                time.sleep(1)
                # Verify it's gone
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    try:
                        s.bind((bind_address, port))
                        print(f"  ✓ Stale tunnel on port {port} cleaned up")
                        return True
                    except OSError:
                        print(f"  ✗ Port {port} still in use after killing PID {pid}")
                        return False
    except Exception as e:
        print(f"  Could not clean up port {port}: {e}")
    return False


def verify_tunnel(port, host="127.0.0.1"):
    """Verify that a listening port is actually a tunnel to REAL_HOST by doing a TLS handshake
    and checking the server certificate."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                             server_hostname=REAL_HOST) as s:
            s.settimeout(5)
            s.connect((host, port))
            cert = s.getpeercert()
            # Check that the cert is valid for REAL_HOST (wrap_socket already does this
            # via server_hostname matching, so reaching here means it passed)
            print(f"  ✓ TLS verified: tunnel on {port} reaches {REAL_HOST}")
            return True
    except ssl.SSLError as e:
        # SSLCertVerificationError is a subclass of SSLError added in 3.7;
        # on 3.6 we distinguish by checking the verify_code attribute.
        if getattr(e, 'verify_code', None) or 'CERTIFICATE_VERIFY_FAILED' in str(e):
            print(f"  ✗ Port {port}: TLS cert does not match {REAL_HOST}: {e}")
        else:
            print(f"  ✗ Port {port}: TLS handshake failed (not a tunnel to a TLS server): {e}")
        return False
    except (ConnectionRefusedError, OSError) as e:
        print(f"  ✗ Port {port}: connection failed: {e}")
        return False


def is_own_process(port):
    """Check if the process listening on a port belongs to the current user."""
    try:
        # Use TCP:{port} without address filter — lsof represents 0.0.0.0 as *
        # so TCP@127.0.0.1 and TCP@0.0.0.0 both fail to match wildcard binds.
        result = subprocess.run(
            ["lsof", "-ti", f"TCP:{port}", "-sTCP:LISTEN"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5
        )
        for pid in result.stdout.strip().split('\n'):
            if not pid:
                continue
            stat = subprocess.run(
                ["ps", "-o", "user=", "-p", pid],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=5
            )
            owner = stat.stdout.strip()
            if owner == API_KEY:
                return True
            print(f"  Skipping port {port} (owned by {owner}, not {API_KEY})")
            return False
    except Exception:
        pass
    return False


def find_existing_tunnel(port, host="127.0.0.1"):
    """Check if a verified tunnel to REAL_HOST already exists on this port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((host, port))
        except (ConnectionRefusedError, OSError):
            return False
    if not is_own_process(port):
        return False
    print(f"Port {port} is listening, verifying tunnel...")
    if verify_tunnel(port, host):
        return True
    # Port is ours but TLS failed — stale tunnel. Try to clean it up
    # so create_tunnel can bind to this port.
    print(f"  Port {port} is not a valid tunnel to {REAL_HOST}")
    _kill_stale_tunnel(port, host)
    return False


def create_tunnel(port, host="127.0.0.1", bind_address="127.0.0.1"):
    """Create a new SSH tunnel on the given port and verify it's working."""
    _ssh_tracker.check_allowed()
    check_port_available(port, bind_address)
    cmd = [
        "ssh", "-N", "-f",
        "-o", "BatchMode=yes",
        "-o", "ConnectionAttempts=1",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=4",
        "-o", "ControlMaster=auto",
        "-o", f"ControlPath=~/.ssh/argo-shim-%C",
        "-o", "ControlPersist=yes",
    ]
    if SSH_PROXY_JUMP:
        cmd.extend(["-J", f"{API_KEY}@{SSH_PROXY_JUMP}"])
    cmd.extend([
        "-L", f"{bind_address}:{port}:{REAL_HOST}:443",
        f"{API_KEY}@{SSH_JUMP_HOST}",
    ])
    print(f"Creating SSH tunnel on port {port}...")
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        _ssh_tracker.record_failure()
        raise SSHAuthError(f"SSH tunnel failed (exit code {result.returncode})")

    # Wait for tunnel to start accepting connections
    for i in range(10):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect((host, port))
                break
            except (ConnectionRefusedError, OSError):
                time.sleep(0.5)
    else:
        raise RuntimeError(f"SSH tunnel on port {port} never started accepting connections")

    print(f"Verifying new tunnel...")
    if not verify_tunnel(port, host):
        raise RuntimeError(f"SSH tunnel on port {port} did not verify against {REAL_HOST}")

    _ssh_tracker.record_success()
    return port


def create_reverse_tunnel(remote_host, port):
    """Create a reverse SSH tunnel, forwarding remote_host:port to localhost:port."""
    _ssh_tracker.check_allowed()
    cmd = ["ssh", "-N", "-f",
           "-o", "BatchMode=yes", "-o", "ConnectionAttempts=1",
           "-R", f"0.0.0.0:{port}:127.0.0.1:{port}", remote_host]
    print(f"Creating reverse tunnel to {remote_host}:{port}...")
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        _ssh_tracker.record_failure()
        raise SSHAuthError(f"Reverse SSH tunnel to {remote_host} failed (exit code {result.returncode})")


def read_existing_token():
    """Read the auth token currently stored in settings.json, if any."""
    settings_path = os.path.expanduser("~/.claude/settings.json")
    try:
        with open(settings_path) as f:
            settings = json.load(f)
        helper = settings.get("apiKeyHelper", "")
        if helper.startswith("echo ") and helper[5:] not in ("no-auth", ""):
            return helper[5:]
    except Exception:
        pass
    return None


def update_claude_settings(listen_port, auth_token):
    """Update ~/.claude/settings.json with the correct ANTHROPIC_BASE_URL and auth token."""
    settings_path = os.path.expanduser("~/.claude/settings.json")
    os.makedirs(os.path.dirname(settings_path), exist_ok=True)
    try:
        with open(settings_path, "r") as f:
            settings = json.load(f)
    except FileNotFoundError:
        settings = {
            "env": {
                "CLAUDE_CODE_SKIP_ANTHROPIC_AUTH": "1"
            }
        }
        print(f"  Creating new {settings_path}")
    except json.JSONDecodeError as e:
        print(f"  ⚠ Could not parse {settings_path}: {e}")
        return False

    new_url = f"http://127.0.0.1:{listen_port}/argoapi"
    if auth_token:
        settings["apiKeyHelper"] = f"echo {auth_token}"
    else:
        settings["apiKeyHelper"] = "echo no-auth"
    env = settings.setdefault("env", {})
    env["ANTHROPIC_BASE_URL"] = new_url
    # Bypass proxy for localhost (argo-shim) while preserving proxy for
    # internet access (web fetches, package installs, etc.)
    # Clean up stale empty proxy vars from older versions of argo-shim
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        if var in env and env[var] == "":
            del env[var]
    for var in ("no_proxy", "NO_PROXY"):
        existing = env.get(var, "")
        hosts = [h.strip() for h in existing.split(",") if h.strip()] if existing else []
        for h in ("localhost", "127.0.0.1"):
            if h not in hosts:
                hosts.append(h)
        env[var] = ",".join(hosts)

    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")
    auth_status = "auth token set" if auth_token else "no auth"
    print(f"  ✓ Updated settings.json (port={listen_port}, {auth_status})")
    return True


def update_opencode_settings(tunnel_port, tunnel_host="127.0.0.1"):
    """Update ~/.config/opencode/opencode.json to point the argo provider at the SSH tunnel."""
    try:
        with open(OPENCODE_CONFIG) as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"  ✗ opencode config not found: {OPENCODE_CONFIG}")
        return False
    except json.JSONDecodeError as e:
        print(f"  ⚠ Could not parse {OPENCODE_CONFIG}: {e}")
        return False

    try:
        options = config["provider"]["argo"]["options"]
    except KeyError:
        print(f"  ⚠ No provider.argo.options found in {OPENCODE_CONFIG}")
        return False

    new_url = f"https://{tunnel_host}:{tunnel_port}/argoapi/v1"
    options["baseURL"] = new_url
    headers = options.setdefault("headers", {})
    headers["Host"] = REAL_HOST
    with open(OPENCODE_CONFIG, "w") as f:
        json.dump(config, f, indent=2)
        f.write("\n")
    print(f"  ✓ Updated opencode.json baseURL -> {new_url}")
    print(f"  ✓ Set Host header -> {REAL_HOST}")
    return True


def health_check(tunnel_host, tunnel_port, listen_port, auth_token):
    """Validate the full chain: tunnel -> remote endpoint, and shim -> tunnel."""
    print("\nRunning health checks...")
    ok = True

    # 1. Tunnel health: TLS + HTTP request to the real endpoint
    print(f"  [1/2] Tunnel ({tunnel_host}:{tunnel_port} -> {REAL_HOST})...")
    try:
        context = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(tunnel_host, tunnel_port, context=context, timeout=10)
        conn.request("GET", "/argoapi/v1/models", headers={"Host": REAL_HOST, "x-api-key": API_KEY})
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        if resp.status < 500:
            print(f"    ✓ Tunnel healthy (HTTP {resp.status})")
        else:
            print(f"    ⚠ Tunnel responded but upstream returned HTTP {resp.status}: {body[:200]}")
            ok = False
    except ssl.SSLError as e:
        print(f"    ✗ Tunnel SSL error: {e}")
        print(f"    → This often means the SSH tunnel is stale. If you use ControlMaster,")
        print(f"      try: ssh -O exit {SSH_JUMP_HOST}  then re-run this script.")
        ok = False
    except Exception as e:
        print(f"    ✗ Tunnel error: {e}")
        ok = False

    # 2. Shim health: HTTP request through the shim
    print(f"  [2/2] Shim (127.0.0.1:{listen_port} -> tunnel:{tunnel_port})...")
    try:
        conn = http.client.HTTPConnection(TARGET_HOST, listen_port, timeout=10)
        headers = {"x-api-key": auth_token} if auth_token else {}
        conn.request("GET", "/v1/models", headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        if resp.status < 500:
            print(f"    ✓ Shim healthy (HTTP {resp.status})")
        else:
            print(f"    ⚠ Shim returned HTTP {resp.status}: {body[:200]}")
            ok = False
    except Exception as e:
        print(f"    ✗ Shim error: {e}")
        ok = False

    if ok:
        print("  ✅ All health checks passed\n")
    else:
        print("  ❌ Some health checks failed — see above\n")
    return ok


def main():
    parser = argparse.ArgumentParser(description="HTTP proxy shim for Argo API via SSH tunnel")
    parser.add_argument("--no-auth", action="store_true",
                        help="Disable token authentication on the shim (useful when project-level "
                             "Claude settings override the global apiKeyHelper)")
    parser.add_argument("--port", type=int, default=None,
                        help="Listen port for the shim (default: derived from username)")
    parser.add_argument("--tunnel", action="store_true",
                        help="Create an SSH tunnel bound to 0.0.0.0 (for compute node access) and exit. "
                             "Requires SSH access to CELS. Run on a UAN, or use --relay from your Mac.")
    parser.add_argument("--tunnel-host", default=None,
                        help="Connect to an existing tunnel on a remote host (e.g., a UAN hostname). "
                             "Skips local tunnel creation. Use when running from compute nodes.")
    parser.add_argument("--relay", metavar="REMOTE_HOST", default=None,
                        help="Relay mode: create SSH tunnel locally, then reverse-forward it to "
                             "REMOTE_HOST (e.g., a UAN). Run this on your Mac so compute nodes "
                             "can reach the API via the UAN.")
    parser.add_argument("--no-update-settings", action="store_true",
                        help="Don't modify ~/.claude/settings.json (useful if you manage settings separately)")
    parser.add_argument("--tunnel-port", type=int, default=None,
                        help="Override the tunnel port (default: listen port - 1). Use with --tunnel "
                             "and --tunnel-host to decouple the tunnel port from the listen port, "
                             "enabling simultaneous login and compute node shims with a stable "
                             "settings.json.")
    parser.add_argument("--direct", action="store_true",
                        help="Direct mode: connect straight to the Argo API without an SSH tunnel. "
                             "Use on CELS machines that have direct network access to apps.inside.anl.gov.")
    parser.add_argument("--test", action="store_true",
                        help="Use the Argo test environment (apps-test.inside.anl.gov) instead of production.")
    parser.add_argument("--opencode", action="store_true",
                        help="Configure opencode to use the SSH tunnel (updates opencode.json) and exit. "
                             "Does not start the shim.")
    parser.add_argument("--host", default=None,
                        help="Set the SSH_JUMP_HOST to a different machine (default: homes.cels.anl.gov)")
    parser.add_argument("--nojump", action="store_true",
                        help="Make a direct connection to the host rather than jumping through SSH_PROXY_JUMP")
    args = parser.parse_args()

    global REAL_HOST, SSH_JUMP_HOST, SSH_PROXY_JUMP

    if args.test:
        REAL_HOST = "apps-test.inside.anl.gov"
        print(f"Using test environment: {REAL_HOST}")

    if args.host:
        SSH_JUMP_HOST = args.host
        print(f"Using jump host: {SSH_JUMP_HOST}")
    if args.nojump:
        SSH_PROXY_JUMP = None
        print("Disabling proxy jump")

    if args.opencode:
        incompatible = sum(bool(x) for x in [args.tunnel, args.relay, args.direct])
        if incompatible:
            parser.error("--opencode cannot be combined with --tunnel, --relay, or --direct")
    else:
        mode_flags = sum(bool(x) for x in [args.tunnel, args.tunnel_host, args.relay, args.direct])
        if mode_flags > 1:
            parser.error("--tunnel, --tunnel-host, --relay, and --direct are mutually exclusive")

    print(f"API key: {API_KEY}")

    if args.port:
        listen_port = args.port
        port_is_auto = False
    else:
        listen_port = default_port(API_KEY)
        port_is_auto = True
        print(f"Derived port {listen_port} from username (override with --port <PORT>)")
    tunnel_port = args.tunnel_port if args.tunnel_port else listen_port - 1
    tunnel_port_is_auto = args.tunnel_port is None
    tunnel_host = args.tunnel_host or "127.0.0.1"

    if args.tunnel:
        # Tunnel-only mode: create a 0.0.0.0-bound tunnel on the UAN and exit
        hostname = socket.gethostname()
        print(f"Tunnel port {tunnel_port}" + ("" if args.tunnel_port else " (listen_port - 1)"))
        if find_existing_tunnel(tunnel_port):
            print(f"Tunnel already running on port {tunnel_port}")
        else:
            # Only auto-retry port increments when both ports are auto-derived
            max_retries = 10 if (port_is_auto and tunnel_port_is_auto) else 1
            for attempt in range(max_retries):
                try:
                    create_tunnel(tunnel_port, bind_address="0.0.0.0")
                    break
                except SSHAuthError:
                    raise  # Don't retry on auth failures — risk IP block
                except RuntimeError:
                    if attempt + 1 >= max_retries:
                        raise
                    listen_port += 1
                    tunnel_port = listen_port - 1
                    print(f"  Retrying with tunnel port {tunnel_port}...")
            print(f"Tunnel created on port {tunnel_port} (bound to 0.0.0.0)")
        print(f"\nOn the compute node, run:")
        print(f"  argo-shim --tunnel-host {hostname} --port {listen_port} --tunnel-port {tunnel_port}")
        print(f"\nFor opencode on the compute node, run:")
        print(f"  argo-shim --opencode --tunnel-host {hostname} --tunnel-port {tunnel_port}")
        return

    if args.opencode:
        # OpenCode mode: configure opencode.json and exit (no shim)
        if args.tunnel_host:
            # Compute node mode: use pre-existing tunnel on remote UAN
            print(f"Using remote tunnel at {tunnel_host}:{tunnel_port}")
            oc_tunnel_host = tunnel_host
            if not verify_tunnel(tunnel_port, tunnel_host):
                _ssh_tracker.check_allowed()
                print(f"  Direct connection failed, creating SSH forward to {tunnel_host}...")
                fwd_cmd = ["ssh", "-N", "-f",
                           "-o", "BatchMode=yes", "-o", "ConnectionAttempts=1",
                           "-L", f"127.0.0.1:{tunnel_port}:127.0.0.1:{tunnel_port}", tunnel_host]
                print(f"  $ {' '.join(fwd_cmd)}")
                result = subprocess.run(fwd_cmd)
                if result.returncode != 0:
                    _ssh_tracker.record_failure()
                    raise SSHAuthError(f"SSH forward to {tunnel_host} failed (exit code {result.returncode})")
                oc_tunnel_host = "127.0.0.1"
                if not verify_tunnel(tunnel_port, oc_tunnel_host):
                    raise RuntimeError(
                        f"No valid tunnel found at {args.tunnel_host}:{tunnel_port} "
                        f"(tried direct and SSH forward). "
                        f"Ensure argo-shim --tunnel is running on the UAN."
                    )
        else:
            # Local mode: create tunnel on this machine
            print(f"Tunnel port {tunnel_port}" + ("" if args.tunnel_port else " (listen_port - 1)"))
            if find_existing_tunnel(tunnel_port):
                print(f"Tunnel already running on port {tunnel_port}")
            else:
                max_retries = 10 if (port_is_auto and tunnel_port_is_auto) else 1
                for attempt in range(max_retries):
                    try:
                        create_tunnel(tunnel_port)
                        break
                    except SSHAuthError:
                        raise
                    except RuntimeError:
                        if attempt + 1 >= max_retries:
                            raise
                        listen_port += 1
                        tunnel_port = listen_port - 1
                        print(f"  Retrying with tunnel port {tunnel_port}...")
                print(f"Tunnel created on port {tunnel_port}")
            oc_tunnel_host = "127.0.0.1"
        update_opencode_settings(tunnel_port, oc_tunnel_host)
        print(f"\nThe tunnel's TLS cert is for {REAL_HOST}, not {oc_tunnel_host}.")
        print(f"Start opencode with TLS verification disabled:")
        print(f"  NODE_TLS_REJECT_UNAUTHORIZED=0 opencode")
        return

    if args.relay:
        # Relay mode: create local tunnel, then reverse-forward to remote host
        if find_existing_tunnel(tunnel_port):
            print(f"Using existing tunnel on port {tunnel_port}")
        else:
            max_retries = 10 if port_is_auto else 1
            for attempt in range(max_retries):
                try:
                    create_tunnel(tunnel_port)
                    break
                except SSHAuthError:
                    raise  # Don't retry on auth failures — risk IP block
                except RuntimeError:
                    if attempt + 1 >= max_retries:
                        raise
                    listen_port += 1
                    tunnel_port = listen_port - 1
                    print(f"  Retrying with port pair {tunnel_port}/{listen_port}...")
            print(f"Tunnel created on port {tunnel_port}")
        create_reverse_tunnel(args.relay, tunnel_port)
        print(f"\nRelay active: {args.relay}:{tunnel_port} -> localhost:{tunnel_port}")
        print(f"\nOn the compute node, run:")
        print(f"  argo-shim --tunnel-host {args.relay} --port {listen_port}")
        # Continue to start the local shim so Mac can also use Claude

    if args.direct:
        # Direct mode: no tunnel needed, proxy straight to REAL_HOST:443
        tunnel_host = REAL_HOST
        tunnel_port = 443
        print(f"Direct mode: connecting to {REAL_HOST}:443 without SSH tunnel")

    elif args.tunnel_host:
        # Compute node mode: use pre-existing tunnel on remote host
        print(f"Using remote tunnel at {tunnel_host}:{tunnel_port}")
        if not verify_tunnel(tunnel_port, tunnel_host):
            # Direct connection failed (likely GatewayPorts disabled).
            # Try SSH local forward to reach the remote host's localhost port.
            _ssh_tracker.check_allowed()
            print(f"  Direct connection failed, creating SSH forward to {tunnel_host}...")
            fwd_cmd = ["ssh", "-N", "-f",
                       "-o", "BatchMode=yes", "-o", "ConnectionAttempts=1",
                       "-L", f"127.0.0.1:{tunnel_port}:127.0.0.1:{tunnel_port}", tunnel_host]
            print(f"  $ {' '.join(fwd_cmd)}")
            result = subprocess.run(fwd_cmd)
            if result.returncode != 0:
                _ssh_tracker.record_failure()
                raise SSHAuthError(f"SSH forward to {tunnel_host} failed (exit code {result.returncode})")
            tunnel_host = "127.0.0.1"
            if not verify_tunnel(tunnel_port, tunnel_host):
                raise RuntimeError(
                    f"No valid tunnel found at {args.tunnel_host}:{tunnel_port} "
                    f"(tried direct and SSH forward). "
                    f"Ensure --relay is running on your Mac."
                )
    elif args.relay:
        pass  # tunnel already created above
    elif find_existing_tunnel(tunnel_port):
        print(f"Using existing tunnel on port {tunnel_port}")
    else:
        # Auto-retry port pair if derived (not explicit --port)
        max_retries = 10 if port_is_auto else 1
        for attempt in range(max_retries):
            try:
                create_tunnel(tunnel_port)
                break
            except SSHAuthError:
                raise  # Don't retry on auth failures — risk IP block
            except RuntimeError:
                if attempt + 1 >= max_retries:
                    raise
                listen_port += 1
                tunnel_port = listen_port - 1
                print(f"  Retrying with port pair {tunnel_port}/{listen_port}...")
        print(f"Tunnel created on port {tunnel_port}")

    # 3. Start the shim
    check_port_available(listen_port)
    if args.no_auth:
        auth_token = None
    elif args.tunnel_host:
        # Reuse the login node's token so its shim stays valid — both nodes share settings.json
        auth_token = read_existing_token() or secrets.token_urlsafe(32)
    else:
        auth_token = secrets.token_urlsafe(32)

    if args.no_auth:
        print("⚠ Auth disabled (--no-auth): shim accepts unauthenticated requests on localhost")

    # 4. Update Claude settings with the correct port and token
    if not args.no_update_settings:
        update_claude_settings(listen_port, auth_token)
        print(f"Set ANTHROPIC_BASE_URL=http://127.0.0.1:{listen_port}/argoapi")

    tunnel_is_remote = bool(args.tunnel_host) or args.direct
    with ThreadedTCPServer(("127.0.0.1", listen_port), ProxyHandler, tunnel_host, tunnel_port, auth_token, tunnel_is_remote) as httpd:
        if args.direct:
            print(f"✅ Shim running on {listen_port} -> {tunnel_host}:{tunnel_port} (direct). Supports GET/POST/HEAD.")
        else:
            print(f"✅ Shim running on {listen_port} -> {tunnel_port}. Supports GET/POST/HEAD.")
        proxy_set = any(os.environ.get(v) for v in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"))
        no_proxy_hosts = (os.environ.get("NO_PROXY", "") + "," + os.environ.get("no_proxy", "")).strip(",")
        if proxy_set and not any(h in no_proxy_hosts for h in ("localhost", "127.0.0.1")):
            print(f"\nProxy detected. Start Claude Code with:")
            print(f"  no_proxy=localhost,127.0.0.1 NO_PROXY=localhost,127.0.0.1 claude")

        def shutdown_handler(signum, frame):
            signame = signal.Signals(signum).name
            print(f"\n{signame} received, shutting down...")
            threading.Thread(target=httpd.shutdown).start()

        signal.signal(signal.SIGINT, shutdown_handler)
        signal.signal(signal.SIGTERM, shutdown_handler)

        # 5. Run health checks in background after shim is listening
        threading.Thread(target=health_check, args=(tunnel_host, tunnel_port, listen_port, auth_token), daemon=True).start()

        httpd.serve_forever()
        print("Shim stopped.")


if __name__ == "__main__":
    main()
