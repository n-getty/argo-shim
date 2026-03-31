import getpass
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

BASE_TUNNEL_PORT = 8080
BASE_LISTEN_PORT = 8081
MAX_PORT_RETRIES = 10
TARGET_HOST = "127.0.0.1"
REAL_HOST = "apps.inside.anl.gov"
API_KEY = os.environ.get("CELS_USERNAME", getpass.getuser())
SSH_JUMP_HOST = "homes.cels.anl.gov"
SSH_PROXY_JUMP = "logins.cels.anl.gov"

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

    def handle_proxy(self, method):
        # Validate auth token (HEAD is exempt — used by Claude Code as a connectivity probe)
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

        # Path rewrite logic
        path = self.path
        if not path.startswith("/argoapi"):
            path = ("/argoapi/" + path.lstrip("/")).replace("//", "/")

        context = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(TARGET_HOST, self.server.target_port, context=context, timeout=300)

        # Build headers
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ['host', 'content-length', 'authorization']}
        headers['Host'] = REAL_HOST
        headers['x-api-key'] = API_KEY
        headers['Connection'] = 'close'

        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()

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

        except Exception as e:
            print(f"Proxy Error ({method}): {e}")
        finally:
            conn.close()

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, handler, target_port, auth_token):
        self.target_port = target_port
        self.auth_token = auth_token
        super().__init__(server_address, handler)


def find_free_port(base, host="127.0.0.1"):
    """Find a port that nothing is bound to (for the shim to listen on)."""
    for port in range(base, base + MAX_PORT_RETRIES):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                return port
            except OSError:
                print(f"Port {port} in use, trying next...")
    raise RuntimeError(f"No free port found in range {base}-{base + MAX_PORT_RETRIES - 1}")


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
    except ssl.SSLCertVerificationError as e:
        print(f"  ✗ Port {port}: TLS cert does not match {REAL_HOST}: {e}")
        return False
    except ssl.SSLError as e:
        print(f"  ✗ Port {port}: TLS handshake failed (not a tunnel to a TLS server): {e}")
        return False
    except (ConnectionRefusedError, OSError) as e:
        print(f"  ✗ Port {port}: connection failed: {e}")
        return False


def is_own_process(port):
    """Check if the process listening on a port belongs to the current user."""
    try:
        result = subprocess.run(
            ["lsof", "-ti", f"TCP@127.0.0.1:{port}", "-sTCP:LISTEN"],
            capture_output=True, text=True, timeout=5
        )
        for pid in result.stdout.strip().split('\n'):
            if not pid:
                continue
            stat = subprocess.run(
                ["ps", "-o", "user=", "-p", pid],
                capture_output=True, text=True, timeout=5
            )
            owner = stat.stdout.strip()
            if owner == API_KEY:
                return True
            print(f"  Skipping port {port} (owned by {owner}, not {API_KEY})")
            return False
    except Exception:
        pass
    return False


def find_existing_tunnel(base, host="127.0.0.1"):
    """Check if a verified tunnel to REAL_HOST already exists in the port range."""
    for port in range(base, base + MAX_PORT_RETRIES):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect((host, port))
                if not is_own_process(port):
                    continue
                print(f"Port {port} is listening, verifying tunnel...")
                if verify_tunnel(port, host):
                    return port
                else:
                    print(f"  Skipping port {port} (not a valid tunnel to {REAL_HOST})")
            except (ConnectionRefusedError, OSError):
                pass
    return None


def create_tunnel(base, host="127.0.0.1"):
    """Create a new SSH tunnel and verify it's working."""
    port = find_free_port(base)
    cmd = ["ssh", "-N", "-f", "-J", f"{API_KEY}@{SSH_PROXY_JUMP}", "-L", f"{port}:{REAL_HOST}:443", f"{API_KEY}@{SSH_JUMP_HOST}"]
    print(f"Creating SSH tunnel on port {port}...")
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise RuntimeError(f"SSH tunnel failed (exit code {result.returncode})")

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

    return port


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
    settings["apiKeyHelper"] = f"echo {auth_token}"
    settings.setdefault("env", {})["ANTHROPIC_BASE_URL"] = new_url

    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)
        f.write("\n")
    print(f"  ✓ Updated settings.json (port={listen_port}, token rotated)")
    return True


def health_check(tunnel_port, listen_port, auth_token):
    """Validate the full chain: tunnel -> remote endpoint, and shim -> tunnel."""
    print("\nRunning health checks...")
    ok = True

    # 1. Tunnel health: TLS + HTTP request to the real endpoint
    print(f"  [1/2] Tunnel (127.0.0.1:{tunnel_port} -> {REAL_HOST})...")
    try:
        context = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(TARGET_HOST, tunnel_port, context=context, timeout=10)
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
        conn.request("GET", "/v1/models", headers={"x-api-key": auth_token})
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


if __name__ == "__main__":
    print(f"API key: {API_KEY}")

    # 1. Look for an existing verified tunnel
    tunnel_port = find_existing_tunnel(BASE_TUNNEL_PORT)
    if tunnel_port:
        print(f"Using existing tunnel on port {tunnel_port}")
    else:
        # 2. No valid tunnel found — create one
        tunnel_port = create_tunnel(BASE_TUNNEL_PORT)
        print(f"Tunnel created on port {tunnel_port}")

    # 3. Start the shim
    listen_port = find_free_port(max(BASE_LISTEN_PORT, tunnel_port + 1))
    auth_token = secrets.token_urlsafe(32)

    # 4. Update Claude settings with the correct port and token
    update_claude_settings(listen_port, auth_token)
    print(f"Set ANTHROPIC_BASE_URL=http://127.0.0.1:{listen_port}/argoapi")

    with ThreadedTCPServer(("127.0.0.1", listen_port), ProxyHandler, tunnel_port, auth_token) as httpd:
        print(f"✅ Shim running on {listen_port} -> {tunnel_port}. Supports GET/POST/HEAD.")

        def shutdown_handler(signum, frame):
            signame = signal.Signals(signum).name
            print(f"\n{signame} received, shutting down...")
            threading.Thread(target=httpd.shutdown).start()

        signal.signal(signal.SIGINT, shutdown_handler)
        signal.signal(signal.SIGTERM, shutdown_handler)

        # 5. Run health checks in background after shim is listening
        threading.Thread(target=health_check, args=(tunnel_port, listen_port, auth_token), daemon=True).start()

        httpd.serve_forever()
        print("Shim stopped.")
