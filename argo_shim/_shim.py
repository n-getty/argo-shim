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


def default_port(username):
    """Derive a deterministic listen port from the username."""
    h = hashlib.sha256(username.encode()).hexdigest()
    return 10000 + (int(h[:8], 16) % 22768)  # range 10000-32767 (below ephemeral range)

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
        if method == "POST" and body and "/messages" in self.path:
            try:
                req_json = json.loads(body)
                stream_val = req_json.get("stream", "<not set>")
                model_val = req_json.get("model", "<not set>")
                if req_json.get("stream") is not True:
                    print(f"[{method}] /messages: stream={stream_val} -> forcing stream=true (model={model_val})")
                    req_json["stream"] = True
                    body = json.dumps(req_json).encode("utf-8")
                else:
                    print(f"[{method}] /messages: stream={stream_val}, model={model_val}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                print(f"[{method}] /messages: could not parse body, forwarding as-is")

        # Path rewrite logic
        path = self.path
        if not path.startswith("/argoapi"):
            path = ("/argoapi/" + path.lstrip("/")).replace("//", "/")

        context = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(self.server.target_host, self.server.target_port, context=context, timeout=300)

        # Build headers
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ['host', 'content-length', 'authorization']}
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
                print(f"[{method}] Upstream connection refused (tunnel is down)")
                self._send_error(502, "Bad Gateway: SSH tunnel is down. Restart argo-shim.")
                return
            except Exception as e:
                conn.close()
                print(f"[{method}] Upstream error: {e}")
                self._send_error(502, f"Bad Gateway: {e}")
                return

        try:
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
            except Exception as e:
                print(f"Tunnel recovery failed: {e}")
                return False


def check_port_available(port, host="127.0.0.1"):
    """Check that a port is available, or raise with a helpful message."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
        except OSError:
            raise RuntimeError(
                f"Port {port} is already in use. "
                f"Use --port <PORT> to specify a different port."
            )


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
        # Use TCP:{port} without address filter — lsof represents 0.0.0.0 as *
        # so TCP@127.0.0.1 and TCP@0.0.0.0 both fail to match wildcard binds.
        result = subprocess.run(
            ["lsof", "-ti", f"TCP:{port}", "-sTCP:LISTEN"],
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
    print(f"  Port {port} is not a valid tunnel to {REAL_HOST}")
    return False


def create_tunnel(port, host="127.0.0.1", bind_address="127.0.0.1"):
    """Create a new SSH tunnel on the given port and verify it's working."""
    check_port_available(port, bind_address)
    cmd = [
        "ssh", "-N", "-f",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=4",
        "-J", f"{API_KEY}@{SSH_PROXY_JUMP}",
        "-L", f"{bind_address}:{port}:{REAL_HOST}:443",
        f"{API_KEY}@{SSH_JUMP_HOST}",
    ]
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


def create_reverse_tunnel(remote_host, port):
    """Create a reverse SSH tunnel, forwarding remote_host:port to localhost:port."""
    cmd = ["ssh", "-N", "-f", "-R", f"0.0.0.0:{port}:127.0.0.1:{port}", remote_host]
    print(f"Creating reverse tunnel to {remote_host}:{port}...")
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise RuntimeError(f"Reverse SSH tunnel to {remote_host} failed (exit code {result.returncode})")


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
    auth_status = "token rotated" if auth_token else "no auth"
    print(f"  ✓ Updated settings.json (port={listen_port}, {auth_status})")
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
    args = parser.parse_args()

    mode_flags = sum(bool(x) for x in [args.tunnel, args.tunnel_host, args.relay])
    if mode_flags > 1:
        parser.error("--tunnel, --tunnel-host, and --relay are mutually exclusive")

    print(f"API key: {API_KEY}")

    if args.port:
        listen_port = args.port
    else:
        listen_port = default_port(API_KEY)
        print(f"Derived port {listen_port} from username (override with --port <PORT>)")
    tunnel_port = listen_port - 1
    tunnel_host = args.tunnel_host or "127.0.0.1"

    if args.tunnel:
        # Tunnel-only mode: create a 0.0.0.0-bound tunnel on the UAN and exit
        hostname = socket.gethostname()
        if find_existing_tunnel(tunnel_port, "0.0.0.0") or find_existing_tunnel(tunnel_port):
            print(f"Tunnel already running on port {tunnel_port}")
        else:
            create_tunnel(tunnel_port, bind_address="0.0.0.0")
            print(f"Tunnel created on port {tunnel_port} (bound to 0.0.0.0)")
        print(f"\nOn the compute node, run:")
        print(f"  argo-shim --tunnel-host {hostname}")
        return

    if args.relay:
        # Relay mode: create local tunnel, then reverse-forward to remote host
        if find_existing_tunnel(tunnel_port):
            print(f"Using existing tunnel on port {tunnel_port}")
        else:
            create_tunnel(tunnel_port)
            print(f"Tunnel created on port {tunnel_port}")
        create_reverse_tunnel(args.relay, tunnel_port)
        print(f"\nRelay active: {args.relay}:{tunnel_port} -> localhost:{tunnel_port}")
        print(f"\nOn the compute node, run:")
        print(f"  argo-shim --tunnel-host {args.relay}")
        # Continue to start the local shim so Mac can also use Claude

    if args.tunnel_host:
        # Compute node mode: use pre-existing tunnel on remote host
        print(f"Using remote tunnel at {tunnel_host}:{tunnel_port}")
        if not verify_tunnel(tunnel_port, tunnel_host):
            # Direct connection failed (likely GatewayPorts disabled).
            # Try SSH local forward to reach the remote host's localhost port.
            print(f"  Direct connection failed, creating SSH forward to {tunnel_host}...")
            fwd_cmd = ["ssh", "-N", "-f", "-L",
                       f"127.0.0.1:{tunnel_port}:127.0.0.1:{tunnel_port}", tunnel_host]
            print(f"  $ {' '.join(fwd_cmd)}")
            result = subprocess.run(fwd_cmd)
            if result.returncode != 0:
                raise RuntimeError(f"SSH forward to {tunnel_host} failed (exit code {result.returncode})")
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
        create_tunnel(tunnel_port)
        print(f"Tunnel created on port {tunnel_port}")

    # 3. Start the shim
    check_port_available(listen_port)
    auth_token = None if args.no_auth else secrets.token_urlsafe(32)

    if args.no_auth:
        print("⚠ Auth disabled (--no-auth): shim accepts unauthenticated requests on localhost")

    # 4. Update Claude settings with the correct port and token
    if not args.no_update_settings:
        update_claude_settings(listen_port, auth_token)
        print(f"Set ANTHROPIC_BASE_URL=http://127.0.0.1:{listen_port}/argoapi")

    tunnel_is_remote = bool(args.tunnel_host)
    with ThreadedTCPServer(("127.0.0.1", listen_port), ProxyHandler, tunnel_host, tunnel_port, auth_token, tunnel_is_remote) as httpd:
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
