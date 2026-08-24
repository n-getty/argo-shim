#!/usr/bin/env python3
"""Validate the idle keep-alive connection reaping fix.

SAFETY: this test connects ONLY to the shim's local listen port and sends at
most a HEAD request (answered locally by do_HEAD). It never sends a proxiable
request, so handle_proxy / recover_tunnel / create_tunnel / ssh are never
reached. There is no path from this test to a CELS SSH attempt.

What it proves: opening N idle keep-alive connections spawns N handler threads
blocked in readline; with ProxyHandler.timeout set, the SERVER reaps them after
the idle timeout even though the client keeps the sockets open. Thread count
(nlwp) should rise by ~N, then fall back toward baseline ~timeout seconds later.
"""
import socket
import subprocess
import sys
import time

LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 20098
N = 30                 # connections to open
SEND_HEAD = True       # simulate a real keep-alive client (HEAD is local-only)
WATCH_SECONDS = 330    # must exceed CONNECTION_IDLE_TIMEOUT (305) with margin
POLL = 5


def shim_pid(port):
    out = subprocess.run(
        ["lsof", "-ti", f"TCP:{port}", "-sTCP:LISTEN"],
        stdout=subprocess.PIPE, universal_newlines=True,
    ).stdout.strip().split("\n")
    return out[0] if out and out[0] else None


def nlwp(pid):
    r = subprocess.run(["ps", "-o", "nlwp=", "-p", pid],
                       stdout=subprocess.PIPE, universal_newlines=True)
    s = r.stdout.strip()
    return int(s) if s else -1


def main():
    pid = shim_pid(LISTEN_PORT)
    if not pid:
        print(f"FAIL: no shim listening on {LISTEN_PORT}")
        return 1
    print(f"shim pid={pid} on port {LISTEN_PORT}, timeout-reaping test")

    base = nlwp(pid)
    print(f"baseline threads (nlwp): {base}")

    socks = []
    for _ in range(N):
        s = socket.create_connection(("127.0.0.1", LISTEN_PORT), timeout=5)
        if SEND_HEAD:
            # HEAD to the base path: do_HEAD answers 200 locally, then the
            # HTTP/1.1 connection stays open (keep-alive) -> thread idles in
            # readline. This is exactly Claude Code's pooled-connection pattern.
            s.sendall(b"HEAD /argoapi HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            s.recv(4096)  # drain the 200 so the server returns to readline
        socks.append(s)
    time.sleep(1)
    peak = nlwp(pid)
    print(f"after opening {N} idle keep-alive conns: nlwp={peak}  (+{peak - base})")
    if peak - base < N * 0.7:
        print("WARN: thread count did not rise as expected — connections may "
              "not have stuck (is the fix's keep-alive behavior as assumed?)")

    print(f"holding {N} client sockets OPEN and idle; watching server reap them...")
    t0 = time.time()
    reaped_at = None
    while time.time() - t0 < WATCH_SECONDS:
        time.sleep(POLL)
        cur = nlwp(pid)
        elapsed = int(time.time() - t0)
        print(f"  t+{elapsed:>2}s  nlwp={cur}  (+{cur - base})")
        if reaped_at is None and cur - base <= N * 0.3:
            reaped_at = elapsed

    for s in socks:
        try:
            s.close()
        except OSError:
            pass

    print("-" * 50)
    if reaped_at is not None:
        print(f"PASS: server reaped idle threads ~{reaped_at}s after open "
              f"(client never closed). Idle-timeout fix works.")
        return 0
    print(f"FAIL: threads still elevated after {WATCH_SECONDS}s "
          f"(nlwp stayed near {peak}). Idle connections are NOT being reaped.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
