#!/usr/bin/env python3
"""Validate that a 401 drains the request body before replying.

SAFETY: this test binds ProxyHandler to a throwaway localhost port with a
known auth token and sends only requests carrying a WRONG token. Every request
is rejected by the auth gate at the top of handle_proxy, so the proxy path
(recover_tunnel / create_tunnel / ssh / any upstream connection) is never
reached. There is no path from this test to a CELS SSH attempt.

What it proves: protocol_version is HTTP/1.1, so connections are keep-alive by
default. Before the fix, the 401 branch returned without consuming
Content-Length bytes, leaving the body in the socket buffer; the next read
parsed that body as a request line. Two pipelined bad-token POSTs therefore
produced one 401 plus one bogus 501/400 whose "request line" was the JSON
payload:

    127.0.0.1 - - [...] "{"model":"claude-...","messages":[...]}POST /..." 501 -

After the fix, the same two requests produce two clean 401s.

Also covers the bounded-drain guard: a body larger than MAX_DRAIN_BYTES is not
read at all (an unauthenticated caller must not be able to size a buffer via
Content-Length); the connection is closed after the 401 instead, so there is
nothing left over to desync a subsequent request.
"""
import http.server
import os
import socket
import sys
import threading
import time

# Repo root, so `argo_shim` imports from the working tree, not an installed copy.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import argo_shim._shim as shim

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 20099
GOOD = "GOODTOKEN"
BODY = b'{"model":"claude-sonnet-5","messages":[{"role":"user","content":"hi"}]}'


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    auth_token = GOOD


def _bad_token_post():
    return (
        b"POST /argoapi/v1/messages HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"x-api-key: WRONGTOKEN\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(BODY)).encode() + b"\r\n\r\n" + BODY
    )


def _check_oversize_body_closes(port):
    """A body over MAX_DRAIN_BYTES must still get a 401, and must not be read.

    We declare a huge Content-Length but send only a small prefix. If the
    handler tried to drain the declared length it would block until the socket
    timeout; instead it should answer 401 promptly and close.
    """
    declared = shim.MAX_DRAIN_BYTES + 1
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(
        b"POST /argoapi/v1/messages HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"x-api-key: WRONGTOKEN\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(declared).encode() + b"\r\n\r\n" + b"x" * 1024
    )
    started = time.monotonic()
    s.settimeout(5)
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, TimeoutError):
        pass
    elapsed = time.monotonic() - started
    s.close()

    got_401 = b"HTTP/1.1 401" in data
    closed = data.endswith(b"Bearer token)") or b"close" in data.lower()
    print(f"oversize: 401={got_401} elapsed={elapsed:.2f}s")
    if not got_401:
        print("FAIL: oversize body did not get a 401")
        return False
    if elapsed > 4:
        print("FAIL: handler appears to have waited on the undelivered body")
        return False
    print("PASS: oversize body rejected without draining")
    return True


def main():
    srv = _Server(("127.0.0.1", PORT), shim.ProxyHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)

    # Two pipelined bad-token POSTs on ONE keep-alive connection.
    s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    s.sendall(_bad_token_post() + _bad_token_post())
    time.sleep(1.0)
    s.settimeout(3)
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, TimeoutError):
        pass
    s.close()

    # Responses are concatenated with no separator between one body and the
    # next status line, so count status lines rather than splitting on CRLF.
    n_401 = data.count(b"HTTP/1.1 401")
    n_other = data.count(b"HTTP/1.1 ") - n_401
    print(f"responses: {n_401} x 401, {n_other} x other")

    pipelined_ok = n_401 == 2 and n_other == 0
    if pipelined_ok:
        print("PASS: both pipelined requests answered 401; body was drained")
    else:
        print("FAIL: expected exactly two 401s and nothing else.")
        print("      A 501/400 here means the undrained body was parsed as a request line.")
        print("      raw:", data[:400])

    oversize_ok = _check_oversize_body_closes(PORT)

    srv.shutdown()
    return 0 if (pipelined_ok and oversize_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
