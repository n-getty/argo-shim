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

Also covers the cases where draining is unsafe and the handler must close the
connection instead of reading:

  * a body larger than MAX_DRAIN_BYTES (an unauthenticated caller must not be
    able to size a buffer via Content-Length);
  * a negative Content-Length, which parses as an int and would otherwise skip
    the drain silently and desync the next request;
  * a chunked body, which is framed by chunk headers rather than
    Content-Length, so there is no byte count to drain.

And the drain deadline: a client dribbling its body one byte at a time must not
be able to pin a handler thread. CONNECTION_IDLE_TIMEOUT is a per-operation
socket timeout, so a slow trickle renews it on every read; MAX_DRAIN_SECONDS
bounds the loop as a whole.
"""
import http.server
import os
import socket
import socketserver
import sys
import threading
import time

# Repo root, so `argo_shim` imports from the working tree, not an installed copy.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import argo_shim._shim as shim

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 20099
GOOD = "GOODTOKEN"
BODY = b'{"model":"claude-sonnet-5","messages":[{"role":"user","content":"hi"}]}'


# ThreadingMixIn + HTTPServer rather than ThreadingHTTPServer: the latter is
# 3.7+, and this runs against the 3.6 stdlib on some ALCF login nodes.
class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    auth_token = GOOD


def _serve(port):
    srv = _Server(("127.0.0.1", port), shim.ProxyHandler)
    threading.Thread(target=srv.serve_forever).start()
    time.sleep(0.3)
    return srv


def _drain_socket(sock, timeout=3):
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, TimeoutError, OSError):
        pass
    return data


def _bad_token_post(content_length=None, body=BODY, extra_headers=b""):
    declared = len(body) if content_length is None else content_length
    return (
        b"POST /argoapi/v1/messages HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"x-api-key: WRONGTOKEN\r\n"
        b"Content-Type: application/json\r\n"
        + extra_headers
        + b"Content-Length: " + str(declared).encode() + b"\r\n\r\n" + body
    )


def _check_oversize_body_closes(port):
    """A body over MAX_DRAIN_BYTES must still get a 401, and must not be read.

    We declare a huge Content-Length but send only a small prefix. If the
    handler tried to drain the declared length it would block until the socket
    timeout; instead it should answer 401 promptly and close.
    """
    declared = shim.MAX_DRAIN_BYTES + 1
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.sendall(_bad_token_post(content_length=declared, body=b"x" * 1024))
    started = time.monotonic()
    data = _drain_socket(s, timeout=5)
    elapsed = time.monotonic() - started
    s.close()

    got_401 = b"HTTP/1.1 401" in data
    print("oversize: 401={} elapsed={:.2f}s".format(got_401, elapsed))
    if not got_401:
        print("FAIL: oversize body did not get a 401")
        return False
    if elapsed > 4:
        print("FAIL: handler appears to have waited on the undelivered body")
        return False
    print("PASS: oversize body rejected without draining")
    return True


def _check_undrainable_closes(port, label, request):
    """Requests we can't drain byte-exactly must get a 401 and a closed socket.

    Two pipelined copies. If the handler closes as it should, the second is
    never served and the 401 is the ONLY thing on the wire. Anything after it
    means leftover bytes were parsed as a request line — the original desync,
    reached by a path the Content-Length drain doesn't cover.

    We assert on trailing bytes rather than counting status lines: when the
    leftover bytes don't parse as a request line, the stdlib treats the request
    as HTTP/0.9 and send_response_only emits the error page with NO status line
    at all, so a status-line count would score that desync as clean.
    """
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(request + request)
    data = _drain_socket(s)
    s.close()

    if b"HTTP/1.1 401" not in data:
        print("FAIL: {} did not get a 401".format(label))
        print("      raw:", data[:300])
        return False

    head, _, rest = data.partition(b"\r\n\r\n")
    declared = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            declared = int(line.split(b":", 1)[1].strip())
    trailing = len(rest) - declared
    print("{}: 401 + {} trailing byte(s)".format(label, trailing))
    if trailing > 0:
        print("FAIL: {} left bytes in the buffer; connection was not closed.".format(label))
        print("      trailing:", rest[declared:][:200])
        return False
    print("PASS: {} answered 401 and closed".format(label))
    return True


def _check_dribble_deadline(port):
    """A byte-at-a-time body must not pin the handler thread indefinitely.

    ProxyHandler.timeout is a PER-OPERATION socket timeout, so a client that
    sends one byte just often enough renews it forever. MAX_DRAIN_SECONDS
    bounds the drain loop as a whole, so the 401 should land shortly after it
    expires even though the client is still dribbling.
    """
    budget = shim.MAX_DRAIN_SECONDS
    s = socket.create_connection(("127.0.0.1", port), timeout=budget * 4)
    s.sendall(_bad_token_post(content_length=200000, body=b""))
    started = time.monotonic()
    replied_after = None
    for _ in range(int(budget * 2.5)):
        try:
            s.sendall(b"x")
        except OSError:
            break                      # handler closed on us; that's the point
        time.sleep(1.0)
        s.settimeout(0.05)
        try:
            if s.recv(64):
                replied_after = time.monotonic() - started
                break
        except (socket.timeout, TimeoutError, OSError):
            pass
        s.settimeout(budget * 4)
    s.close()

    if replied_after is None:
        print("dribble: no reply after {:.1f}s".format(time.monotonic() - started))
        print("FAIL: handler is still draining a dribbled body (thread pinned).")
        return False
    print("dribble: 401 after {:.1f}s (deadline {}s)".format(replied_after, budget))
    print("PASS: drain loop is bounded by wall clock, not per-read timeout")
    return True


def main():
    srv = _serve(PORT)

    # Two pipelined bad-token POSTs on ONE keep-alive connection.
    s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    s.sendall(_bad_token_post() + _bad_token_post())
    data = _drain_socket(s)
    s.close()

    # Responses are concatenated with no separator between one body and the
    # next status line, so count status lines rather than splitting on CRLF.
    n_401 = data.count(b"HTTP/1.1 401")
    n_other = data.count(b"HTTP/1.1 ") - n_401
    print("responses: {} x 401, {} x other".format(n_401, n_other))

    pipelined_ok = n_401 == 2 and n_other == 0
    if pipelined_ok:
        print("PASS: both pipelined requests answered 401; body was drained")
    else:
        print("FAIL: expected exactly two 401s and nothing else.")
        print("      A 501/400 here means the undrained body was parsed as a request line.")
        print("      raw:", data[:400])

    chunked_req = (
        b"POST /argoapi/v1/messages HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"x-api-key: WRONGTOKEN\r\n"
        b"Content-Type: application/json\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        + hex(len(BODY))[2:].encode() + b"\r\n" + BODY + b"\r\n0\r\n\r\n"
    )
    results = [
        pipelined_ok,
        _check_oversize_body_closes(PORT),
        _check_undrainable_closes(PORT, "negative length", _bad_token_post(content_length=-1)),
        _check_undrainable_closes(PORT, "chunked", chunked_req),
        _check_dribble_deadline(PORT),
    ]

    srv.shutdown()
    srv.server_close()
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
