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
"""
import http.server
import socket
import sys
import threading
import time

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
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
    srv.shutdown()

    # Responses are concatenated with no separator between one body and the
    # next status line, so count status lines rather than splitting on CRLF.
    n_401 = data.count(b"HTTP/1.1 401")
    n_other = data.count(b"HTTP/1.1 ") - n_401
    print(f"responses: {n_401} x 401, {n_other} x other")

    if n_401 == 2 and n_other == 0:
        print("PASS: both pipelined requests answered 401; body was drained")
        return 0
    print("FAIL: expected exactly two 401s and nothing else.")
    print("      A 501/400 here means the undrained body was parsed as a request line.")
    print("      raw:", data[:400])
    return 1


if __name__ == "__main__":
    sys.exit(main())
