#!/usr/bin/env python3
"""Validate the shim's handling of Argo's native OpenAI Responses API.

SAFETY: this test replaces http.client.HTTPSConnection inside the shim module
with a fake that never opens a socket, so no request reaches Argo, Vertex, or
any ALCF host. The client side binds a real ThreadedTCPServer to a throwaway
localhost port, but that server is only ever driven by requests this test
sends itself. There is no path from this test to a CELS SSH attempt or any
outbound network I/O — the fake connection object is a pure in-memory stand-in.

Background: Argo now exposes /argoapi/v1/responses natively (what Codex CLI
actually speaks). argo-shim is a path-agnostic pass-through proxy, so it never
404'd this path — but /responses rejects the x-api-key header argo-shim always
sent and instead wants the ALCF username as an `Authorization: Bearer` token.
handle_proxy (argo_shim/_shim.py) now adds that header for any request whose
path contains "/responses", in addition to (not instead of) x-api-key, and
extends the existing /chat/completions model-normalization block to also cover
/responses create calls — without the /chat/completions-only `user` injection,
which /responses doesn't take.

This test drives the real ProxyHandler / ThreadedTCPServer code end-to-end and
inspects the headers and JSON body that actually reach the (faked) upstream
connection, so it fails if the auth header is missing, forwards the client's
own Authorization instead of the shim's, leaks onto unrelated paths, or the
model isn't normalized.
"""
import json
import os
import socket
import sys
import threading
import time

# Repo root, so `argo_shim` imports from the working tree, not an installed copy.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import argo_shim._shim as shim

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 20198

RESPONSES_BODY = json.dumps({
    "id": "resp_1", "object": "response", "status": "completed", "output": [],
}).encode("utf-8")

CHAT_COMPLETIONS_BODY = json.dumps({
    "id": "chatcmpl_1", "object": "chat.completion",
    "choices": [{"message": {"role": "assistant", "content": "hi"}}],
}).encode("utf-8")

MESSAGES_SSE_BODY = (
    b'data: {"type":"message_start","message":{"id":"msg_1","type":"message",'
    b'"role":"assistant","content":[],"model":"claude","usage":{}}}\n\n'
    b'data: {"type":"content_block_start","index":0,"content_block":'
    b'{"type":"text","text":""}}\n\n'
    b'data: {"type":"content_block_delta","index":0,"delta":'
    b'{"type":"text_delta","text":"hi"}}\n\n'
    b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},'
    b'"usage":{"output_tokens":1}}\n\n'
    b'data: [DONE]\n\n'
)


class _FakeResponse:
    """Stands in for http.client.HTTPResponse; only the methods handle_proxy uses."""

    def __init__(self, body, status=200, headers=None):
        self._body = body
        self.status = status
        self._headers = headers or [("Content-Type", "application/json")]

    def read(self, n=None):
        if n is None:
            chunk, self._body = self._body, b""
            return chunk
        chunk, self._body = self._body[:n], self._body[n:]
        return chunk

    def getheaders(self):
        return self._headers


class _FakeHTTPSConnection:
    """Stands in for http.client.HTTPSConnection. Records the request it was
    asked to send instead of opening any socket, so the outgoing headers and
    body — after the shim's own transformations — are inspectable by the
    test."""

    captured = []  # class-level, appended by each instance's request()

    def __init__(self, host, port, context=None, timeout=None):
        pass

    def request(self, method, path, body=None, headers=None):
        if "/responses" in path:
            resp_body = RESPONSES_BODY
        elif "/chat/completions" in path:
            resp_body = CHAT_COMPLETIONS_BODY
        else:
            resp_body = MESSAGES_SSE_BODY
        is_sse = resp_body is MESSAGES_SSE_BODY
        self._response = _FakeResponse(
            resp_body,
            headers=[("Content-Type", "text/event-stream" if is_sse else "application/json")])
        _FakeHTTPSConnection.captured.append({
            "method": method, "path": path,
            "body": json.loads(body) if body else None,
            "headers": headers,
        })

    def getresponse(self):
        return self._response

    def close(self):
        pass


def _serve(port):
    srv = shim.ThreadedTCPServer(
        ("127.0.0.1", port), shim.ProxyHandler,
        target_host="127.0.0.1", target_port=1,  # never dialed; connection is faked
        auth_token=None)
    # Pre-seed the alias map: the fake connection also intercepts
    # fetch_argo_models, so an unseeded run would parse a non-/models fake body
    # as the model list, throw, and cache an empty alias map — silently
    # disabling the normalization this test asserts.
    srv._model_alias = {"gpt4o": "gpt4o"}
    t = threading.Thread(target=srv.serve_forever)
    t.daemon = True
    t.start()
    time.sleep(0.3)
    return srv


def _post(port, path, payload, extra_headers=None):
    body = json.dumps(payload).encode("utf-8")
    header_lines = (
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: {length}\r\n"
        "Connection: close\r\n"
    ).format(length=len(body))
    for k, v in (extra_headers or {}).items():
        header_lines += "{}: {}\r\n".format(k, v)
    req = ("POST {path} HTTP/1.1\r\n".format(path=path) + header_lines + "\r\n").encode("utf-8") + body

    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(req)
    s.settimeout(5)
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, TimeoutError, OSError):
        pass
    s.close()
    return data


def _check_bearer_added(port):
    """/responses gains an Authorization: Bearer <API_KEY> header, plus x-api-key."""
    _FakeHTTPSConnection.captured.clear()
    resp = _post(port, "/v1/responses", {"model": "gpt4o", "input": "hi"})
    if b"HTTP/1.1 200" not in resp:
        print("FAIL: bearer_added: request did not complete: {!r}".format(resp[:200]))
        return False
    sent = _FakeHTTPSConnection.captured[-1]
    auth = sent["headers"].get("Authorization")
    api_key = sent["headers"].get("x-api-key")
    if auth != "Bearer {}".format(shim.API_KEY):
        print("FAIL: bearer_added: Authorization was {!r}, want Bearer {!r}".format(auth, shim.API_KEY))
        return False
    if api_key != shim.API_KEY:
        print("FAIL: bearer_added: x-api-key was {!r} (should still be sent alongside Authorization)".format(api_key))
        return False
    print("PASS: /responses gets Authorization: Bearer <API_KEY> in addition to x-api-key")
    return True


def _check_client_bearer_not_forwarded(port):
    """A client-supplied Authorization must not reach Argo; only our API_KEY should."""
    _FakeHTTPSConnection.captured.clear()
    resp = _post(port, "/v1/responses", {"model": "gpt4o", "input": "hi"},
                 extra_headers={"Authorization": "Bearer some-client-token"})
    if b"HTTP/1.1 200" not in resp:
        print("FAIL: client_bearer_not_forwarded: request did not complete: {!r}".format(resp[:200]))
        return False
    sent = _FakeHTTPSConnection.captured[-1]
    auth = sent["headers"].get("Authorization")
    if auth != "Bearer {}".format(shim.API_KEY):
        print("FAIL: client_bearer_not_forwarded: upstream Authorization was {!r} — "
              "the client's own token leaked through instead of being replaced".format(auth))
        return False
    print("PASS: client-supplied Authorization is replaced with the shim's own API_KEY")
    return True


def _check_other_paths_no_bearer(port):
    """/chat/completions and /messages must NOT gain an Authorization header."""
    ok = True
    _FakeHTTPSConnection.captured.clear()
    resp = _post(port, "/v1/chat/completions", {"model": "gpt4o", "messages": []})
    if b"HTTP/1.1 200" not in resp:
        print("FAIL: other_paths_no_bearer: /chat/completions did not complete: {!r}".format(resp[:200]))
        ok = False
    else:
        auth = _FakeHTTPSConnection.captured[-1]["headers"].get("Authorization")
        if auth is not None:
            print("FAIL: /chat/completions gained Authorization: {!r} (overbroad)".format(auth))
            ok = False

    _FakeHTTPSConnection.captured.clear()
    resp = _post(port, "/v1/messages", {"model": "claude-opus-4-6", "stream": True, "messages": []})
    if b"HTTP/1.1 200" not in resp:
        print("FAIL: other_paths_no_bearer: /messages did not complete: {!r}".format(resp[:200]))
        ok = False
    else:
        auth = _FakeHTTPSConnection.captured[-1]["headers"].get("Authorization")
        if auth is not None:
            print("FAIL: /messages gained Authorization: {!r} (overbroad)".format(auth))
            ok = False

    if ok:
        print("PASS: /chat/completions and /messages do not gain an Authorization header")
    return ok


def _check_model_normalized(port):
    """/responses normalizes model names via the seeded alias map."""
    _FakeHTTPSConnection.captured.clear()
    resp = _post(port, "/v1/responses", {"model": "gpt-4o", "input": "hi"})
    if b"HTTP/1.1 200" not in resp:
        print("FAIL: model_normalized: request did not complete: {!r}".format(resp[:200]))
        return False
    sent_model = _FakeHTTPSConnection.captured[-1]["body"].get("model")
    if sent_model != "gpt4o":
        print("FAIL: model_normalized: forwarded model was {!r}, want 'gpt4o'".format(sent_model))
        return False
    print("PASS: /responses normalizes 'gpt-4o' -> 'gpt4o' via the alias map")
    return True


def _check_no_user_field(port):
    """/responses gets no `user` field; /chat/completions still does (regression guard)."""
    ok = True
    _FakeHTTPSConnection.captured.clear()
    resp = _post(port, "/v1/responses", {"model": "gpt4o", "input": "hi"})
    if b"HTTP/1.1 200" not in resp:
        print("FAIL: no_user_field: /responses did not complete: {!r}".format(resp[:200]))
        ok = False
    elif "user" in _FakeHTTPSConnection.captured[-1]["body"]:
        print("FAIL: /responses body gained a 'user' field it doesn't need: {!r}".format(
            _FakeHTTPSConnection.captured[-1]["body"]))
        ok = False

    _FakeHTTPSConnection.captured.clear()
    resp = _post(port, "/v1/chat/completions", {"model": "gpt4o", "messages": []})
    if b"HTTP/1.1 200" not in resp:
        print("FAIL: no_user_field: /chat/completions did not complete: {!r}".format(resp[:200]))
        ok = False
    elif "user" not in _FakeHTTPSConnection.captured[-1]["body"]:
        print("FAIL: /chat/completions lost its 'user' injection (regression)")
        ok = False

    if ok:
        print("PASS: /responses gets no 'user' field; /chat/completions still does")
    return ok


def main():
    real_conn_cls = shim.http.client.HTTPSConnection
    shim.http.client.HTTPSConnection = _FakeHTTPSConnection
    srv = _serve(PORT)
    results = []

    try:
        results.append(_check_bearer_added(PORT))
        results.append(_check_client_bearer_not_forwarded(PORT))
        results.append(_check_other_paths_no_bearer(PORT))
        results.append(_check_model_normalized(PORT))
        results.append(_check_no_user_field(PORT))
    finally:
        shim.http.client.HTTPSConnection = real_conn_cls
        srv.shutdown()
        srv.server_close()

    print("{}/{} checks passed".format(sum(results), len(results)))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
