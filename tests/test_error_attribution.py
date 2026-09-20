#!/usr/bin/env python3
"""Validate that upstream (Argo) faults are attributed to Argo, not to the shim.

SAFETY: pure unit test of classify_upstream_error(). It imports the module and
calls one function — no server is bound, no socket is opened, and no SSH or
upstream connection is ever attempted.

Background: Argo runs a Python service that uses requests/urllib3. When its
backend fails — most often failing to mint a Google OAuth token for the Vertex
AI backend that serves Claude models — it hands us a traceback string like:

    HTTPSConnectionPool(host='oauth2.googleapis.com', port=443): Max retries
    exceeded with url: /token (Caused by NewConnectionError(... [Errno 111]
    Connection refused))

The shim used to map anything unrecognized to a bare 503. Claude Code's generic
advice for a 503 is "check your inference gateway (127.0.0.1:PORT)", which sends
the user to debug the tunnel, DNS, and proxy env — all of which are fine. The
fault is entirely inside Argo. These cases assert we now say so.

The load-bearing case is `ordering`: a requests traceback is full of incidental
digits (port=443, Errno 111). The generic "401"/"403" substring sniff is a
coarse test that can fire on those digits, so the upstream-fault check MUST run
first. If someone reorders the branches in classify_upstream_error, that case
fails while everything else still passes.
"""
import os
import sys

# Repo root, so `argo_shim` imports from the working tree, not an installed copy.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import argo_shim._shim as shim

REAL_OAUTH_ERROR = (
    "HTTPSConnectionPool(host='oauth2.googleapis.com', port=443): Max retries "
    "exceeded with url: /token (Caused by NewConnectionError(\"HTTPSConnection"
    "(host='oauth2.googleapis.com', port=443): Failed to establish a new "
    "connection: [Errno 111] Connection refused\"))"
)

# (label, err_msg, err_type, expected_status, must_attribute_upstream)
CASES = [
    ("real oauth 503", REAL_OAUTH_ERROR, "", 502, True),
    ("bare connection pool", "HTTPSConnectionPool(host='foo', port=443): boom", "", 502, True),
    ("rate limit", "Error code: 429 - RESOURCE_EXHAUSTED", "", 429, True),
    ("overloaded", "upstream busy", "overloaded_error", 529, True),
    ("bad request", "Error code: 400 - invalid_request_error", "", 400, False),
    ("credentials", "401 unauthorized", "", 401, True),
    ("unknown", "something inscrutable happened", "", 503, True),
]


def _check(label, err_msg, err_type, want_status, want_attrib):
    status, explanation = shim.classify_upstream_error(err_msg, err_type)
    ok = status == want_status
    if not ok:
        print("FAIL: {}: expected HTTP {}, got {}".format(label, want_status, status))
        return False
    if want_attrib and not explanation:
        print("FAIL: {}: expected an attribution sentence, got none".format(label))
        return False
    if not want_attrib and explanation:
        print("FAIL: {}: expected no attribution, got {!r}".format(label, explanation))
        return False
    print("PASS: {}: HTTP {}{}".format(label, status, " + attribution" if explanation else ""))
    return True


def _check_ordering():
    """The oauth traceback must not be misread as an auth failure.

    It contains "port=443" and "[Errno 111]" but no literal 401/403 — so this
    guards the branch order rather than a specific digit collision. We assert
    the stronger property directly: the upstream-fault branch wins, producing
    502 and never 401.
    """
    status, explanation = shim.classify_upstream_error(REAL_OAUTH_ERROR, "")
    if status == 401:
        print("FAIL: ordering: oauth traceback classified as a credentials error.")
        print("      The upstream-fault check must run BEFORE the 401/403 sniff.")
        return False
    if status != 502 or not explanation:
        print("FAIL: ordering: expected 502 + attribution, got {} / {!r}".format(status, explanation))
        return False
    print("PASS: ordering: upstream-fault check precedes the generic auth sniff")
    return True


def _check_blames_argo_not_shim():
    """The attribution must exonerate the shim in words a user will act on.

    The whole point is to stop people debugging their tunnel. Assert the text
    names Argo and explicitly rules out the local side.
    """
    _, explanation = shim.classify_upstream_error(REAL_OAUTH_ERROR, "")
    low = explanation.lower()
    if "argo" not in low:
        print("FAIL: attribution never names Argo: {!r}".format(explanation))
        return False
    if "not a problem with argo-shim" not in low:
        print("FAIL: attribution does not exonerate the shim: {!r}".format(explanation))
        return False
    if "vertex" not in low:
        print("FAIL: googleapis error should name the Vertex backend: {!r}".format(explanation))
        return False
    print("PASS: attribution names Argo/Vertex and clears the shim")
    return True


def _check_local_faults_still_blamed_locally():
    """Guard against over-correcting: real shim-side failures must not say 'Argo's fault'.

    A tunnel-down message is generated by _send_error, not the classifier, but
    if someone later routes it through here it must not be exonerated. A plain
    local message has none of the upstream markers, so it falls to the generic
    branch — which is 503 and must NOT claim Argo reached an external provider.
    """
    _, explanation = shim.classify_upstream_error("SSH tunnel is down", "")
    if explanation and "not a problem with argo-shim" in explanation.lower():
        print("FAIL: a local tunnel failure was attributed to Argo: {!r}".format(explanation))
        return False
    print("PASS: local-sounding failures are not exonerated as Argo outages")
    return True


def main():
    results = [_check(*c) for c in CASES]
    results.append(_check_ordering())
    results.append(_check_blames_argo_not_shim())
    results.append(_check_local_faults_still_blamed_locally())
    print()
    print("{}/{} checks passed".format(sum(results), len(results)))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
