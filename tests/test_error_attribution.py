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

Branch order in classify_upstream_error is load-bearing in BOTH directions, and
two cases pin it from opposite sides:

  * `ordering` — the upstream-fault check must run BEFORE the 401/403 sniff.
    That sniff is a bare substring test, and a requests traceback is full of
    incidental digits: "port=8403" and "127.0.0.1:8401" both contain the
    characters it looks for, so an Argo connection failure would be reported
    as a credentials problem.

  * `specific_wins_over_marker` — the upstream-fault check must run AFTER the
    429/529/400 branches. Those are more specific than the marker sweep, not
    less, and Argo's retry loop stacks "Max retries exceeded" on top of a rate
    limit, so a 429 routinely arrives wearing a marker string. Sweeping it into
    a generic 502 tells a throttled caller to wait out an Argo outage, and
    turns a genuine 400 into advice to retry a request that cannot succeed.

Moving the marker branch in either direction fails one of those two while the
rest of the suite still passes.
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
    # A specific status wrapped in a retry traceback keeps its own status. Argo
    # emits exactly these shapes: the marker sweep must not swallow them.
    ("429 under retry noise",
     "HTTPSConnectionPool(host='apps.inside.anl.gov', port=443): Max retries exceeded "
     "with url: /argoapi/v1/messages (Caused by ResponseError('too many 429 error responses'))",
     "", 429, True),
    ("429 with pool noise",
     "Error code: 429 - RESOURCE_EXHAUSTED; Max retries exceeded", "", 429, True),
    ("overloaded under retry noise", "Max retries exceeded", "overloaded_error", 529, True),
    ("400 under pool noise",
     "Error code: 400 - invalid_request_error; HTTPSConnectionPool retry log attached",
     "", 400, False),
    ("400 by type under retry noise", "Max retries exceeded", "invalid_request_error", 400, False),
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
    """An Argo connection failure must not be misread as an auth failure.

    The marker check has to beat the 401/403 substring sniff. REAL_OAUTH_ERROR
    happens to contain no literal 401/403, so we also run a traceback whose
    port number does ("port=8403") — that is the collision the ordering exists
    to prevent, and asserting it directly keeps this case honest if the sample
    traceback is ever edited.
    """
    collision = ("HTTPSConnectionPool(host='apps.inside.anl.gov', port=8403): "
                 "Max retries exceeded (Caused by NewConnectionError('refused'))")
    status, _ = shim.classify_upstream_error(collision, "")
    if status != 502:
        print("FAIL: ordering: a traceback with 'port=8403' classified as {}.".format(status))
        print("      The upstream-fault check must run BEFORE the 401/403 sniff.")
        return False

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


def _check_specific_wins_over_marker():
    """The marker sweep must not swallow a status the error already states.

    This is the mirror of `ordering`. Argo's retry loop wraps a rate limit in
    "Max retries exceeded", so the marker branch, if it ran first, would report
    a throttled request as a generic Argo outage — telling the caller to wait
    rather than back off. The 400 case is worse still: a malformed request
    would be reported as transient and retryable forever.
    """
    throttled = ("HTTPSConnectionPool(host='apps.inside.anl.gov', port=443): Max retries "
                 "exceeded (Caused by ResponseError('too many 429 error responses'))")
    status, _ = shim.classify_upstream_error(throttled, "")
    if status != 429:
        print("FAIL: specific_wins_over_marker: a 429 wrapped in a retry traceback "
              "classified as {}.".format(status))
        print("      The 429/529/400 branches must run BEFORE the marker sweep.")
        return False

    status, _ = shim.classify_upstream_error("Max retries exceeded", "invalid_request_error")
    if status != 400:
        print("FAIL: specific_wins_over_marker: an invalid_request_error wrapped in a "
              "retry traceback classified as {}.".format(status))
        return False

    print("PASS: specific statuses survive being wrapped in a retry traceback")
    return True


def _check_local_faults_still_blamed_locally():
    """Guard against over-correcting: real shim-side failures must not say 'Argo's fault'.

    A tunnel-down message is generated by _send_error, not the classifier, but
    if someone later routes it through here it must not be exonerated. A plain
    local message has none of the upstream markers, so it falls to the generic
    branch — which is 503 and must not assert anything it has not established.

    Checking only for the marker branch's exact wording would be too weak: the
    fall-through could claim "the request failed upstream, not in the shim" and
    still pass. That sentence is an unwarranted exoneration on the one branch
    that by definition matched no fingerprint, so assert the absence of the
    claim, not the absence of one phrasing of it.
    """
    for probe in ("SSH tunnel is down", "connection reset by peer", ""):
        _, explanation = shim.classify_upstream_error(probe, "")
        low = (explanation or "").lower()
        if "not a problem with argo-shim" in low:
            print("FAIL: {!r} was attributed to Argo: {!r}".format(probe, explanation))
            return False
        if "not in the shim" in low or "not a shim problem" in low:
            print("FAIL: {!r} hit the unclassified branch but still cleared the "
                  "shim: {!r}".format(probe, explanation))
            print("      The fall-through matched no fingerprint; it cannot know that.")
            return False
    print("PASS: unclassified failures are not exonerated as Argo outages")
    return True


def main():
    results = [_check(*c) for c in CASES]
    results.append(_check_ordering())
    results.append(_check_specific_wins_over_marker())
    results.append(_check_blames_argo_not_shim())
    results.append(_check_local_faults_still_blamed_locally())
    print()
    print("{}/{} checks passed".format(sum(results), len(results)))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
