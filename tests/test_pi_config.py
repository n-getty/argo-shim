#!/usr/bin/env python3
"""Validate the pi (omp.sh) models.yml writer.

SAFETY: this test never opens a network connection and never runs a
subprocess. The only functions that touch the network — fetch_argo_models and
fetch_argo_models_via_shim — are stubbed with a canned model list, and every
file it writes goes to a temporary directory. There is no path from this test
to a CELS SSH attempt.

What it proves:
  1. Splicing preserves the user's file. argo-shim is stdlib-only (no PyYAML),
     so it never parses models.yml — it replaces only the span between its
     marker comments as text. A sibling provider and a comment must survive
     verbatim, and a re-run must leave exactly one `argo:` key. Duplicate keys
     would make pi drop every custom provider, so "wrote it twice" is not a
     cosmetic failure.
  2. Corrupting merges are refused, not guessed: an unmanaged `argo:` provider
     the user hand-wrote, or a file with only one of the two markers.
  3. Claude models route to anthropic-messages and everything else to
     openai-completions, because pi picks the wire format per model and the
     shim serves both. Embedding models are dropped — they have no chat
     endpoint and pi would list them as broken chat models.
  4. Model ids and display names are quoted. Argo names contain spaces and
     dots ("GPT-5.6 Sol"); emitted bare they are not valid YAML scalars.
  5. --no-auth emits `auth: none` rather than an apiKey, so pi suppresses the
     bogus `Authorization: Bearer N/A` the keyless path would otherwise send.
     `disableStrictTools: true` is always emitted — verified load-bearing by
     removing it against a real pi install, which fails the first Claude tool
     call with HTTP 400 FAILED_PRECONDITION (a Vertex org policy rejects the
     `structured_outputs` feature for partner Claude models).
  6. A failed model fetch leaves the file untouched instead of writing an
     empty or guessed catalog (pi treats empty `models` as a config error).

Run: python3 tests/test_pi_config.py
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import argo_shim._shim as shim

# Shaped like the real GET /argoapi/v1/models payload: a display `id` that
# differs from `internal_id` by case and punctuation, plus owned_by, plus the
# embedding entries that must not reach a chat client.
FAKE_MODELS = [
    {"id": "GPT-4o", "owned_by": "openai", "internal_id": "gpt4o"},
    {"id": "GPT-5.6 Sol", "owned_by": "openai", "internal_id": "gpt56sol"},
    {"id": "Gemini 2.5 Pro", "owned_by": "google", "internal_id": "gemini25pro"},
    {"id": "Claude Opus 5", "owned_by": "anthropic", "internal_id": "claudeopus5"},
    {"id": "Claude Sonnet 5", "owned_by": "anthropic", "internal_id": "claudesonnet5"},
    {"id": "Text Embedding 3 Small", "owned_by": "openai", "internal_id": "v3small"},
    {"id": "Text Embedding Ada 002", "owned_by": "openai", "internal_id": "ada002"},
]

TOKEN = "test-token-not-a-real-secret"

results = []


def check(label, got, want):
    ok = got == want
    results.append(ok)
    print(f"  [{'ok' if ok else 'XX'}] {label}")
    if not ok:
        print(f"         got:  {got!r}")
        print(f"         want: {want!r}")
    return ok


def write(tmpdir, port=20098, token=TOKEN, models=FAKE_MODELS):
    """Run the writer against tmpdir with the network stubbed out."""
    shim.PI_CONFIG = os.path.join(tmpdir, "models.yml")
    real = shim.fetch_argo_models_via_shim

    def fake(listen_port, auth_token):
        if models is None:
            raise RuntimeError("simulated fetch failure")
        return models

    shim.fetch_argo_models_via_shim = fake
    try:
        return shim.update_pi_settings(port, token)
    finally:
        shim.fetch_argo_models_via_shim = real


def read(tmpdir):
    with open(os.path.join(tmpdir, "models.yml")) as f:
        return f.read()


def test_create_and_preserve():
    print("\n1. creates the file, then preserves user content on re-write")
    tmp = tempfile.mkdtemp()
    try:
        check("first write succeeds", write(tmp), True)
        text = read(tmp)
        check("has a providers: root", text.startswith("providers:\n"), True)

        # Add a sibling provider and a comment, as a real user would.
        text = text.replace(
            "providers:\n",
            "providers:\n  # my own notes\n  ollama:\n    baseUrl: http://localhost:11434\n",
            1)
        with open(os.path.join(tmp, "models.yml"), "w") as f:
            f.write(text)

        check("second write succeeds", write(tmp, port=21000), True)
        after = read(tmp)
        check("user comment survived", "# my own notes" in after, True)
        check("user provider survived", "baseUrl: http://localhost:11434" in after, True)
        # The duplicate-key case: two `argo:` keys make pi discard ALL custom
        # providers, so this is the assertion that matters most here.
        check("exactly one argo: key",
              sum(1 for ln in after.splitlines() if ln == "  argo:"), 1)
        check("one BEGIN marker", after.count(shim.PI_BEGIN.strip()), 1)
        check("one END marker", after.count(shim.PI_END.strip()), 1)
        check("port was updated in place", "http://127.0.0.1:21000/v1" in after, True)
        check("old port is gone", "20098" in after, False)
    finally:
        shutil.rmtree(tmp)


def test_refuses_corrupting_merges():
    print("\n2. refuses merges that would corrupt the file")
    tmp = tempfile.mkdtemp()
    try:
        path = os.path.join(tmp, "models.yml")
        hand_written = "providers:\n  argo:\n    baseUrl: http://mine\n"
        with open(path, "w") as f:
            f.write(hand_written)
        check("refuses an unmanaged argo: provider", write(tmp), False)
        check("left it byte-for-byte unchanged", read(tmp), hand_written)

        stray = "providers:\n" + shim.PI_BEGIN + "\n  argo:\n    baseUrl: x\n"
        with open(path, "w") as f:
            f.write(stray)
        check("refuses a file with only a BEGIN marker", write(tmp), False)
        check("left it byte-for-byte unchanged", read(tmp), stray)
    finally:
        shutil.rmtree(tmp)


def test_routing_and_quoting():
    print("\n3. per-model routing, embedding exclusion, YAML quoting")
    entries = shim.build_pi_models(FAKE_MODELS)
    by_id = {e["id"]: e for e in entries}

    check("embeddings dropped (5 of 7 kept)", len(entries), 5)
    check("v3small excluded", "v3small" in by_id, False)
    check("ada002 excluded", "ada002" in by_id, False)
    check("Claude -> anthropic-messages",
          by_id["claudeopus5"]["api"], "anthropic-messages")
    check("Sonnet -> anthropic-messages",
          by_id["claudesonnet5"]["api"], "anthropic-messages")
    check("GPT -> openai-completions",
          by_id["gpt4o"]["api"], "openai-completions")
    check("Gemini -> openai-completions",
          by_id["gemini25pro"]["api"], "openai-completions")
    check("uses internal_id as the id Argo expects",
          by_id["gpt56sol"]["name"], "GPT-5.6 Sol")
    check("Claude gets a 200K window",
          by_id["claudeopus5"]["contextWindow"], 200000)

    block = shim.render_pi_block(20098, TOKEN, entries)
    # "GPT-5.6 Sol" bare would be invalid YAML; the space and dot need quoting.
    check("display names are quoted", 'name: "GPT-5.6 Sol"' in block, True)
    check("ids are quoted", 'id: "gpt56sol"' in block, True)
    check("emits authHeader for bearer auth", "authHeader: true" in block, True)
    check("emits disableStrictTools", "disableStrictTools: true" in block, True)
    check("baseUrl carries the /v1 suffix",
          "baseUrl: http://127.0.0.1:20098/v1" in block, True)

    noauth = shim.render_pi_block(20098, None, entries)
    check("--no-auth emits auth: none", "auth: none" in noauth, True)
    check("--no-auth emits no apiKey", "apiKey:" in noauth, False)


def test_fetch_failure_leaves_file_alone():
    print("\n4. a failed model fetch leaves the file unchanged")
    tmp = tempfile.mkdtemp()
    try:
        check("write succeeds first", write(tmp), True)
        before = read(tmp)
        check("refuses when the fetch fails", write(tmp, models=None), False)
        check("file is unchanged", read(tmp), before)

        empty = tempfile.mkdtemp()
        try:
            check("refuses when Argo returns no chat models",
                  write(empty, models=[{"id": "Text Embedding 3 Small",
                                        "owned_by": "openai",
                                        "internal_id": "v3small"}]), False)
            check("no file was created",
                  os.path.exists(os.path.join(empty, "models.yml")), False)
        finally:
            shutil.rmtree(empty)
    finally:
        shutil.rmtree(tmp)


def main():
    saved = shim.PI_CONFIG
    try:
        test_create_and_preserve()
        test_refuses_corrupting_merges()
        test_routing_and_quoting()
        test_fetch_failure_leaves_file_alone()
    finally:
        shim.PI_CONFIG = saved

    print()
    if all(results):
        print(f"PASS: {len(results)} pi-config checks")
        return 0
    print(f"FAIL: {results.count(False)} of {len(results)} checks failed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
