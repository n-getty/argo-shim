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
     the user hand-wrote (block, flow, or quoted — all the same key to YAML),
     a file with only one of the two markers, or a `providers:` key we can't
     splice into because it carries a trailing comment or uses flow style.
     Appending past one of those would duplicate the root key. The refusals
     are narrow on purpose, so a companion test checks the safe shapes — a
     plain `providers:`, a top-level `argo:`, no providers key, empty — still
     splice.
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
  7. models.yml is created 0600 and leaves no temp file behind — it holds the
     shim's bearer token and argo-shim runs on shared login nodes.
  8. Reading and writing pin encoding="utf-8". The markers contain an em-dash,
     so under a non-UTF-8 locale the locale default would raise a
     UnicodeEncodeError/UnicodeDecodeError — a ValueError, which main()'s
     handler doesn't catch, so it would abort shim startup with a traceback.
     (Separately, the "✓" glyphs every writer in _shim.py prints still crash
     under such a locale. That is pre-existing and repo-wide, not specific to
     the pi writer, so it is out of scope here.)

Run: python3 tests/test_pi_config.py
"""
import inspect
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
    # encoding="utf-8" explicitly, like the writer: the marker comments carry
    # an em-dash, so a locale-default open() would fail this suite under a
    # non-UTF-8 LC_ALL rather than exercising the code under test.
    with open(os.path.join(tmpdir, "models.yml"), encoding="utf-8") as f:
        return f.read()


def seed(tmpdir, text):
    """Write a starting models.yml for the writer to merge into."""
    path = os.path.join(tmpdir, "models.yml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


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
        seed(tmp, text)

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
        # Every one of these would, if spliced, leave the file with two `argo:`
        # keys or two `providers:` keys. YAML keeps only one of a duplicate
        # pair, so pi would silently drop providers — a wrong write is worse
        # than no write. Each case must refuse AND leave the bytes alone.
        #
        # The `argo:` variants below are all the same key to a YAML parser;
        # matching only the block form would let the flow and quoted spellings
        # through. Likewise `providers:` is only spliceable as a bare key on
        # its own line — with a trailing comment or in flow style there is no
        # line to insert after, and appending our own would duplicate the root.
        # That one is sticky: the next run finds its markers and updates in
        # place, so the duplicate root would survive forever.
        corrupting = [
            ("an unmanaged argo: provider",
             "providers:\n  argo:\n    baseUrl: http://mine\n"),
            ("a flow-style argo: provider",
             "providers:\n  argo: {baseUrl: http://mine}\n"),
            ("a quoted argo: key",
             'providers:\n  "argo":\n    baseUrl: http://mine\n'),
            ("a file with only a BEGIN marker",
             "providers:\n" + shim.PI_BEGIN + "\n  argo:\n    baseUrl: x\n"),
            ("a file with only an END marker",
             "providers:\n  ollama:\n    baseUrl: x\n" + shim.PI_END + "\n"),
            ("providers: with a trailing comment",
             "providers:  # my stuff\n  ollama:\n    baseUrl: http://localhost:11434\n"),
            ("flow-style providers:",
             "providers: {ollama: {baseUrl: http://localhost:11434}}\n"),
            ("a quoted providers: key",
             '"providers":\n  ollama:\n    baseUrl: http://localhost:11434\n'),
        ]
        for label, content in corrupting:
            seed(tmp, content)
            check("refuses " + label, write(tmp), False)
            check("  left it byte-for-byte unchanged", read(tmp), content)
    finally:
        shutil.rmtree(tmp)


def test_splices_valid_shapes():
    print("\n2b. still splices the shapes that ARE safe")
    # The refusals above are narrow on purpose: tightening them must not start
    # rejecting ordinary files. In particular a top-level `argo:` (not nested
    # under providers:) is a different key from a provider named argo, and an
    # indent pattern matching newlines would refuse it by mistake.
    safe = [
        ("bare providers: with a sibling",
         "providers:\n  ollama:\n    baseUrl: http://localhost:11434\n"),
        ("a top-level argo: key after a blank line",
         "\nargo:\n  baseUrl: http://not-a-provider\n"),
        ("a file with no providers: key at all", "someOtherKey: 1\n"),
        ("an empty file", ""),
    ]
    for label, content in safe:
        tmp = tempfile.mkdtemp()
        try:
            seed(tmp, content)
            check("splices into " + label, write(tmp), True)
            after = read(tmp)
            check("  exactly one argo: provider key",
                  sum(1 for ln in after.splitlines() if ln == "  argo:"), 1)
            check("  exactly one providers: root",
                  sum(1 for ln in after.splitlines()
                      if ln.rstrip() == "providers:"), 1)
        finally:
            shutil.rmtree(tmp)


def test_routing_and_quoting():
    print("\n3. per-model routing, embedding exclusion, YAML quoting")
    entries = shim.build_pi_models(FAKE_MODELS)
    by_id = {e["id"]: e for e in entries}

    check("embeddings dropped (5 of 7 kept)", len(entries), 5)
    check("v3small excluded", "v3small" in by_id, False)
    check("ada002 excluded", "ada002" in by_id, False)
    # The word "embedding" is matched against internal_id as well as the
    # display id. A future embedding model not on the hardcoded id list, whose
    # display name omits the word the way v3small/ada002 already do, would
    # otherwise reach pi as a chat model that 404s on first use.
    future = shim.build_pi_models([
        {"id": "Nomic v2", "owned_by": "openai", "internal_id": "nomicembedding2"}])
    check("embedding detected via internal_id alone", future, [])
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


def test_token_file_is_not_world_readable():
    print("\n5. the file holding the auth token is written 0600")
    # models.yml carries the shim's bearer token, and argo-shim runs on shared
    # ALCF login nodes where the default umask leaves new files world-readable.
    # os.replace preserves the temp file's mode, so the mode has to be set at
    # creation rather than fixed up afterwards.
    tmp = tempfile.mkdtemp()
    try:
        check("write succeeds", write(tmp), True)
        mode = os.stat(os.path.join(tmp, "models.yml")).st_mode & 0o777
        check("mode is 0600", oct(mode), oct(0o600))
        check("no temp file left behind",
              [f for f in os.listdir(tmp) if f.endswith(".tmp")], [])
    finally:
        shutil.rmtree(tmp)


def test_non_ascii_content_and_pinned_encoding():
    print("\n6. non-ASCII content round-trips; file IO pins encoding=utf-8")
    tmp = tempfile.mkdtemp()
    try:
        seed(tmp, "providers:\n  # café — my notes\n  ollama:\n    baseUrl: x\n")
        check("write succeeds over a non-ASCII file", write(tmp), True)
        after = read(tmp)
        check("the accented comment survived", "café — my notes" in after, True)
        check("the em-dash marker round-tripped", shim.PI_BEGIN.strip() in after, True)
        # Bytes on disk, not str: proves the encoding is UTF-8 rather than
        # whatever the ambient locale happens to be.
        with open(os.path.join(tmp, "models.yml"), "rb") as f:
            check("em-dash is stored as UTF-8 bytes",
                  b"\xe2\x80\x94" in f.read(), True)

        # The checks above pass under a UTF-8 locale even if the writer used a
        # locale-default open(), because there the two agree. The failure only
        # appears under e.g. LC_ALL=en_US.iso88591, where the em-dash in the
        # markers raises UnicodeEncodeError on write (and an accented user
        # comment raises UnicodeDecodeError on read) — both ValueError, which
        # main()'s handler doesn't catch, so shim startup dies with a
        # traceback instead of degrading. A test process can't change its own
        # locale after startup, so assert on the source instead; this guard
        # holds under every locale.
        #
        # Running this suite under LC_ALL=en_US.iso88591 does NOT exercise it
        # end to end today: it stops earlier, on the "✓"/"✗" glyphs in the
        # progress prints, which is a pre-existing repo-wide issue (the same
        # crash hits update_claude_settings on main) and not this writer's to
        # fix. Should stdout ever be pinned to UTF-8 at startup, drop this
        # source assertion for a real non-UTF-8 locale run.
        src = inspect.getsource(shim.update_pi_settings)
        opens = [ln.strip() for ln in src.splitlines()
                 if ("open(PI_CONFIG" in ln or "os.fdopen(" in ln)]
        check("both file opens found", len(opens), 2)
        check("every file open pins encoding=utf-8",
              [ln for ln in opens if 'encoding="utf-8"' not in ln], [])
    finally:
        shutil.rmtree(tmp)


def main():
    saved = shim.PI_CONFIG
    try:
        test_create_and_preserve()
        test_refuses_corrupting_merges()
        test_splices_valid_shapes()
        test_routing_and_quoting()
        test_fetch_failure_leaves_file_alone()
        test_token_file_is_not_world_readable()
        test_non_ascii_content_and_pinned_encoding()
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
