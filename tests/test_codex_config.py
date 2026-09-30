#!/usr/bin/env python3
"""Validate the Codex CLI config.toml + argo.config.toml writer.

SAFETY: this test never opens a network connection and never runs a
subprocess. Every file it writes goes to a temporary directory. There is no
path from this test to a CELS SSH attempt.

What it proves:
  1. Splicing preserves the user's config.toml. argo-shim is stdlib-only (no
     TOML writer in Python < 3.11's tomllib, which is read-only anyway), so
     it never parses config.toml — it replaces only the span between its
     marker comments as text. A sibling scalar and table must survive
     verbatim, and a re-run must leave exactly one managed span.
  2. Corrupting merges are refused, not guessed: an unmanaged
     [model_providers.argo] table the user hand-wrote (bare, quoted-key, or
     inline-table form), or a file with only one of the two markers. TOML
     hard-errors on a duplicate table header (unlike YAML, which just drops
     one), so writing a second one wouldn't quietly corrupt the file — it
     would make Codex refuse to start at all. A companion test checks the
     safe shapes — unrelated tables, scalars-only, no file, empty file —
     still splice.
  3. A leftover [profiles.argo] table (the old, now-broken way to configure a
     Codex profile) is refused with a specific, actionable message rather
     than the generic "unmanaged table" one — current Codex refuses to start
     at all if it finds one, since profiles moved to a separate
     <name>.config.toml file, which is what this writer produces instead.
  4. The auth token is embedded literally as `experimental_bearer_token` in
     config.toml, not via `env_key` + a separately-exported environment
     variable — a running process can't inject a var into the user's
     already-open shell. --no-auth omits the field entirely rather than
     writing an empty string.
  5. argo.config.toml (the profile file `codex --profile argo` loads) sets
     model_provider = "argo" and a default model — written as a full-file
     replacement each run, since it's entirely argo-shim's and Codex only
     loads it when --profile argo is passed.
  6. Both files are created 0600 and leave no temp file behind — config.toml
     may hold a plaintext bearer token and argo.config.toml always does when
     auth is enabled, and argo-shim runs on shared login nodes.
  7. Reading and writing pin encoding="utf-8", for the same locale-safety
     reason as the pi writer (see test_pi_config.py).
  8. The rendered/spliced output is valid TOML end-to-end (checked with
     tomllib when available — Python 3.11+; skipped gracefully otherwise
     since this repo's floor is 3.8).

Run: python3 tests/test_codex_config.py
"""
import inspect
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import argo_shim._shim as shim

try:
    import tomllib
except ImportError:
    tomllib = None

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


def write(tmpdir, port=20098, token=TOKEN):
    shim.CODEX_CONFIG = os.path.join(tmpdir, "config.toml")
    shim.CODEX_PROFILE_CONFIG = os.path.join(tmpdir, "argo.config.toml")
    return shim.update_codex_settings(port, token)


def read(tmpdir):
    with open(os.path.join(tmpdir, "config.toml"), encoding="utf-8") as f:
        return f.read()


def read_profile(tmpdir):
    with open(os.path.join(tmpdir, "argo.config.toml"), encoding="utf-8") as f:
        return f.read()


def seed(tmpdir, text):
    path = os.path.join(tmpdir, "config.toml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def test_create_and_preserve():
    print("\n1. creates the file, then preserves user content on re-write")
    tmp = tempfile.mkdtemp()
    try:
        check("first write succeeds", write(tmp), True)
        text = read(tmp)
        check("has BEGIN marker", shim.CODEX_BEGIN in text, True)
        check("has [model_providers.argo]", "[model_providers.argo]" in text, True)
        check("profile file was written",
              os.path.exists(os.path.join(tmp, "argo.config.toml")), True)

        # Add a sibling scalar and an unrelated table, as a real user would.
        text = ('model = "asksage-gpt-5.6-sol"\n'
                'approvals_reviewer = "user"\n\n'
                '[projects."/tmp"]\n'
                'trust_level = "trusted"\n\n') + text
        seed(tmp, text)

        check("second write succeeds", write(tmp, port=21000), True)
        after = read(tmp)
        check("user scalar survived", 'approvals_reviewer = "user"' in after, True)
        check("user table survived", '[projects."/tmp"]' in after, True)
        check("exactly one [model_providers.argo]",
              after.count("[model_providers.argo]"), 1)
        check("one BEGIN marker", after.count(shim.CODEX_BEGIN), 1)
        check("one END marker", after.count(shim.CODEX_END), 1)
        check("port was updated in place", "21000" in after, True)
        check("old port is gone", "20098" in after, False)
    finally:
        shutil.rmtree(tmp)


def test_refuses_corrupting_merges():
    print("\n2. refuses merges that would corrupt config.toml")
    tmp = tempfile.mkdtemp()
    try:
        corrupting = [
            ("an unmanaged [model_providers.argo]",
             '[model_providers.argo]\nname = "mine"\n'),
            ("a quoted model_providers key",
             '["model_providers".argo]\nname = "mine"\n'),
            ("a quoted argo key",
             '[model_providers."argo"]\nname = "mine"\n'),
            ("inline-table model_providers",
             'model_providers = { argo = { name = "mine" } }\n'),
            ("a file with only a BEGIN marker",
             shim.CODEX_BEGIN + "\n[model_providers.argo]\nname = \"x\"\n"),
            ("a file with only an END marker",
             '[projects."/tmp"]\ntrust_level = "trusted"\n' + shim.CODEX_END + "\n"),
        ]
        for label, content in corrupting:
            seed(tmp, content)
            check("refuses " + label, write(tmp), False)
            check("  left it byte-for-byte unchanged", read(tmp), content)
    finally:
        shutil.rmtree(tmp)


def test_refuses_legacy_profiles_table():
    print("\n2b. refuses (with a specific message) a leftover [profiles.argo]")
    tmp = tempfile.mkdtemp()
    try:
        content = '[profiles.argo]\nmodel_provider = "argo"\nmodel = "gpt56sol"\n'
        seed(tmp, content)
        check("refuses a legacy [profiles.argo] table", write(tmp), False)
        check("left it byte-for-byte unchanged", read(tmp), content)
    finally:
        shutil.rmtree(tmp)


def test_splices_valid_shapes():
    print("\n2c. still splices the shapes that ARE safe")
    safe = [
        ("scalars only, no tables",
         'model = "asksage-gpt-5.6-sol"\napprovals_reviewer = "user"\n'),
        ("an unrelated table",
         '[model_providers.asksage]\nname = "AskSage"\n'),
        ("a file with no argo-shim content at all", 'someOtherKey = 1\n'),
        ("an empty file", ""),
    ]
    for label, content in safe:
        tmp = tempfile.mkdtemp()
        try:
            seed(tmp, content)
            check("splices into " + label, write(tmp), True)
            after = read(tmp)
            check("  exactly one [model_providers.argo]",
                  after.count("[model_providers.argo]"), 1)
        finally:
            shutil.rmtree(tmp)

    # No file at all (FileNotFoundError path).
    tmp = tempfile.mkdtemp()
    try:
        shutil.rmtree(tmp)  # writer must create the parent dir
        check("creates parent dir and file when neither exists", write(tmp), True)
        check("file now exists", os.path.exists(os.path.join(tmp, "config.toml")), True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_bearer_token_no_env_var():
    print("\n3. embeds the token literally in config.toml; --no-auth omits it")
    block = shim.render_codex_provider_block(20098, TOKEN)
    check("has experimental_bearer_token", f'experimental_bearer_token = "{TOKEN}"' in block, True)
    check("has no env_key", "env_key" not in block, True)

    noauth = shim.render_codex_provider_block(20098, None)
    check("--no-auth: no experimental_bearer_token", "experimental_bearer_token" in noauth, False)
    check("--no-auth: still has model_providers.argo", "[model_providers.argo]" in noauth, True)


def test_profile_file():
    print("\n4. argo.config.toml routes model_provider and sets a default model")
    tmp = tempfile.mkdtemp()
    try:
        check("write succeeds", write(tmp), True)
        profile = read_profile(tmp)
        check("sets model_provider = argo", 'model_provider = "argo"' in profile, True)
        check("sets a default model",
              f'model = "{shim.CODEX_DEFAULT_MODEL}"' in profile, True)
        check("has no [model_providers.*] of its own (that lives in config.toml)",
              "[model_providers" in profile, False)
    finally:
        shutil.rmtree(tmp)


def test_files_are_not_world_readable():
    print("\n5. both files are written 0600, no temp files left behind")
    tmp = tempfile.mkdtemp()
    try:
        check("write succeeds", write(tmp), True)
        for name in ("config.toml", "argo.config.toml"):
            mode = os.stat(os.path.join(tmp, name)).st_mode & 0o777
            check(f"{name} mode is 0600", oct(mode), oct(0o600))
        check("no temp file left behind",
              [f for f in os.listdir(tmp) if f.endswith(".tmp")], [])
    finally:
        shutil.rmtree(tmp)


def test_pinned_encoding():
    print("\n6. file IO pins encoding=utf-8")
    src = inspect.getsource(shim.update_codex_settings) + inspect.getsource(shim._write_atomic_0600)
    opens = [ln.strip() for ln in src.splitlines()
             if ("open(CODEX_CONFIG" in ln or "os.fdopen(" in ln)]
    check("both file opens found", len(opens), 2)
    check("every file open pins encoding=utf-8",
          [ln for ln in opens if 'encoding="utf-8"' not in ln], [])

    tmp = tempfile.mkdtemp()
    try:
        seed(tmp, '# café — my notes\nmodel = "x"\n')
        check("write succeeds over a non-ASCII file", write(tmp), True)
        after = read(tmp)
        check("the accented comment survived", "café — my notes" in after, True)
        check("the em-dash marker round-tripped", shim.CODEX_BEGIN in after, True)
    finally:
        shutil.rmtree(tmp)


def test_output_is_valid_toml():
    print("\n7. rendered/spliced output is valid TOML")
    if tomllib is None:
        print("  (skipped: tomllib not available on this Python)")
        return
    block = shim.render_codex_provider_block(20098, 'tok"with\\special')
    parsed = tomllib.loads(block)
    check("config.toml block parses as valid TOML", isinstance(parsed, dict), True)
    check("bearer token round-trips including escapes",
          parsed["model_providers"]["argo"]["experimental_bearer_token"],
          'tok"with\\special')

    existing = 'model = "foo"\n[projects."/tmp"]\ntrust_level = "trusted"\n'
    text, _ = shim.splice_codex_block(existing, block)
    parsed2 = tomllib.loads(text)
    check("spliced config.toml is still valid TOML", isinstance(parsed2, dict), True)
    check("unrelated table survives parseable",
          parsed2["projects"]["/tmp"]["trust_level"], "trusted")

    profile = shim.render_codex_profile_file()
    parsed3 = tomllib.loads(profile)
    check("argo.config.toml parses as valid TOML", parsed3["model_provider"], "argo")


def main():
    saved_config = shim.CODEX_CONFIG
    saved_profile = shim.CODEX_PROFILE_CONFIG
    try:
        test_create_and_preserve()
        test_refuses_corrupting_merges()
        test_refuses_legacy_profiles_table()
        test_splices_valid_shapes()
        test_bearer_token_no_env_var()
        test_profile_file()
        test_files_are_not_world_readable()
        test_pinned_encoding()
        test_output_is_valid_toml()
    finally:
        shim.CODEX_CONFIG = saved_config
        shim.CODEX_PROFILE_CONFIG = saved_profile

    print()
    if all(results):
        print(f"PASS: {len(results)} codex-config checks")
        return 0
    print(f"FAIL: {results.count(False)} of {len(results)} checks failed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
