# tests

Standalone scripts, run by hand from the repo root. There is no pytest setup
and no test job in CI (`publish.yml` only builds and releases), so nothing here
runs automatically — run the relevant script when you touch the code it covers.

```bash
python3 tests/test_idle_reaping.py       # takes ~5½ min (waits out a 305s timeout)
./tests/test_stream_500.sh               # needs a running shim
```

Each script exits non-zero on failure and prints what it checked.

## Two kinds of test here

**Black-box** — talk to a *running* shim over the network, and read port and
token from `~/.claude/settings.json`: `test_idle_reaping.py`,
`test_stream_500.sh`. These need a shim up first.

**In-process** — import `argo_shim._shim` and drive it directly, with no shim
running and no network. They put the repo root on `sys.path` so the import
comes from the working tree rather than an installed copy:

```python
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
```

## Conventions

Open with a **SAFETY** docstring stating what the test can and cannot reach —
specifically whether any path leads to a real CELS SSH attempt. Failed logins
push the shared login-node IP toward a CSPO block, so a test must never risk
one; say plainly why it can't. Prefer the auth-gate or a throwaway local socket
so the network path is unreachable by construction.

A regression test should **fail on the commit before the fix**. Check that
before submitting — a test that passes either way documents nothing. Worth
recording the before/after output in the PR.
