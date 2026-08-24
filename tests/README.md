# tests

Standalone scripts, run by hand from the repo root. There is no pytest setup
and no test job in CI (`publish.yml` only builds and releases), so nothing here
runs automatically — run the relevant script when you touch the code it covers.

Each script exits non-zero on failure and prints what it checked.

## Two kinds of test here

**Black-box** — drive a *running* shim over the network, so start one first.
They differ in how they find it, so read the header before running:

| script | finds the shim by | other requirements |
| ------ | ----------------- | ------------------ |
| `test_idle_reaping.py` | listen port from `argv[1]`, default `20098` | `lsof` and `ps` on PATH; takes ~5½ min (waits out the 305s `CONNECTION_IDLE_TIMEOUT`) |
| `test_stream_500.sh` | base URL and auth token from `~/.claude/settings.json` | `curl`, `python3` |

```bash
python3 tests/test_idle_reaping.py 20098
./tests/test_stream_500.sh
```

**In-process** — import `argo_shim._shim` and drive it directly, with no shim
running and no network. Put the repo root on `sys.path` so the import comes
from the working tree rather than an installed copy:

```python
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import argo_shim._shim as shim
```

## Conventions

Open with a **SAFETY** docstring stating what the test can and cannot reach —
specifically whether any path leads to a real CELS SSH attempt. Failed logins
push the shared login-node IP toward a CSPO block, so a test must never risk
one; say plainly why it can't. Prefer the auth gate or a throwaway local socket,
so the network path is unreachable by construction rather than merely unused.

A regression test should **fail on the commit before the fix**. Check that
before submitting — one that passes either way documents nothing. Worth
recording the before/after output in the PR.
