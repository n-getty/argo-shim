"""Stop pytest from collecting these scripts.

`tests/test_*.py` is exactly pytest's discovery pattern, but nothing here is a
pytest test: each script is a standalone program with a main() and its own
prerequisites (a running shim, lsof/ps, several minutes of wall clock). Bare
`pytest` would collect them, find no test functions, and report success while
having verified nothing — or, for the black-box scripts, sit through a 5½
minute timeout first.

Failing at collection with a pointer to the README is more useful than either.
"""
import pytest


def pytest_configure(config):
    # Bail at configure time, before collection imports anything. pytest.exit
    # (not SystemExit) is what pytest expects from a hook: it exits non-zero
    # with a bare message, no INTERNALERROR traceback and no collection-error
    # framing around the explanation.
    pytest.exit(
        "tests/ holds standalone scripts, not pytest tests — see tests/README.md.\n"
        "Run them directly, e.g.:\n"
        "    python3 tests/test_401_body_drain.py\n"
        "    python3 tests/test_idle_reaping.py [port]",
        returncode=2,
    )
