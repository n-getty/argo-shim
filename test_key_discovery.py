#!/usr/bin/env python3
"""Validate SSH key discovery and the setup guide's smoke-test command.

SAFETY: this test never opens a network connection. It points HOME at a
temporary directory and inspects the files there; the only subprocess it can
spawn is `ssh -G`, which parses config and exits without contacting a host.
There is no path from this test to a CELS SSH attempt.

What it proves:
  1. A key with a non-stock filename (e.g. cels-gce-id_ed25519) is found.
     Previously _local_key_files() probed only id_ed25519/id_ecdsa/id_rsa/
     id_dsa, so such a user was told "No SSH key found" while holding a
     working, CELS-registered key, and argo-shim refused to start.
  2. Public keys, known_hosts, config etc. are NOT mistaken for private keys.
  3. A genuinely empty ~/.ssh still reports no keys, so the first-time guide
     still fires for the new user it was written for.
  4. The smoke-test command mirrors create_tunnel's real invocation: same
     BatchMode, same -J through the login node, same destination host. A
     login-node-only check never exercises the ProxyJump path the tunnel uses.
  5. The smoke-test names API_KEY (the login create_tunnel uses), not
     ARGO_USER (which resolves separately, for HTTP `user` injection). Where
     the two differ, a smoke test naming ARGO_USER can pass for one account
     while the tunnel still fails for the other.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import argo_shim._shim as shim

STOCK = "id_ed25519"
CUSTOM = "cels-gce-id_ed25519"
BODY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"


def _mkssh(tmp, files):
    ssh_dir = os.path.join(tmp, ".ssh")
    os.makedirs(ssh_dir, exist_ok=True)
    for name, content in files.items():
        with open(os.path.join(ssh_dir, name), "w") as fh:
            fh.write(content)
        os.chmod(os.path.join(ssh_dir, name), 0o600)
    return ssh_dir


def _with_home(tmp, fn):
    old = os.environ.get("HOME")
    os.environ["HOME"] = tmp
    try:
        return fn()
    finally:
        if old is None:
            del os.environ["HOME"]
        else:
            os.environ["HOME"] = old


def check(label, got, want):
    ok = got == want
    print(f"{'PASS' if ok else 'FAIL'}: {label}")
    if not ok:
        print(f"      got:  {got}")
        print(f"      want: {want}")
    return ok


def main():
    results = []

    # 1. custom-named key is discovered (the mbph / non-stock-filename case)
    with tempfile.TemporaryDirectory() as tmp:
        _mkssh(tmp, {
            CUSTOM: BODY,
            CUSTOM + ".pub": "ssh-ed25519 AAAAC3Nz fake\n",
            "known_hosts": "example.com ssh-ed25519 AAAAC3Nz\n",
            "authorized_keys": "ssh-ed25519 AAAAC3Nz inbound\n",
        })
        found = _with_home(tmp, shim._local_key_files)
        names = sorted(os.path.basename(f) for f in found)
        results.append(check("custom-named key discovered", names, [CUSTOM]))

    # 2. stock key still discovered
    with tempfile.TemporaryDirectory() as tmp:
        _mkssh(tmp, {STOCK: BODY})
        found = _with_home(tmp, shim._local_key_files)
        names = sorted(os.path.basename(f) for f in found)
        results.append(check("stock-named key discovered", names, [STOCK]))

    # 3. empty ~/.ssh -> no keys, so the first-time guide still fires
    with tempfile.TemporaryDirectory() as tmp:
        _mkssh(tmp, {"known_hosts": "example.com ssh-ed25519 AAAAC3Nz\n"})
        found = _with_home(tmp, shim._local_key_files)
        stray = [f for f in found if f.startswith(tmp)]
        results.append(check("empty ~/.ssh reports no keys", stray, []))

    # 4. smoke-test command shape — must match what create_tunnel runs
    cmd = shim._smoke_test_command()
    results.append(check("smoke test jumps via the login node", " -J " in cmd, True))
    results.append(check("smoke test uses BatchMode, like the tunnel",
                         "BatchMode=yes" in cmd, True))
    results.append(check("smoke test targets the tunnel's host",
                         cmd.endswith(shim.SSH_JUMP_HOST), True))
    print(f"      command: {cmd}")

    # 4b. --host must be reflected, and no {smoke} placeholder may leak into
    # the error hints (they are import-time literals filled in at render).
    saved_host = shim.SSH_JUMP_HOST
    try:
        shim.SSH_JUMP_HOST = "compute-01.cels.anl.gov"
        hcmd = shim._smoke_test_command()
        results.append(check("--host is reflected in the smoke test",
                             hcmd.endswith("@compute-01.cels.anl.gov"), True))
        _, hint = shim._classify_ssh_error("Permission denied (publickey).")
        results.append(check("no {smoke} placeholder leaks into hints",
                             "{smoke}" in hint, False))
        results.append(check("hint carries the real command",
                             hcmd in hint, True))
        print(f"      with --host: {hcmd}")
    finally:
        shim.SSH_JUMP_HOST = saved_host

    # 5. smoke test must follow the SSH login, not the HTTP user
    import importlib
    saved = dict(os.environ)
    try:
        os.environ["CELS_USERNAME"] = "sshlogin"
        os.environ["ARGO_USER"] = "httpuser"
        reloaded = importlib.reload(shim)
        cmd2 = reloaded._smoke_test_command()
        results.append(check("smoke test uses the SSH login (API_KEY)",
                             "sshlogin@" in cmd2, True))
        results.append(check("smoke test ignores ARGO_USER",
                             "httpuser" in cmd2, False))
        print(f"      command: {cmd2}")
    finally:
        os.environ.clear()
        os.environ.update(saved)
        importlib.reload(shim)

    print()
    if all(results):
        print("PASS: all key-discovery checks")
        return 0
    print("FAIL: see above")
    return 1


if __name__ == "__main__":
    sys.exit(main())
