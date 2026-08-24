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
  4. The smoke-test command is not BatchMode and jumps to the interior host.
     CELS requires a second factor after the key is accepted, so a BatchMode
     check can never pass and must not be presented as the success criterion.
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

    # 4. smoke-test command shape
    cmd = shim._smoke_test_command()
    results.append(check("smoke test is not BatchMode", "BatchMode" in cmd, False))
    results.append(check("smoke test jumps to interior host", " -J " in cmd, True))
    print(f"      command: {cmd}")

    print()
    if all(results):
        print("PASS: all key-discovery checks")
        return 0
    print("FAIL: see above")
    return 1


if __name__ == "__main__":
    sys.exit(main())
