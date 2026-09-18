#!/usr/bin/env python3
"""Validate SSH key discovery and the setup guide's smoke-test command.

SAFETY: this test never opens a network connection. It points HOME at a
temporary directory and stubs out the one function that shells out, so no
subprocess runs at all. There is no path from this test to a CELS SSH attempt.

Why the stub, and not just HOME: `ssh -G` resolves `~` through getpwuid(), NOT
$HOME, so it reads the developer's real ~/.ssh no matter what we set. It also
evaluates `Match exec` blocks, meaning a developer's own config could run
commands here. The disk-scanning cases below therefore stub
_configured_identity_files to [] and test the two sources a temp HOME really
does control; source 1 is covered separately by _check_ssh_g_contract, which
asserts the parse without depending on any particular machine's config.

Without the stub these cases pass only by luck: ssh -G emits `~/.ssh/id_rsa`,
expanduser maps it into the temp HOME, and it happens not to exist there. A
config using an ABSOLUTE IdentityFile path — common in the multi-cluster setups
this change is for — survives expanduser and leaks a real key into the result,
failing the exact-equality assertions on a machine that is configured fine.

What it proves:
  1. A key with a non-stock filename (e.g. cels-gce-id_ed25519) is found.
     Previously _local_key_files() probed only id_ed25519/id_ecdsa/id_rsa/
     id_dsa, so such a user was told "No SSH key found" while holding a
     working, CELS-registered key, and argo-shim refused to start.
  2. Public keys, known_hosts, config etc. are NOT mistaken for private keys.
  3. A genuinely empty ~/.ssh still reports no keys, so the first-time guide
     still fires for the new user it was written for.
  4. The smoke-test command mirrors create_tunnel's real invocation: same
     BatchMode, same -J through the login node, same destination host, same
     ControlPath. A login-node-only check never exercises the ProxyJump path
     the tunnel uses, and a differing ControlPath would put the smoke test in
     a separate socket namespace from the tunnel it is supposed to predict.
  5. The smoke-test names API_KEY (the login create_tunnel uses), not
     ARGO_USER (which resolves separately, for HTTP `user` injection). Where
     the two differ, a smoke test naming ARGO_USER can pass for one account
     while the tunnel still fails for the other.
  6. ssh -G output parsing picks up identityfile lines and drops paths that do
     not exist, without shelling out.
"""
import os
import sys
import tempfile

# Repo root, so `argo_shim` imports from the working tree, not an installed copy.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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


def _disk_keys_only(tmp):
    """_local_key_files() with source 1 (ssh -G) stubbed out.

    ssh -G ignores $HOME (it uses getpwuid), so leaving it live would consult
    the developer's real ~/.ssh and can leak an absolute-path IdentityFile into
    these exact-equality assertions. Stubbing it also guarantees no subprocess
    runs. Sources 2 and 3 are the ones a temp HOME actually governs.
    """
    real = shim._configured_identity_files
    shim._configured_identity_files = lambda hosts: []
    try:
        return _with_home(tmp, shim._local_key_files)
    finally:
        shim._configured_identity_files = real


def _check_ssh_g_contract(results):
    """Cover source 1 (ssh -G parsing) without running ssh or touching a host.

    Fakes subprocess.run so the parse is exercised against known output: an
    identityfile that exists must be returned, one that does not must be
    dropped, and non-identityfile lines must be ignored.
    """
    import subprocess as sp
    with tempfile.TemporaryDirectory() as tmp:
        present = os.path.join(tmp, "configured_key")
        with open(present, "w") as fh:
            fh.write(BODY)
        missing = os.path.join(tmp, "does_not_exist")

        class _Result:
            returncode = 0
            stdout = (
                "host logins.cels.anl.gov\n"
                f"identityfile {present}\n"
                f"identityfile {missing}\n"
                "user someone\n"
            )

        calls = []

        def _fake_run(cmd, **kwargs):
            calls.append(cmd)
            return _Result()

        real_run = shim.subprocess.run
        shim.subprocess.run = _fake_run
        try:
            got = shim._configured_identity_files(["logins.cels.anl.gov"])
        finally:
            shim.subprocess.run = real_run

        results.append(check("ssh -G: existing identityfile returned",
                             got, [present]))
        results.append(check("ssh -G: queried as the SSH login (-l API_KEY)",
                             calls and calls[0][:4] == ["ssh", "-G", "-l", shim.API_KEY],
                             True))

    # A None host (SSH_PROXY_JUMP is None under --nojump) must be skipped, not
    # handed to ssh as the string "None".
    def _boom(cmd, **kwargs):
        raise AssertionError(f"ssh should not run for a None host: {cmd}")

    real_run = shim.subprocess.run
    shim.subprocess.run = _boom
    try:
        results.append(check("ssh -G: None host skipped (--nojump)",
                             shim._configured_identity_files([None]), []))
    finally:
        shim.subprocess.run = real_run


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
        found = _disk_keys_only(tmp)
        names = sorted(os.path.basename(f) for f in found)
        results.append(check("custom-named key discovered", names, [CUSTOM]))

    # 2. stock key still discovered
    with tempfile.TemporaryDirectory() as tmp:
        _mkssh(tmp, {STOCK: BODY})
        found = _disk_keys_only(tmp)
        names = sorted(os.path.basename(f) for f in found)
        results.append(check("stock-named key discovered", names, [STOCK]))

    # 3. empty ~/.ssh -> no keys, so the first-time guide still fires
    with tempfile.TemporaryDirectory() as tmp:
        _mkssh(tmp, {"known_hosts": "example.com ssh-ed25519 AAAAC3Nz\n"})
        found = _disk_keys_only(tmp)
        stray = [f for f in found if f.startswith(tmp)]
        results.append(check("empty ~/.ssh reports no keys", stray, []))

    # 3b. source 1 (ssh -G parsing), stubbed — no subprocess, no host contact
    _check_ssh_g_contract(results)

    # 4. smoke-test command shape — must match what create_tunnel runs
    cmd = shim._smoke_test_command()
    results.append(check("smoke test jumps via the login node", " -J " in cmd, True))
    results.append(check("smoke test uses BatchMode, like the tunnel",
                         "BatchMode=yes" in cmd, True))
    results.append(check("smoke test targets the tunnel's host",
                         cmd.endswith(shim.SSH_JUMP_HOST), True))
    # ControlPath must match create_tunnel's, or the smoke test lands in a
    # different socket namespace and cannot predict the tunnel at all.
    results.append(check("smoke test shares create_tunnel's ControlPath",
                         "ControlPath=~/.ssh/argo-shim-%C" in cmd, True))
    print(f"      command: {cmd}")

    # 4a. the interactive variant shown to new users: same path, same socket,
    # but no BatchMode — otherwise Duo can never prompt and step 5 can't pass.
    icmd = shim._smoke_test_command(interactive=True)
    results.append(check("interactive variant drops BatchMode",
                         "BatchMode" in icmd, False))
    results.append(check("interactive variant keeps the ControlPath",
                         "ControlPath=~/.ssh/argo-shim-%C" in icmd, True))
    results.append(check("interactive variant keeps the jump",
                         " -J " in icmd, True))
    print(f"      interactive: {icmd}")

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
