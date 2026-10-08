#!/usr/bin/env python3
"""Validate create_tunnel's handling of a wedged SSH ControlMaster.

SAFETY: the create_tunnel checks stub _spawn_ssh out entirely, so no `ssh`
process is spawned there and no CELS host is contacted. The _spawn_ssh timeout
check runs a real subprocess, but it is `sleep`, never `ssh` — there is no
command in this file capable of reaching a network host.

Background: a user reported argo-shim looping forever on "SSH tunnel on port
N never started accepting connections" without ever showing a Duo prompt,
which only recovered after killing and restarting the shim process. The
absence of any `ssh: ...` diagnostic line means ssh exited 0 every time: with
ControlMaster=auto/ControlPersist=yes, a later create_tunnel call can hand the
new -L forward to an already-wedged multiplexed master, which accepts the
request and exits successfully without ever bringing the forward up. Nothing
in the old "port never came up" branch closed that master, so every later
recovery attempt reused the same stuck one and failed identically forever —
matching the report. Killing the shim's process tree (e.g. a pattern-based
`pkill -f argo-shim`, since ControlPath embeds that string) incidentally also
killed the wedged ssh master, which is why a restart "fixed" it even though
stop_own_shim() deliberately leaves the tunnel alone.

This simulates exactly that: _spawn_ssh is stubbed to return normally (exit 0)
without anything ever listening on the target port, standing in for the ssh
client reporting success against a master that never brings the forward up.

What it proves:
  1. The ssh command line requests ExitOnForwardFailure=yes, so a real ssh
     client (not this stub) would itself exit nonzero on a genuinely dead
     forward instead of silently "succeeding" — this is the first line of
     defense, running before the case below is ever reached.
  2. When the port still never accepts connections despite a zero exit (the
     wedged-master case ExitOnForwardFailure cannot see, because the master
     process never re-execs the ssh client that set that option), create_tunnel
     closes the control master before raising, so the next attempt is forced
     to open a fresh session rather than reusing the same stuck one.
  3. The failure is NOT recorded against the persistent auth lockout
     (SSHAttemptTracker) — this is a dead forward, not a rejected credential,
     and must not burn down the shared login node's attempt budget.

A second, harder case: a master that is alive enough to hold its control
socket open, but too wedged to answer at all (its underlying session to CELS
silently dropped), never exits — ExitOnForwardFailure can't help, because the
new ssh client is blocked waiting on the master's reply, not running its own
forward logic. Reproducing that exactly needs a real half-dead TCP session,
which isn't triggerable on demand, so this instead proves the general
contract _spawn_ssh now provides for ANY hang of this shape: subprocess.run
is bounded by `timeout`, a hang raises plain RuntimeError (not SSHAuthError —
a hang is not a credential failure), closes the control master, and does not
touch the auth lockout.

This must fail (step 2 of the first case) on the commit before the fix and
pass from it onward.
"""
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import argo_shim._shim as shim


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def check(label, got, want):
    ok = got == want
    print("{}: {}".format("PASS" if ok else "FAIL", label))
    if not ok:
        print("      got:  {!r}".format(got))
        print("      want: {!r}".format(want))
    return ok


def _check_spawn_ssh_timeout():
    """_spawn_ssh must not hang forever on an unresponsive ControlMaster.

    `sleep 5` stands in for a real ssh client blocked indefinitely on a
    master's mux reply — any command that outlives the timeout demonstrates
    the same contract. No ssh binary and no network are involved.
    """
    results = []
    real_close_master = shim._close_control_master
    real_record_failure = shim._ssh_tracker.record_failure

    close_calls = []
    failure_calls = []
    shim._close_control_master = lambda: close_calls.append(True)
    shim._ssh_tracker.record_failure = lambda kind="unknown": failure_calls.append(kind)

    try:
        raised = None
        try:
            shim._spawn_ssh(["sleep", "5"], "test hang", timeout=0.5)
        except Exception as e:
            raised = e

        results.append(check(
            "a hung ssh client raises plain RuntimeError, not SSHAuthError",
            type(raised).__name__ if raised else None,
            "RuntimeError",
        ))
        results.append(check(
            "timeout message names the timeout",
            raised is not None and "timed out" in str(raised),
            True,
        ))
        results.append(check(
            "wedged control master is closed on timeout",
            len(close_calls),
            1,
        ))
        results.append(check(
            "a hang is not recorded against the SSH auth lockout",
            failure_calls,
            [],
        ))
    finally:
        shim._close_control_master = real_close_master
        shim._ssh_tracker.record_failure = real_record_failure

    return results


def main():
    results = []
    port = _free_port()

    # Stub everything that would otherwise touch the network, a real ssh
    # binary, or the persisted lockout file on disk.
    real_spawn_ssh = shim._spawn_ssh
    real_close_master = shim._close_control_master
    real_check_port = shim.check_port_available
    real_sleep = shim.time.sleep
    real_check_allowed = shim._ssh_tracker.check_allowed
    real_record_failure = shim._ssh_tracker.record_failure

    spawn_cmd = {}
    close_calls = []
    failure_calls = []

    def fake_spawn_ssh(cmd, what):
        # Stand-in for a real ssh client handing the forward request to an
        # already-wedged ControlMaster: the client process exits 0 (this
        # function just returns, mirroring _spawn_ssh's success path) but
        # nothing ever actually listens on `port`.
        spawn_cmd["cmd"] = cmd
        return None

    def fake_close_master():
        close_calls.append(True)

    def fake_record_failure(kind="unknown"):
        failure_calls.append(kind)
        return {}

    shim._spawn_ssh = fake_spawn_ssh
    shim._close_control_master = fake_close_master
    shim.check_port_available = lambda port, bind_address="127.0.0.1": None
    shim.time.sleep = lambda s: None  # skip the 5s poll-timeout wait
    shim._ssh_tracker.check_allowed = lambda: None
    shim._ssh_tracker.record_failure = fake_record_failure

    try:
        raised = None
        try:
            shim.create_tunnel(port)
        except RuntimeError as e:
            raised = e

        results.append(check(
            "create_tunnel raises when the port never comes up",
            raised is not None and "never started accepting connections" in str(raised),
            True,
        ))

        # 1. the real ssh invocation asks for ExitOnForwardFailure, so a genuine
        #    ssh client (unlike this stub) would itself fail loudly on a dead
        #    forward instead of silently exiting 0.
        cmd = spawn_cmd.get("cmd", [])
        results.append(check(
            "ssh command requests ExitOnForwardFailure=yes",
            "ExitOnForwardFailure=yes" in cmd,
            True,
        ))

        # 2. the control master must be torn down so the next recovery attempt
        #    can't reuse the same wedged multiplexed session.
        results.append(check(
            "wedged control master is closed before raising",
            len(close_calls),
            1,
        ))

        # 3. a dead forward is not a credential failure — must not count
        #    toward the shared-login-node auth lockout.
        results.append(check(
            "dead forward is not recorded against the SSH auth lockout",
            failure_calls,
            [],
        ))
    finally:
        shim._spawn_ssh = real_spawn_ssh
        shim._close_control_master = real_close_master
        shim.check_port_available = real_check_port
        shim.time.sleep = real_sleep
        shim._ssh_tracker.check_allowed = real_check_allowed
        shim._ssh_tracker.record_failure = real_record_failure

    results.extend(_check_spawn_ssh_timeout())

    print()
    print("{}/{} checks passed".format(sum(results), len(results)))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
