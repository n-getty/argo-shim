# argo-shim

A lightweight HTTP proxy that lets Claude Code talk to the Argo API through an SSH tunnel from an ALCF machine. It handles path rewriting (`/v1/messages` -> `/argoapi/v1/messages`), injects your API key, and bridges plain HTTP (what Claude Code speaks) to HTTPS (what the tunnel carries).

## Installation

```bash
# Run directly (no install needed):
uvx argo-shim

# Or install globally:
pip install argo-shim
# then run:
argo-shim
```

## Prerequisites

- SSH access to CELS machines ([setup guide](https://help.cels.anl.gov/docs/linux/ssh/))
- Python 3.8+
- Claude Code (`curl -fsSL https://claude.ai/install.sh | bash`)

## First-time setup (new users start here)

argo-shim reaches the Argo API over an **SSH tunnel to CELS**. That tunnel only
works if CELS recognizes your SSH key. **Set this up once, and verify it works,
before you run argo-shim.** Skipping this is the #1 cause of failures.

1. **Generate an SSH key** (press Enter at every prompt to accept defaults):
   ```bash
   ssh-keygen -t ed25519
   ```
2. **Upload your _public_ key to your CELS account.** Print it and copy the
   whole line:
   ```bash
   cat ~/.ssh/id_ed25519.pub
   ```
   Paste it into the SSH Keys section at **https://accounts.cels.anl.gov**.
   Paste the `.pub` contents — never your private key.
3. **Load the key into your SSH agent:**
   ```bash
   ssh-add
   ```
4. **Verify it works.** This must log you in **without a password prompt**:
   ```bash
   ssh -o BatchMode=yes logins.cels.anl.gov true
   ```
   If that command succeeds (no output, no password prompt, exit 0), you're
   ready. If it fails, fix it here — argo-shim cannot work until this does.

> argo-shim runs this same check for you on startup and **refuses to start** if
> it finds no SSH key at all, pointing you back to these steps. That's on
> purpose — see the warning below.

> ⚠️ **If argo-shim fails, do _not_ keep restarting it.**
> ALCF login nodes are shared, and CELS/CSPO security blocks the **whole node's
> IP** after too many failed SSH logins — which would break Argo access for
> *everyone* on that node (and is why this is getting locked down). A failed
> connection almost always means a setup problem that a restart won't fix.
> Read the error message, fix the one thing it names, then try again. argo-shim
> now enforces a cooldown after repeated failures so an accidental restart loop
> can't get the node blocked (see [SSH Auth Failure Protection](#ssh-auth-failure-protection)).

## Quick Start

**1. Run the shim**

```bash
argo-shim
```

The shim will:
- Find or create an SSH tunnel to `apps.inside.anl.gov:443`
- Start a local HTTP proxy on a port derived from your username (deterministic across restarts)
- Generate a per-session auth token and update `~/.claude/settings.json` with the correct `ANTHROPIC_BASE_URL` and `apiKeyHelper`
- Run health checks to verify connectivity

To use a specific port instead of the auto-derived one:

```bash
argo-shim --port 8083
```

The tunnel will use the port immediately below (e.g., `--port 8083` → tunnel on 8082, shim on 8083).

> If your ALCF username differs from your CELS username, set `CELS_USERNAME` to your CELS username

**2. Start Claude Code** (in another terminal on the same node)

```bash
claude
```

## Running from Compute Nodes

Compute nodes don't have outbound network access, so they can't create SSH tunnels directly. Instead, create the tunnel on a UAN and point the shim at it.

**1. On a UAN:**

```bash
argo-shim --tunnel
```

This creates an SSH tunnel bound to all interfaces and prints the command to run on the compute node.

**2. On the compute node:**

```bash
argo-shim --tunnel-host <uan-hostname>
```

Then start Claude Code. If proxy env vars are set (common on HPC nodes), bypass them for localhost:

```bash
no_proxy=localhost,127.0.0.1 NO_PROXY=localhost,127.0.0.1 claude
```

The shim prints this command automatically when it detects proxy variables. Without `no_proxy`, the proxy intercepts API traffic to `127.0.0.1` and breaks the connection.

### Fallback: Relay through your Mac

If your UAN cannot SSH to CELS (e.g., network restrictions on Aurora), you can relay the tunnel through your Mac instead. This requires keeping your Mac connected for the duration of the session.

**1. On your Mac:**

```bash
argo-shim --relay <uan-hostname>
```

This creates the SSH tunnel locally, reverse-forwards it to the UAN, and starts the local shim (so your Mac can also use Claude Code).

**2. On the compute node:**

```bash
argo-shim --tunnel-host <uan-hostname>
```

If the UAN has `GatewayPorts` disabled (the default), the shim will automatically create an SSH local forward from the compute node to the UAN's localhost port.

> **Note:** The relay approach adds an extra network hop (compute node -> UAN -> Mac -> CELS -> API) and depends on your Mac staying connected. Prefer `--tunnel` on the UAN when SSH to CELS is available.

## Claude Code Settings

The shim automatically creates `~/.claude/settings.json` on first run and keeps the port in `ANTHROPIC_BASE_URL` correct on subsequent runs. No manual setup needed.

To use a specific model (e.g., Opus), add a `"model"` field to your settings:

```json
{
  "model": "claudeopus46"
}
```

Without this, Claude Code defaults to Sonnet.

## Health Checks

The shim runs these automatically on startup. To run them manually:

```bash
# Tunnel only (direct HTTPS through tunnel; use your tunnel port from startup logs)
curl -k -H "Host: apps.inside.anl.gov" \
     -H "x-api-key: <username>" \
     https://127.0.0.1:<tunnel-port>/argoapi/v1/models

# Tunnel + shim end-to-end (use your shim port; token is printed at startup)
curl -H "x-api-key: <auth-token>" http://127.0.0.1:<shim-port>/v1/models
```

## SSH Auth Failure Protection

ALCF and CELS networks are monitored by CSPO (Cyber Security). Too many failed SSH authentication attempts from a single IP will cause CSPO to block that IP — and since multiple users share ALCF login nodes, one user's broken auth can block the entire node for everyone.

argo-shim protects against this in three layers:

**1. Preflight checks (before any SSH attempt).**
On startup, argo-shim looks for usable SSH key material. If you have **no key at
all**, it prints the [first-time setup](#first-time-setup-new-users-start-here)
steps and **refuses to start** — it will not make a doomed connection that
counts against the node's IP. If you have a key on disk but nothing loaded in
your agent, it warns you to run `ssh-add` (a common symptom of a laptop that
slept and dropped agent forwarding).

**2. Failure classification.**
When an SSH command does fail, argo-shim reads ssh's own error output and
classifies it: an **auth** failure (`Permission denied (publickey)`, etc.) is
the dangerous, IP-block-triggering kind and is counted; a transient **network**
error or a busy **local port** is *not* counted, because it isn't a failed
login. Each failure prints a specific, actionable hint.

**3. A persistent lockout that survives restarts.**
This is the key change. The failure counter is stored on disk
(`~/.claude/argo-shim-state.json`), so quitting and re-running argo-shim **does
not** reset it — you can no longer accidentally hammer CELS with a restart loop.

- After **2 consecutive auth failures**, all SSH attempts pause for a **15-minute
  cooldown**. The cooldown clears itself.
- If failures continue across multiple cooldowns, argo-shim escalates to a
  **hard lock** that only `argo-shim --reset` clears (after you've fixed auth).

Check or clear the state at any time:

```bash
argo-shim --status   # show current lockout/cooldown state (read-only)
argo-shim --reset    # clear the lockout after you've fixed your SSH auth
```

Common causes of repeated SSH auth failures:
- SSH **public** key not uploaded to https://accounts.cels.anl.gov
- Closing your laptop while SSH agent forwarding is active (kills the forwarded key)
- SSH key removed from the agent (`ssh-add -D`) — fix with `ssh-add`
- Expired Kerberos tickets

To recover from a cooldown or hard lock: **first** make this succeed —
`ssh -o BatchMode=yes logins.cels.anl.gov true` — then run `argo-shim --reset`
(if hard-locked) and start argo-shim again.

All SSH commands also use `BatchMode=yes` (no interactive password fallback) and `ConnectionAttempts=1` to ensure each attempt is a single, non-interactive connection.

## Troubleshooting

> **Before anything else:** confirm SSH itself works, independent of argo-shim:
> ```bash
> ssh -o BatchMode=yes logins.cels.anl.gov true
> ```
> If that fails, argo-shim cannot work — fix SSH first (see the table below).
> **Do not loop on restarting argo-shim** while SSH is broken.

| Symptom | Likely cause | Fix (do this one thing) |
| --- | --- | --- |
| `Permission denied (publickey)` | Public key not on your CELS account, or wrong key in use | Upload `~/.ssh/id_ed25519.pub` at https://accounts.cels.anl.gov, then `ssh-add` |
| argo-shim prints "No SSH key found" and exits | You haven't set up an SSH key yet | Follow [First-time setup](#first-time-setup-new-users-start-here) |
| Worked earlier, now `Permission denied` after closing your laptop | Agent forwarding dropped when the laptop slept | Reconnect, then `ssh-add` |
| "SSH attempts are paused for ~N minutes" | You hit the failure cooldown | Fix your SSH auth and wait out the cooldown; check with `argo-shim --status` |
| "SSH attempts are HARD-LOCKED" | Repeated failures across cooldowns | Fix SSH auth, then `argo-shim --reset` |
| `Host key verification failed` / host identity changed | Stale entry in `~/.ssh/known_hosts` | Remove the stale line **only if you trust the change**, then retry once |
| `Could not resolve hostname` / `Connection timed out` | Network/VPN problem, not auth | Check your connection/VPN (this is *not* counted against the lockout) |
| `Port already in use` | Another process holds the derived port | `argo-shim --port <PORT>` |

**`[SSL: WRONG_VERSION_NUMBER]` proxy errors**

The SSH tunnel is stale, usually caused by SSH ControlMaster keeping a dead connection open. Fix:

```bash
ssh -O exit homes.cels.anl.gov
argo-shim   # re-creates the tunnel
```

**`HEAD /argoapi HTTP/1.1 501`**

You're running an older version of the shim that didn't handle HEAD requests. Update to the latest version.

**Port already in use**

The shim derives a deterministic port from your username. If that port is taken, specify a different one:

```bash
argo-shim --port 8083
```

To find and kill stale SSH tunnels occupying ports:

```bash
# List SSH tunnels
ps aux | grep 'ssh -N'
# Kill a specific one
kill <pid>
```

**Claude Code can't connect / API connection refused**

A few things to check:
- **Restart Claude Code** after restarting the shim — Claude Code only reads `~/.claude/settings.json` at startup, so it won't pick up a new port or token until restarted.
- **Try a different port** — in rare cases the derived port may not work on your node. Use `--port <PORT>` to specify an alternative (e.g., `argo-shim --port 8083`).

**401 errors / auth failures with project-level Claude settings**

The shim writes `apiKeyHelper` and `ANTHROPIC_BASE_URL` to `~/.claude/settings.json` (global). If you have a project-level `.claude/settings.json` with its own `env` object, it **overrides** the global `env` entirely (Claude Code does not merge object/scalar settings across scopes — only arrays merge). This means the shim's auth token never reaches Claude Code.

Fix: run the shim with `--no-auth` to disable token authentication:

```bash
argo-shim --no-auth
```

This is safe because the shim only listens on `127.0.0.1`. You will still need `ANTHROPIC_BASE_URL` set correctly — either in your global settings (where the shim writes it) or in your project settings.

**`500: Streaming is required for operations that may take longer than 10 minutes`**

This error comes from Google Vertex AI (the backend hosting Claude behind Argo), not from the shim or Argo Gateway. It occurs when a non-streaming request (`stream: false` or omitted) has a large payload — typically when Claude Code sends tool results (file reads, web searches) back to the model.

The shim works around this by forcing `stream: true` on all POST requests to `/messages` before forwarding upstream. If you see this error, make sure you're running the latest version of the shim.

**"ERROR: The requested URL could not be retrieved" in Claude Code**

HPC login nodes set `HTTP_PROXY` / `HTTPS_PROXY` environment variables that can interfere with the shim's localhost proxy. The shim handles this automatically by setting `no_proxy=localhost,127.0.0.1` in Claude Code's settings, so API traffic bypasses the proxy while internet access still works.

If you still see proxy errors, ensure you're running the latest version of the shim. See the [ALCF proxy docs](https://docs.alcf.anl.gov/aurora/getting-started-on-aurora/#proxy) for more details.

## Publishing to PyPI

Publishing is automated via GitHub Actions. To release a new version:

1. Bump the version in `argo_shim/__init__.py`
2. Commit and tag:
   ```bash
   git commit -am "Bump version to X.Y.Z"
   git tag vX.Y.Z
   git push && git push --tags
   ```

The workflow builds with `uv build` and publishes with `uv publish` using [trusted publishing](https://docs.pypi.org/trusted-publishers/) (no API tokens needed — configure the GitHub repo as a trusted publisher on PyPI).
