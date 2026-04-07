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

The shim protects against this with an **SSH attempt tracker** that counts consecutive SSH failures. After **3 consecutive failures**, all further SSH attempts are disabled and the shim returns `503` errors to clients with a message to fix auth and restart.

Common causes of repeated SSH auth failures:
- Closing your laptop while SSH agent forwarding is active (kills the forwarded key)
- Expired Kerberos tickets
- SSH key removed from the agent (`ssh-add -D`)

When the tracker trips, you'll see:

```
⚠ SSH has failed 3 consecutive times. Disabling further SSH attempts to prevent IP blocks.
  Fix your SSH authentication (ssh-add, reconnect agent forwarding, etc.) and restart argo-shim.
```

To recover: fix your SSH auth (e.g., `ssh-add`, reconnect your laptop, renew tickets), then restart argo-shim. The tracker resets on restart.

All SSH commands also use `BatchMode=yes` (no interactive password fallback) and `ConnectionAttempts=1` to ensure each attempt is a single, non-interactive connection.

## Troubleshooting

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
