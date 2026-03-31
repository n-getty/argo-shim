# argo-shim

A lightweight HTTP proxy that lets Claude Code talk to the Argo API through an SSH tunnel from an ALCF machine. It handles path rewriting (`/v1/messages` -> `/argoapi/v1/messages`), injects your API key, and bridges plain HTTP (what Claude Code speaks) to HTTPS (what the tunnel carries).

## Prerequisites

- SSH access to CELS machines ([setup guide](https://help.cels.anl.gov/docs/linux/ssh/))
- Python 3.8+
- Claude Code (`curl -fsSL https://claude.ai/install.sh | bash`)

## Quick Start

**1. Run the shim**

```bash
python3 argo_shim.py
```

The shim will:
- Find or create an SSH tunnel to `apps.inside.anl.gov:443`
- Start a local HTTP proxy on the next available port (8081+)
- Update `~/.claude/settings.json` with the correct `ANTHROPIC_BASE_URL`
- Run health checks to verify connectivity

> If your ALCF username differs from your CELS username, set `CELS_USERNAME` to your CELS username

**2. Start Claude Code** (in another terminal on the same node)

```bash
claude
```

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
# Tunnel only (direct HTTPS through tunnel, use your tunnel port)
curl -k -H "Host: apps.inside.anl.gov" \
     -H "x-api-key: <username>" \
     https://127.0.0.1:8080/argoapi/v1/models

# Tunnel + shim end-to-end (use your shim port)
curl http://127.0.0.1:8081/v1/models
```

## Troubleshooting

**`[SSL: WRONG_VERSION_NUMBER]` proxy errors**

The SSH tunnel is stale, usually caused by SSH ControlMaster keeping a dead connection open. Fix:

```bash
ssh -O exit homes.cels.anl.gov
python3 argo_shim.py   # re-creates the tunnel
```

**`HEAD /argoapi HTTP/1.1 501`**

You're running an older version of the shim that didn't handle HEAD requests. Update to the latest version.

**Port already in use**

The shim automatically scans ports 8080-8089 (tunnel) and 8081-8090 (shim). If all are taken, kill stale tunnels:

```bash
# List SSH tunnels
ps aux | grep 'ssh -N'
# Kill a specific one
kill <pid>
```

**Claude Code can't connect after restarting the shim**

The shim port may have changed. The shim updates `~/.claude/settings.json` automatically, but you need to restart Claude Code to pick up the new port.

**"ERROR: The requested URL could not be retrieved" in Claude Code**

If you see the above in Claude Code after sending a prompt, you may need to unset some HTTP proxies in your .bashrc.

Please use these proxy settings to prevent setting proxies on login nodes.
https://docs.alcf.anl.gov/aurora/getting-started-on-aurora/#proxy
