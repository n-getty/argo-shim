# Argo-Shim Remote Proxy

**Author**: Sandeep Madireddy

An automated UI extension for VS Code that functions as a streamlined wrapper around the powerful `argo-shim` Python CLI that allows users to connect to internal Argonne API endpoints seamlessly over secure Jump Host proxies.

## Feature Overview

### 1. Zero-Friction Setup
The very first time you boot the proxy, a native VS Code pop-up will ask you for your **Argonne CELS Username**. The plugin permanently saves this, allowing you to establish proxies in exactly one click going forward. You never have to manually edit port tunnels again!

### 2. Duo 2FA Interactive Support
When establishing secure remote proxy lines onto nodes like Aurora or Polaris, ALCF requires Duo Two-Factor Authentication. This plugin safely spawns a visible VS Code Terminal buffer prompting you exactly when to press `1` and authorize the SSH Push, preventing background timeouts. 

### 3. Integrated CLI Power Features
By relying exclusively on the native `argo-shim` python CLI codebase asynchronously under the hood:
* **Vertex AI 500-Error Deflection**: The baseline CLI forcefully intercepts any large, non-streaming Claude Code requests (often caused by large file loads) and patches them to `stream: true` to prevent hard 10-minute HTTP timeouts inside Google Vertex AI's infrastructure constraints. 
* **Dynamic Deterministic Porting**: Uses SHA-256 to hash your Argonne CELS username to mathematically assign you a permanent, unique proxy port (e.g. `12499`). This absolutely prevents `Address already in use` clashes when multiple scientists have VS Code Server windows open on the exact same access node.
* **Network Transparency**: Submits proxy interceptors that dynamically insert `localhost` and `127.0.0.1` into `no_proxy` environmental flags. This stops standard ALCF server firewalls from accidentally hijacking the IDE's connection loops!
* **Auto-healing Tunnels**: Automatically detects instances where the SSH tunnel abruptly dies and transparently rebuilds it programmatically mid-request without requiring VS Code user intervention.

## Usage Guide
1. Run the VS Code command palette: `Argonne: Start Proxy`
2. Let the plugin verify or ask for your CELS Username.
3. Observe the integrated terminal `🟢 Argo Proxy` prompting you to accept the Duo Push.
4. Let the `argo-shim` Python logic complete the loop! 

Claude Code will programmatically identify the dynamic port mapping via an automated refresh to `~/.claude/settings.json`, and the VS Code status bar will visually turn Green to indicate perfect health.
