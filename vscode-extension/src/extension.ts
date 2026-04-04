import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as net from 'net';
import { execSync } from 'child_process';

let statusBarItem: vscode.StatusBarItem;
let healthCheckTimer: NodeJS.Timeout | undefined;

function getConfig() {
    const cfg = vscode.workspace.getConfiguration('argonneClaude');
    return {
        username: cfg.get<string>('username', ''),
        model: cfg.get<string>('model', 'opus[1m]')
    };
}

export async function activate(context: vscode.ExtensionContext) {
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'argonne-claude.checkStatus';
    context.subscriptions.push(statusBarItem);
    statusBarItem.show();
    setStatus('warning', 'Initializing...');

    context.subscriptions.push(
        vscode.commands.registerCommand('argonne-claude.startProxy', () => fullBootstrap(false)),
        vscode.commands.registerCommand('argonne-claude.stopProxy', stopProxy),
        vscode.commands.registerCommand('argonne-claude.checkStatus', checkStatus),
        vscode.commands.registerCommand('argonne-claude.restart', () => fullBootstrap(false)),
        vscode.commands.registerCommand('argonne-claude.configure', configureSettings)
    );

    // Initial load checks
    const config = getConfig();
    if (!config.username) {
        setStatus('warning', 'Needs setup');
        // Explicitly pop UI on the very first fresh install
        await configureSettings();
        await fullBootstrap(true);
    } else {
        await fullBootstrap(true); // Auto-boot on load silently
    }

    // Health checks using dynamic port every 30s
    healthCheckTimer = setInterval(runHealthCheck, 30_000);
    context.subscriptions.push({ dispose: () => {
        if (healthCheckTimer) { clearInterval(healthCheckTimer); }
    }});
}

async function configureSettings() {
    let config = getConfig();
    const username = await vscode.window.showInputBox({
        prompt: 'Argonne Claude Proxy: Please set your Argonne CELS username to continue',
        value: config.username,
        placeHolder: 'e.g. smadireddy',
        ignoreFocusOut: true
    });
    if (username === undefined) { return; } // User cancelled

    const model = await vscode.window.showInputBox({
        prompt: 'Claude model to use',
        value: config.model,
        placeHolder: 'opus[1m]',
        ignoreFocusOut: true
    });
    if (model === undefined) { return; }

    const cfg = vscode.workspace.getConfiguration('argonneClaude');
    await cfg.update('username', username, vscode.ConfigurationTarget.Global);
    await cfg.update('model', model, vscode.ConfigurationTarget.Global);
    vscode.window.showInformationMessage('✅ Argonne Claude extension configured!');
}

function syncModelSetting() {
    try {
        const config = getConfig();
        const settingsPath = path.join(os.homedir(), '.claude', 'settings.json');
        let data: any = {};
        if (fs.existsSync(settingsPath)) {
            data = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
        }
        if (config.model && data.model !== config.model) {
            data.model = config.model;
            fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
            fs.writeFileSync(settingsPath, JSON.stringify(data, null, 2) + '\n');
        }
    } catch {}
}

async function fullBootstrap(silent = false) {
    let config = getConfig();
    if (!config.username) {
        setStatus('error', 'Not configured');
        return;
    }

    setStatus('warning', 'Bootstrapping CLI...');

    // Synchronize Claude model preference before we hand over to the CLI
    syncModelSetting();

    // 1. Get or create Argo terminal
    let term = vscode.window.terminals.find(t => t.name === '🟢 Argo Proxy');
    if (!term) {
        term = vscode.window.createTerminal('🟢 Argo Proxy');
    }
    
    // Show only if it was a manual user action to avoid popups on startup
    if (!silent) {
        term.show();
    }

    // 2. Clear terminal and send command
    term.sendText(`export CELS_USERNAME="${config.username}"`);
    term.sendText('if command -v uvx &> /dev/null; then echo "Using uvx..."; uvx argo-shim; else echo "Using pip... this may take a moment"; pip install --upgrade --user argo-shim && export PATH=$PATH:~/.local/bin && argo-shim; fi');
    
    if (!silent) {
        vscode.window.showInformationMessage(`🔐 Please check the '🟢 Argo Proxy' terminal to approve the Duo Push if prompted.`);
    }

    // Check status eagerly in background to update UI
    setTimeout(runHealthCheck, 5000);
    setTimeout(runHealthCheck, 15000);
}

function stopProxy() {
    // Attempt graceful kill of the active terminal session
    const term = vscode.window.terminals.find(t => t.name === '🟢 Argo Proxy');
    if (term) {
        term.sendText('\x03'); // Ctrl+C
    }
    
    // Bruteforce kill on dynamically retrieved port to be safe
    const port = getActivePort();
    if (port) {
        try { execSync(`lsof -ti:${port} | xargs kill 2>/dev/null || true`); } catch {}
    }
    
    setStatus('off', 'Stopped');
    vscode.window.showInformationMessage('Argonne proxy cleanly stopped.');
}

function getActivePort(): number | null {
    try {
        const settingsPath = path.join(os.homedir(), '.claude', 'settings.json');
        if (fs.existsSync(settingsPath)) {
            const data = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
            const url = data?.env?.ANTHROPIC_BASE_URL;
            if (url) {
                const match = url.match(/:(\d+)\/argoapi/);
                if (match) return parseInt(match[1], 10);
            }
        }
    } catch {}
    return null;
}

async function runHealthCheck() {
    const port = getActivePort();
    if (!port) {
        setStatus('error', 'No config found');
        return;
    }

    const isUp = await isPortOpen(port);
    if (isUp) {
        setStatus('ok', `Port ${port}`);
    } else {
        setStatus('error', `Port ${port} down`);
    }
}

async function checkStatus() {
    const port = getActivePort();
    if (!port) {
        vscode.window.showErrorMessage('❌ argo-shim configuration not found in ~/.claude/settings.json');
        return;
    }

    const isUp = await isPortOpen(port);
    const msg = `Argo CLI Shim (port ${port}): ${isUp ? '✅ Running' : '❌ Down'}`;
    vscode.window.showInformationMessage(msg);
}

function setStatus(state: 'ok' | 'warning' | 'error' | 'off', detail: string) {
    const icons: Record<string, string> = {
        ok: '$(pass-filled)',
        warning: '$(warning)',
        error: '$(error)',
        off: '$(circle-slash)'
    };
    statusBarItem.text = `${icons[state]} Argo: ${detail}`;
    statusBarItem.tooltip = 'Argonne Claude Proxy Wrapper — Click for status';
}

function isPortOpen(port: number): Promise<boolean> {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(1000);
        socket.on('connect', () => { socket.destroy(); resolve(true); });
        socket.on('timeout', () => { socket.destroy(); resolve(false); });
        socket.on('error', () => { socket.destroy(); resolve(false); });
        socket.connect(port, '127.0.0.1');
    });
}

export function deactivate() {
    if (healthCheckTimer) { clearInterval(healthCheckTimer); }
}
