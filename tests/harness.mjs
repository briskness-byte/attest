// Enough of a harness to drive a real Firefox with this extension installed.
//
// There is no framework here on purpose. The thing worth testing is a boundary between a web page
// and a background script, and that only exists in a browser — a mock of it would assert that the
// mock agrees with itself.
import { spawn } from 'child_process';
import http from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';

export const ADDON_ID = 'attest@brisknessbyte.com';
export const EXT_CODE = 'attest';

const HERE = path.dirname(new URL(import.meta.url).pathname);
export const ROOT = path.resolve(HERE, '..');

/** The newest built package, so a run always tests what was last built rather than a stale file. */
export function newestXpi() {
    const dir = path.join(ROOT, 'var/releases');
    const files = fs.existsSync(dir)
        ? fs.readdirSync(dir).filter(f => f.endsWith('.xpi')).map(f => path.join(dir, f))
        : [];
    if (!files.length) {
        console.log('✗ no .xpi in var/releases — run `sh release.sh` first');
        process.exit(1);
    }
    return files.sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)[0];
}

export function reporter() {
    const state = { pass: 0, fail: 0 };
    const ok = (name, cond, extra) => {
        if (cond) { state.pass++; console.log('  ✓ ' + name); }
        else { state.fail++; console.log('  ✗ FAIL ' + name + (extra !== undefined ? '  → ' + JSON.stringify(extra) : '')); }
    };
    return { ok, state };
}

/** A page that does nothing, so anything observed came from the extension. */
export function startSite(port) {
    const server = http.createServer((_, res) => {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<!doctype html><html><head><title>QA</title></head><body><h1>QA page</h1></body></html>');
    });
    return new Promise(resolve => server.listen(port, '127.0.0.1', () => resolve(server)));
}

export async function startBrowser({ gdPort, xpi }) {
    const W = fs.mkdtempSync(path.join(os.tmpdir(), 'attest-qa-'));
    fs.mkdirSync(path.join(W, 'home'), { recursive: true });
    const env = { ...process.env, HOME: path.join(W, 'home'), TMPDIR: W };

    const gecko = process.env.GECKODRIVER || path.join(os.homedir(), 'tools/geckodriver');
    const gd = spawn(gecko, ['--port', String(gdPort), '--log', 'fatal'], { stdio: 'ignore', env });
    gd.on('error', e => { console.log('✗ could not start geckodriver: ' + e.message); process.exit(1); });

    const wd = async (m, p, b) => (await fetch(`http://127.0.0.1:${gdPort}${p}`, {
        method: m, headers: { 'Content-Type': 'application/json' },
        body: b ? JSON.stringify(b) : undefined,
    })).json();

    let up = false;
    for (let i = 0; i < 60; i++) {
        try { await fetch(`http://127.0.0.1:${gdPort}/status`); up = true; break; }
        catch { await new Promise(r => setTimeout(r, 250)); }
    }
    // A driver left behind by a run that was killed holds the port, and the next run talks to it
    // instead of its own. That reads as the extension not being installed.
    if (!up) { console.log(`✗ geckodriver did not come up on ${gdPort} — is one still running?`); process.exit(1); }

    const binary = process.env.FIREFOX || '/usr/bin/firefox';
    const sess = await wd('POST', '/session', { capabilities: { alwaysMatch: {
        'moz:firefoxOptions': { binary, args: ['-headless'] } } } });
    const sid = sess.value?.sessionId;
    if (!sid) { console.log('✗ no Firefox session: ' + JSON.stringify(sess).slice(0, 200)); process.exit(1); }

    const added = await wd('POST', `/session/${sid}/moz/addon/install`, { path: xpi, temporary: true });
    if (!added.value) { console.log('✗ could not install ' + xpi); process.exit(1); }
    await new Promise(r => setTimeout(r, 1500));

    const chrome = async script => {
        await wd('POST', `/session/${sid}/moz/context`, { context: 'chrome' });
        const r = await wd('POST', `/session/${sid}/execute/sync`, { script, args: [] });
        await wd('POST', `/session/${sid}/moz/context`, { context: 'content' });
        return r.value;
    };

    // The internal address is random per profile, so the extension's own pages cannot be reached
    // without asking Firefox what it assigned. This is the only way in from outside, and without it
    // half of what this suite checks — that the extension can still talk to itself — is untestable.
    const host = await chrome(
        `return WebExtensionPolicy.getByID(${JSON.stringify(ADDON_ID)})?.mozExtensionHostname ?? null;`);

    return {
        base: host ? `moz-extension://${host}/` : null,
        goto: url => wd('POST', `/session/${sid}/url`, { url }),
        url: async () => (await wd('GET', `/session/${sid}/url`)).value,
        js: async code => (await wd('POST', `/session/${sid}/execute/sync`,
            { script: `return (function(){${code}})()`, args: [] })).value,
        jsAsync: async code => (await wd('POST', `/session/${sid}/execute/async`,
            { script: code, args: [] })).value,
        wait: ms => new Promise(r => setTimeout(r, ms)),
        finish: async code => { try { await wd('DELETE', `/session/${sid}`); } catch (e) {} gd.kill(); process.exit(code); },
    };
}
