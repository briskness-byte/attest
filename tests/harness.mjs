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
    // To test the working tree without cutting a release: zip dist/ somewhere and point this at it.
    if (process.env.QA_XPI) return path.resolve(process.env.QA_XPI);
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
    // --allow-system-access: since Firefox ~138 chrome-context scripts run with a null principal
    // without it, and the extension's address below cannot be read. It has to be given here — Firefox
    // refuses it through capabilities. Needs geckodriver 0.36 or later.
    const gd = spawn(gecko, ['--port', String(gdPort), '--log', 'fatal', '--allow-system-access'],
        { stdio: 'ignore', env });
    gd.on('error', e => { console.log('✗ could not start geckodriver: ' + e.message); process.exit(1); });
    // A suite that crashes never reaches finish(), and a driver left behind holds its port: the next
    // run then talks to that one instead of its own. Kill it on any exit.
    process.on('exit', () => { try { gd.kill(); } catch (e) {} });

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
    // without asking Firefox what it assigned. This only answers when geckodriver runs with
    // --allow-system-access (above); without it this came back as an error object on every run, and
    // `base` was quietly nonsense.
    const host = await chrome(
        `return WebExtensionPolicy.getByID(${JSON.stringify(ADDON_ID)})?.mozExtensionHostname ?? null;`);
    const base = typeof host === 'string' ? `moz-extension://${host}/` : null;

    const EID = 'element-6066-11e4-a52e-4f735466cecf';
    const el = async (using, value) => {
        const r = (await wd('POST', `/session/${sid}/element`, { using, value })).value;
        return r && !r.error ? r : null;
    };

    return {
        base,
        // WebDriver refuses to navigate to moz-extension:// at all ("not allowed in this context"),
        // so the browser chrome opens the page in the current tab instead.
        openExt: async page => {
            if (!base) throw new Error('the extension address is unknown');
            await chrome(`openTrustedLinkIn(${JSON.stringify(base + page)}, 'current'); return true;`);
            await new Promise(r => setTimeout(r, 1500));
        },
        el,
        // A missing element answers like a WebDriver error instead of throwing. A suite that throws
        // stops at the first thing it cannot find, and reports nothing after it; this way the checks
        // that follow fail one by one and say what was missing.
        click: e => e
            ? wd('POST', `/session/${sid}/element/${e[EID]}/click`, {})
            : Promise.resolve({ value: { error: 'no such element' } }),
        type: (e, text) => e
            ? wd('POST', `/session/${sid}/element/${e[EID]}/value`, { text })
            : Promise.resolve({ value: { error: 'no such element' } }),
        text: async e => (await wd('GET', `/session/${sid}/element/${e[EID]}/text`)).value,
        // The current window as a base64 PNG, for checking what a page looks like.
        screenshot: async () => (await wd('GET', `/session/${sid}/screenshot`)).value,
        // Whether a checkbox or radio button is checked.
        selected: async e => (await wd('GET', `/session/${sid}/element/${e[EID]}/selected`)).value,
        // Whether the element is actually drawn, not merely present in the DOM.
        displayed: async e => (await wd('GET', `/session/${sid}/element/${e[EID]}/displayed`)).value,
        elements: async (using, value) =>
            (await wd('POST', `/session/${sid}/elements`, { using, value })).value ?? [],
        // Windows and tabs. The prompt and PIN windows are opened by the extension, not by us, so
        // this is how a suite gets into them.
        handles: async () => (await wd('GET', `/session/${sid}/window/handles`)).value,
        window: async () => (await wd('GET', `/session/${sid}/window`)).value,
        switchTo: handle => wd('POST', `/session/${sid}/window`, { handle }),
        newTab: async () => (await wd('POST', `/session/${sid}/window/new`, { type: 'tab' })).value.handle,
        // window.confirm(). Accepting or dismissing has to be the very next command after the one
        // that opened it; anything else and WebDriver dismisses it on its own.
        acceptAlert: () => wd('POST', `/session/${sid}/alert/accept`, {}),
        dismissAlert: () => wd('POST', `/session/${sid}/alert/dismiss`, {}),
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
