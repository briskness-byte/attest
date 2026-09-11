// Permissions per origin, in a real browser: schemes, old exports, and pages with no origin.
//
// Before 1.25.0 a grant was stored under location.host, which has no scheme. A grant made on
// https://example.com was therefore honoured on http://example.com, for anybody who could serve
// that — on a café network, say. Local files all shared one key between them.
//
// What this pins, from the page's side:
//   - a grant made over https does not cover the same address over plain http;
//   - a profile exported by an older version, with bare-host keys, imports with its grants intact;
//   - a sandboxed page does not inherit its site's grant, and neither it nor a local file is offered
//     an answer that would be remembered.
// The rules themselves, and the move of stored grants on first start, are tests/permission-keys.mjs.
//
//   node tests/origins.mjs
//
// Requires: Firefox, geckodriver 0.36+ (in ~/tools or $GECKODRIVER), and a package in var/releases
// or at $QA_XPI.
import fs from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import { createRequire } from 'module';
import { startBrowser, reporter, newestXpi, ROOT } from './harness.mjs';

const require = createRequire(path.join(ROOT, 'package.json'));
const { getPublicKey } = require('nostr-tools');

const GD_PORT = Number(process.env.QA_PORT || 9750);
const SITE = Number(process.env.QA_SITE_PORT || 8750);
const OTHER = SITE + 1;

// Asks for the public key; '__asked__' means no answer within three seconds, i.e. a prompt.
const PAGE = `<!doctype html><html><head><title>QA</title></head><body><pre id="out"></pre><script>
const ready = () => new Promise(r => { const t = setInterval(() => { if (window.nostr) { clearInterval(t); r(); } }, 50); });
(async () => {
  await ready();
  const result = await Promise.race([
    window.nostr.getPublicKey().catch(e => 'rejected: ' + e.message),
    new Promise(r => setTimeout(() => r('__asked__'), 3000))
  ]);
  // window.origin, not location.origin: the second is worked out from the address and says
  // http://… even for a sandboxed page. The same mistake was once in the content script.
  document.getElementById('out').textContent = JSON.stringify({ result, origin: String(window.origin) });
})();
</script></body></html>`;

const serve = port => new Promise(resolve => {
  const server = http.createServer((req, res) => {
    const headers = { 'Content-Type': 'text/html' };
    // A page its own server sandboxes: its origin is "null", like a local file's.
    if (req.url.startsWith('/sandboxed')) headers['Content-Security-Policy'] = 'sandbox allow-scripts';
    res.writeHead(200, headers);
    res.end(PAGE);
  });
  server.listen(port, '127.0.0.1', () => resolve(server));
});

const sk = '11'.repeat(32);
const pub = getPublicKey(Uint8Array.from(Buffer.from(sk, 'hex')));
const httpsGrant = `https://127.0.0.1:${SITE}`; // made over https
const legacyKey = `127.0.0.1:${OTHER}`;          // as a pre-1.25.0 export has it
const legacyMoved = `http://127.0.0.1:${OTHER}`; // where it should land: loopback keeps http

const fileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'attest-origins-'));
const filePage = path.join(fileDir, 'page.html');
fs.writeFileSync(filePage, PAGE);

const { ok, state } = reporter();
const xpi = newestXpi();
console.log(`\ntesting ${xpi.split('/').pop()}\n`);

const servers = [await serve(SITE), await serve(OTHER)];
const b = await startBrowser({ gdPort: GD_PORT, xpi });
const done = async () => {
  servers.forEach(s => s.close());
  fs.rmSync(fileDir, { recursive: true, force: true });
  await b.finish(state.fail ? 1 : 0);
};

async function ask(url) {
  // A refused navigation has to say so; otherwise it reads as a page that never got an answer.
  const nav = await b.goto(url);
  if (nav?.value?.error) return { result: `navigation refused: ${nav.value.message}` };
  const end = Date.now() + 20000;
  while (Date.now() < end) {
    const e = await b.el('css selector', '#out');
    const t = e ? await b.text(e) : '';
    if (t) return JSON.parse(t);
    await b.wait(250);
  }
  return { result: '(no result)' };
}

const byText = (tag, text) => b.el('xpath', `//${tag}[contains(., ${JSON.stringify(text)})]`);

// ---- setup: a profile as an older version would have exported it ----
console.log('=== importing a profile with one origin key and one bare-host key ===');
ok("the extension's own pages are reachable", !!b.base, b.base);
if (!b.base) await done();
await b.openExt('options.html');
const options = await b.window();
await b.click(await b.el('xpath', "//div[@class='profile-actions']/button[contains(., 'Import')]"));
await b.wait(300);
const now = Math.floor(Date.now() / 1000);
await b.type(await b.el('css selector', '.import-modal textarea'), JSON.stringify({
  privateKey: sk, name: 'qa', relays: {},
  permissions: {
    [httpsGrant]: { condition: 'forever', level: 20, created_at: now, decision: 'allow' },
    [legacyKey]: { condition: 'forever', level: 20, created_at: now, decision: 'allow' }
  }
}));
await b.click(await b.el('css selector', '.import-modal button'));
await b.wait(1500);
ok('the origin key is kept', !!(await b.el('css selector', `button[data-domain="${httpsGrant}"]`)));
ok('the bare-host key is moved to its origin', !!(await b.el('css selector', `button[data-domain="${legacyMoved}"]`)));
ok('  and is not kept under its old name', !(await b.el('css selector', `button[data-domain="${legacyKey}"]`)));

const sites = await b.newTab();
await b.switchTo(sites);

console.log('\n=== the scheme is part of the grant ===');
const plain = await ask(`http://127.0.0.1:${SITE}/`);
ok('a grant made over https does not cover plain http', plain.result === '__asked__', plain.result);
const moved = await ask(`http://127.0.0.1:${OTHER}/`);
ok('the moved grant answers its site', moved.result === pub, moved.result);

console.log('\n=== pages with no origin of their own ===');
const sandboxed = await ask(`http://127.0.0.1:${OTHER}/sandboxed`);
ok('the test page really is sandboxed', sandboxed.origin === 'null', sandboxed.origin);
ok('  and does not inherit the grant of the site serving it', sandboxed.result === '__asked__', sandboxed.result);
const local = await ask(`file://${filePage}`);
// Firefox 155 gives a local file no window.nostr at all: the page loads, the signer is simply not
// there. So a local file cannot ask, and there is nothing it could have had remembered. The rule for
// such keys is pinned in permission-keys.mjs regardless. Should a Firefox ever inject here, this
// switches to checking that a local file asks and is offered nothing that would be remembered.
const localReaches = local.result !== '(no result)';
if (localReaches) {
  ok('a local file has to ask', local.result === '__asked__', local.result);
} else {
  const title = await b.js('return document.title');
  const nostr = await b.js('return typeof (window.wrappedJSObject || window).nostr');
  ok('a local file loads, and Firefox gives it no window.nostr at all',
     title === 'QA' && nostr === 'undefined', JSON.stringify({ title, nostr }));
}

// Walk the queue in the prompt window: only real origins may be offered a remembered answer.
let promptWin = null;
for (const h of await b.handles()) {
  await b.switchTo(h);
  if ((await b.url())?.includes('/prompt.html')) { promptWin = h; break; }
}
ok('the prompt window is open', !!promptWin);
if (promptWin) {
  const seen = {};
  const counter = await b.el('css selector', '.prompt-navigator span');
  const total = counter ? Number((await b.text(counter)).split('/')[1]) : 1;
  for (let i = 0; i < total; i++) {
    const host = await b.text(await b.el('css selector', 'h1.prompt-host'));
    const forever = await byText('button', 'Authorize forever');
    const justThis = await byText('button', 'Authorize just this');
    seen[host] = {
      forever: forever ? await b.displayed(forever) : false,
      justThis: justThis ? await b.displayed(justThis) : false
    };
    const next = await b.el('css selector', '.prompt-navigator button[title="Next"]');
    if (next && i < total - 1) { await b.click(next); await b.wait(300); }
  }
  const find = prefix => Object.entries(seen).find(([h]) => h.startsWith(prefix))?.[1];
  const forPlain = find(`http://127.0.0.1:${SITE}`);
  const forSandboxed = find('sandboxed:');
  const forFile = find('file://');
  ok('a real origin is offered "Authorize forever"', forPlain?.forever === true, JSON.stringify(seen));
  ok('a sandboxed page is not', forSandboxed && forSandboxed.forever === false, JSON.stringify(forSandboxed));
  ok('  but can still be answered this once', forSandboxed?.justThis === true);
  if (localReaches) {
    ok('a local file is not either', forFile && forFile.forever === false, JSON.stringify(forFile));
    ok('  but can still be answered this once', forFile?.justThis === true);
  }
}

console.log(`\n${state.fail === 0 ? '✓' : '✗'} origins: ${state.pass} passed, ${state.fail} failed`);
await done();
