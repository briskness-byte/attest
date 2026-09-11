// What a page gets back from the signer, and from whom.
//
// Three things were wrong here at once. All three were found in the audit of 11 September 2026 and
// shown in this browser before they were fixed:
//
//   - The provider took an answer from any window that posted one, and request ids were four
//     digits. A frame inside the page, or a site holding a handle to it, could post all 10 000 and
//     have its answer taken as the extension's: a stranger's public key, a decrypted message the
//     extension never produced.
//   - The same four digits collided on their own. Of 300 signEvent calls in flight, 7 received
//     another call's event and 7 never settled.
//   - Errors carried the background's stack across, and that stack names moz-extension://<uuid>/ —
//     the per-install identifier that moving the provider into the MAIN world was meant to hide.
//
// Every "nobody else can answer" check has a control next to it that the attack really reached the
// page. Without one, a probe that silently failed to run would pass as a fix.
//
//   node tests/page-answers.mjs
//
// Requires: Firefox, geckodriver 0.36+ (in ~/tools or $GECKODRIVER), and a package in var/releases
// or at $QA_XPI.
import http from 'http';
import path from 'path';
import { createRequire } from 'module';
import { startBrowser, reporter, newestXpi, ROOT } from './harness.mjs';

const require = createRequire(path.join(ROOT, 'package.json'));
const { getPublicKey } = require('nostr-tools');

const GD_PORT = Number(process.env.QA_PORT || 9730);
const SITE = Number(process.env.QA_SITE_PORT || 8730);
const OTHER = SITE + 1; // a second origin, for the frames
const FORGED = 'ab'.repeat(32);

// A frame that posts every four-digit id there is, the way the old ids could be answered blind.
const SPRAY = `<!doctype html><script>
const end = Date.now() + 6000;
(function round() {
  for (let i = 0; i < 10000; i++)
    parent.postMessage({ ext: 'attest', id: String(i).padStart(4, '0'), response: '${FORGED}' }, '*');
  if (Date.now() < end) setTimeout(round, 20);
})();
</script>`;

// A frame that is told the real id and answers with it: the source check, on its own.
const ECHO = `<!doctype html><script>
window.addEventListener('message', m => {
  if (m.data && m.data.id) parent.postMessage({ ext: 'attest', id: m.data.id, response: '${FORGED}' }, '*');
});
</script>`;

const PAGE = `<!doctype html><html><head><title>QA</title></head><body><pre id="out"></pre><script>
const out = v => { document.getElementById('out').textContent = JSON.stringify(v); };
const p = new URLSearchParams(location.search).get('p');
const ready = () => new Promise(r => { const t = setInterval(() => { if (window.nostr) { clearInterval(t); r(); } }, 50); });
const within = (ms, pr) => Promise.race([pr, new Promise(r => setTimeout(() => r('__timeout__'), ms))]);
const frame = src => new Promise(r => {
  const f = document.createElement('iframe'); f.src = src; f.onload = () => r(f); document.body.appendChild(f);
});
let heard = 0;
window.addEventListener('message', m => {
  if (m.source !== window && m.data && m.data.ext === 'attest' && m.data.response) heard++;
});
(async () => {
  await ready();
  if (p === 'pubkey') {
    out({ result: await within(4000, window.nostr.getPublicKey()) });
  } else if (p === 'burst') {
    const now = Math.floor(Date.now() / 1000);
    const res = await Promise.all(Array.from({ length: 300 }, (_, i) =>
      within(30000, window.nostr.signEvent({ kind: 1, content: 'n' + i, tags: [], created_at: now }))
        .then(r => r === '__timeout__' ? 'hang' : (r && r.content === 'n' + i ? 'ok' : 'wrong'), () => 'error')));
    const counts = {}; res.forEach(x => counts[x] = (counts[x] || 0) + 1);
    out(counts);
  } else if (p === 'spray') {
    await frame('http://127.0.0.1:${OTHER}/spray');
    const result = await within(4000, window.nostr.getPublicKey());
    // Read the count a moment later: when a forged answer IS taken, the call settles before this
    // page's own listener has seen the message, and the control would read 0 for the wrong reason.
    await new Promise(r => setTimeout(r, 200));
    out({ result, heard });
  } else if (p === 'informed') {
    const f = await frame('http://127.0.0.1:${OTHER}/echo');
    const post = window.postMessage.bind(window);
    window.postMessage = (msg, target) => {
      if (msg && msg.ext === 'attest' && msg.type) f.contentWindow.postMessage({ id: msg.id }, '*');
      return post(msg, target);
    };
    const result = await within(4000, window.nostr.getPublicKey());
    await new Promise(r => setTimeout(r, 200));
    out({ result, heard });
  } else if (p === 'error') {
    try {
      await window.nostr.signEvent({ kind: 1, content: 'x', tags: [], created_at: 1, pubkey: '${'ff'.repeat(32)}' });
      out({ resolved: true });
    } catch (e) { out({ message: String(e.message), stack: String(e.stack) }); }
  } else if (p === 'frames') {
    // Any page, no permission needed: see what the provider's own code looks like from a stack.
    let stack = '';
    const post = window.postMessage.bind(window);
    window.postMessage = (msg, target) => {
      if (msg && msg.ext === 'attest' && msg.type) stack = String(new Error().stack);
      return post(msg, target);
    };
    await within(2000, window.nostr.getPublicKey().catch(() => null));
    out({ stack });
  }
})();
</script></body></html>`;

const serve = port => new Promise(resolve => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(req.url.startsWith('/spray') ? SPRAY : req.url.startsWith('/echo') ? ECHO : PAGE);
  });
  server.listen(port, '127.0.0.1', () => resolve(server));
});

const { ok, state } = reporter();
const xpi = newestXpi();
console.log(`\ntesting ${xpi.split('/').pop()}\n`);

const servers = [await serve(SITE), await serve(OTHER)];
const b = await startBrowser({ gdPort: GD_PORT, xpi });
const done = async () => { servers.forEach(s => s.close()); await b.finish(state.fail ? 1 : 0); };

/** Load a page, wait for its probe to write a result, return it. */
async function run(url, ms = 40000) {
  await b.goto(url);
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const e = await b.el('css selector', '#out');
    const t = e ? await b.text(e) : '';
    if (t) return JSON.parse(t);
    await b.wait(250);
  }
  return null;
}

// A profile with a standing grant for the test page, put in through the options page's own Import.
const sk = '11'.repeat(32);
const pub = getPublicKey(Uint8Array.from(Buffer.from(sk, 'hex')));
const granted = `127.0.0.1:${SITE}`;

console.log('=== setup ===');
ok("the extension's own pages are reachable", !!b.base, b.base);
if (!b.base) await done();
await b.openExt('options.html');
await b.click(await b.el('xpath', "//div[@class='profile-actions']/button[contains(., 'Import')]"));
await b.wait(300);
await b.type(await b.el('css selector', '.import-modal textarea'), JSON.stringify({
  privateKey: sk, name: 'qa', relays: {},
  permissions: { [granted]: { condition: 'forever', level: 20, created_at: Math.floor(Date.now() / 1000), decision: 'allow' } }
}));
await b.click(await b.el('css selector', '.import-modal button'));
await b.wait(1500);
ok('a profile with a grant for the test page is in place',
   !!(await b.el('css selector', `button[data-domain="${granted}"]`)));

console.log('\n=== the page still gets its own answers ===');
const own = await run(`http://${granted}/?p=pubkey`);
ok('getPublicKey returns the real key', own?.result === pub, own);
const burst = await run(`http://${granted}/?p=burst`, 60000);
ok('300 signEvent calls in flight each get their own event back', burst?.ok === 300, burst);

console.log('\n=== nobody else can answer for the extension ===');
// On an origin with no grant, so the real answer waits on a prompt nobody clicks and anything that
// arrives in the meantime is somebody else's.
const spray = await run(`http://localhost:${SITE}/?p=spray`);
ok('a frame posting every four-digit id was heard by the page', spray?.heard > 0, spray?.heard);
ok('  and none of it was taken as an answer', spray?.result === '__timeout__', spray?.result);
const informed = await run(`http://localhost:${SITE}/?p=informed`);
ok('a frame told the real request id did answer', informed?.heard > 0, informed?.heard);
ok('  and was ignored, because it is not this window', informed?.result === '__timeout__', informed?.result);

console.log("\n=== nothing hands the page the extension's address ===");
const err = await run(`http://${granted}/?p=error`);
ok('a refused signature still says why', /doesn't match the active profile/.test(err?.message ?? ''), err?.message);
ok('  and nothing in the error names moz-extension://', !/moz-extension:/.test(JSON.stringify(err ?? {})), err?.stack);
const frames = await run(`http://${granted}/?p=frames`);
ok("the provider's own frames do not name moz-extension:// either",
   frames && !/moz-extension:/.test(frames.stack), frames?.stack);

console.log(`\n${state.fail === 0 ? '✓' : '✗'} page answers: ${state.pass} passed, ${state.fail} failed`);
await done();
