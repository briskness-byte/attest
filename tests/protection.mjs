// Protecting the keys with a passphrase, through the windows a person actually uses.
//
// The logic is pinned in passphrase.mjs. This drives the real windows, because that is where a
// passphrase would die quietly: the PIN window kept digits and nothing else, so a passphrase typed
// into it would have been cut down to its numbers without a word — and the key encrypted with
// whatever was left.
//
//   node tests/protection.mjs
//
// Requires: Firefox, geckodriver 0.36+ (in ~/tools or $GECKODRIVER), and a package in var/releases
// or at $QA_XPI.
import http from 'http';
import path from 'path';
import { createRequire } from 'module';
import { startBrowser, reporter, newestXpi, ROOT } from './harness.mjs';

const require = createRequire(path.join(ROOT, 'package.json'));
const { getPublicKey } = require('nostr-tools');

const GD_PORT = Number(process.env.QA_PORT || 9760);
const SITE = Number(process.env.QA_SITE_PORT || 8760);
const PASSPHRASE = 'correct horse battery staple';

// Asks for the public key and waits long enough for somebody to unlock.
const PAGE = `<!doctype html><html><head><title>QA</title></head><body><pre id="out"></pre><script>
const ready = () => new Promise(r => { const t = setInterval(() => { if (window.nostr) { clearInterval(t); r(); } }, 50); });
(async () => {
  await ready();
  const result = await Promise.race([
    window.nostr.getPublicKey().catch(e => 'rejected: ' + e.message),
    new Promise(r => setTimeout(() => r('__nothing__'), 60000))
  ]);
  document.getElementById('out').textContent = JSON.stringify({ result });
})();
</script></body></html>`;

const server = await new Promise(resolve => {
  const s = http.createServer((_, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(PAGE); });
  s.listen(SITE, '127.0.0.1', () => resolve(s));
});

const sk = '11'.repeat(32);
const pub = getPublicKey(Uint8Array.from(Buffer.from(sk, 'hex')));
const site = `http://127.0.0.1:${SITE}`;

const { ok, state } = reporter();
const xpi = newestXpi();
console.log(`\ntesting ${xpi.split('/').pop()}\n`);
const b = await startBrowser({ gdPort: GD_PORT, xpi });
const done = async () => { server.close(); await b.finish(state.fail ? 1 : 0); };

const byText = (tag, text) => b.el('xpath', `//${tag}[contains(., ${JSON.stringify(text)})]`);

/** Switch to the first window whose address contains `part`; null if there is none. */
async function findWindow(part) {
  for (const h of await b.handles()) {
    await b.switchTo(h);
    if ((await b.url())?.includes(part)) return h;
  }
  return null;
}

// ---- a profile with a standing grant for the test site ----
console.log('=== setup ===');
ok("the extension's own pages are reachable", !!b.base, b.base);
if (!b.base) await done();
await b.openExt('options.html');
const options = await b.window();
await b.click(await b.el('xpath', "//div[@class='profile-actions']/button[contains(., 'Import')]"));
await b.wait(300);
await b.type(await b.el('css selector', '.import-modal textarea'), JSON.stringify({
  privateKey: sk, name: 'qa', relays: {},
  permissions: { [site]: { condition: 'forever', level: 20, created_at: Math.floor(Date.now() / 1000), decision: 'allow' } }
}));
await b.click(await b.el('css selector', '.import-modal button'));
await b.wait(1500);
ok('a profile with a grant for the test site is in place', !!(await b.el('css selector', `button[data-domain="${site}"]`)));

// ---- turning protection on ----
console.log('\n=== turning protection on ===');
const turnOn = await byText('button', 'Turn protection on');
ok('the options page offers to turn protection on', !!turnOn);
await b.click(turnOn);
await b.wait(1500);
const setupWin = await findWindow('/pin.html');
ok('the protection window opens', !!setupWin);
if (setupWin) {
  const passphrase = await b.el('css selector', 'input[name="secret-kind"][value="passphrase"]');
  const pin = await b.el('css selector', 'input[name="secret-kind"][value="pin"]');
  ok('it offers a passphrase and a PIN', !!passphrase && !!pin);
  ok('  starting on the passphrase', !!passphrase && (await b.selected(passphrase)) === true);

  await b.click(pin);
  await b.wait(200);
  const help = await b.el('css selector', '.secret-kind-help');
  const warning = help ? await b.text(help) : '';
  ok('choosing a PIN says plainly what it does not protect against',
     /copies your Firefox profile/.test(warning), warning);

  await b.click(passphrase);
  await b.wait(200);
  await b.type(await b.el('css selector', '#pin-input'), PASSPHRASE);
  await b.type(await b.el('css selector', '#confirm-pin-input'), PASSPHRASE);
  const kept = await b.js('return document.getElementById("pin-input").value.length');
  ok('the field keeps a passphrase as typed, letters and spaces included', kept === PASSPHRASE.length, kept);
  await b.click(await b.el('css selector', '.action-buttons button'));
  await b.wait(3000); // 600 000 rounds, several times over
}

await b.switchTo(options);
const status = await b.el('css selector', '.pin-status-message');
const said = status ? await b.text(status) : '(no status line)';
ok('the options page says the keys are encrypted with a passphrase', /passphrase/.test(said), said);
ok('  and offers to turn it off, without being reloaded', !!(await byText('button', 'Turn protection off')));

// ---- a site then needs the passphrase ----
console.log('\n=== a site that needs the key ===');
// Setting up caches the secret for the default ten seconds; wait them out, so the site has to ask.
await b.wait(11000);
const sites = await b.newTab();
await b.switchTo(sites);
await b.goto(`${site}/`);
await b.wait(2000);
const unlockWin = await findWindow('/pin.html');
ok('the unlock window opens', !!unlockWin);
if (unlockWin) {
  const label = await b.el('css selector', 'label[for="pin-input"]');
  ok('  and asks for the passphrase, not a PIN', label && /Passphrase/.test(await b.text(label)));
  await b.type(await b.el('css selector', '#pin-input'), PASSPHRASE);
  await b.click(await b.el('css selector', '.action-buttons button'));
  await b.wait(2000);
}
await b.switchTo(sites);
let result = null;
for (let i = 0; i < 40 && !result; i++) {
  const e = await b.el('css selector', '#out');
  const t = e ? await b.text(e) : '';
  if (t) result = JSON.parse(t).result;
  else await b.wait(250);
}
ok('once unlocked, the site is answered with the real key', result === pub, result);

console.log(`\n${state.fail === 0 ? '✓' : '✗'} protection: ${state.pass} passed, ${state.fail} failed`);
await done();
