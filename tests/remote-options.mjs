// Connecting a remote signer from the options page, in a real Firefox, and signing through it.
//
// remote-connect.mjs holds the rules against the background alone. This is the wiring: the page
// sends the address, shows whose key the remote signer signs with, stores nothing until "Use this
// remote signer", and a web page is then signed for through it. Export leaves the client key out,
// Import refuses a remote profile, and Disconnect logs out and deletes.
//
// The relay and the remote signer are the fakes in tests/, run here in node; Firefox reaches them
// on 127.0.0.1, which is the one place a ws:// relay is accepted.
//
//   node tests/remote-options.mjs
//
// Requires: Firefox, geckodriver 0.36+ (in ~/tools or $GECKODRIVER), and a package in var/releases
// or at $QA_XPI.
import http from 'http';
import path from 'path';
import { createRequire } from 'module';
import { startBrowser, reporter, newestXpi, ROOT } from './harness.mjs';
import { startRelay } from './fake-relay.mjs';
import { startBunker } from './fake-bunker.mjs';

const require = createRequire(path.join(ROOT, 'package.json'));
const { nip19, verifyEvent } = require('nostr-tools');

const GD_PORT = Number(process.env.QA_PORT || 9770);
const SITE = Number(process.env.QA_SITE_PORT || 8770);
const origin = `http://127.0.0.1:${SITE}`;

// Signs one event and reports it, or what went wrong, within 20 seconds.
const PAGE = `<!doctype html><html><head><title>QA</title></head><body><pre id="out"></pre><script>
const ready = () => new Promise(r => { const t = setInterval(() => { if (window.nostr) { clearInterval(t); r(); } }, 50); });
(async () => {
  await ready();
  const result = await Promise.race([
    window.nostr.signEvent({ kind: 1, content: 'through the remote signer', tags: [], created_at: Math.floor(Date.now() / 1000) })
      .catch(e => 'rejected: ' + e.message),
    new Promise(r => setTimeout(() => r('__nothing__'), 20000))
  ]);
  document.getElementById('out').textContent = JSON.stringify({ result });
})();
</script></body></html>`;

const server = await new Promise(resolve => {
  const s = http.createServer((_, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(PAGE); });
  s.listen(SITE, '127.0.0.1', () => resolve(s));
});

const relay = await startRelay();
const bunker = startBunker({ relays: [relay.url], secret: 'qa-pairing-secret' });
await new Promise(r => setTimeout(r, 300));

const { ok, state } = reporter();
const xpi = newestXpi();
console.log(`\ntesting ${xpi.split('/').pop()}\n`);

const b = await startBrowser({ gdPort: GD_PORT, xpi });
const done = async () => {
  server.close();
  bunker.close();
  await relay.close();
  await b.finish(state.fail ? 1 : 0);
};

const byText = (tag, text) => b.el('xpath', `//${tag}[contains(., ${JSON.stringify(text)})]`);
/** storage.local as the extension sees it, read from one of its own pages. */
const stored = () => b.jsAsync(
  `const done = arguments[arguments.length - 1];
   browser.storage.local.get(null).then(d => done(d));`
);
async function waitFor(check, ms = 15000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const value = await check();
    if (value) return value;
    await b.wait(250);
  }
  return null;
}

console.log('=== connecting from the options page ===');
ok("the extension's own pages are reachable", !!b.base, b.base);
if (!b.base) await done();
await b.openExt('options.html');
const options = await b.window();

const field = await b.el('css selector', '#bunker-uri');
ok('a fresh install offers to connect a remote signer', !!field);
await b.type(field, bunker.uri());
await b.click(await byText('button', 'Connect'));
const shown = await waitFor(async () => {
  const e = await b.el('css selector', '#remote-offer-npub');
  return e ? b.text(e) : null;
});
ok('it shows whose key the remote signer signs with', shown === nip19.npubEncode(bunker.userPubkey), shown);
ok('  and the address is no longer on the page: it carried the secret', !(await b.el('css selector', '#bunker-uri')));
const before = await stored();
ok('nothing is stored yet', !before.profiles || !before.profiles[bunker.userPubkey]);
ok('  and the secret is not in storage', !JSON.stringify(before).includes('qa-pairing-secret'));

await b.click(await byText('button', 'Use this remote signer'));
const after = await waitFor(async () => {
  const d = await stored();
  return d.profiles?.[bunker.userPubkey] ? d : null;
});
ok('"Use this remote signer" stores the profile', !!after?.profiles?.[bunker.userPubkey]?.remote);
ok('  makes it the one that signs', after?.active_public_key === bunker.userPubkey, after?.active_public_key);
ok('  and keeps the secret out of storage', !JSON.stringify(after ?? {}).includes('qa-pairing-secret'));
ok('the Keys section says it signs through a remote signer', !!(await byText('p', 'This profile signs through a remote signer')));
ok('  and offers no private key to show or copy', !(await b.el('css selector', '#private-key')));
const clientKey = after?.profiles?.[bunker.userPubkey]?.remote?.clientKey ?? '';

console.log('\n=== a web page, signed for through it ===');
// The grant is written straight to storage: the permission prompt is tested elsewhere, and is the
// same for a remote profile.
await b.jsAsync(
  `const done = arguments[arguments.length - 1];
   browser.storage.local.get('profiles').then(d => {
     d.profiles[${JSON.stringify(bunker.userPubkey)}].permissions = {
       ${JSON.stringify(origin)}: { '20': { condition: 'forever', level: 20, created_at: Math.floor(Date.now() / 1000), decision: 'allow' } }
     };
     return browser.storage.local.set({ profiles: d.profiles });
   }).then(() => done(true));`
);
const site = await b.newTab();
await b.switchTo(site);
await b.goto(`${origin}/`);
const result = await waitFor(async () => {
  const e = await b.el('css selector', '#out');
  const t = e ? await b.text(e) : '';
  return t ? JSON.parse(t).result : null;
}, 30000);
let signedOk = false;
try { signedOk = verifyEvent(result); } catch {}
ok('the page gets an event signed by the remote signer\'s user key', signedOk && result.pubkey === bunker.userPubkey, result);
ok('  which the remote signer was asked for', bunker.state.requests.some(r => r.method === 'sign_event'));

console.log('\n=== export and import ===');
await b.switchTo(options);
await b.openExt('options.html');
await b.click(await b.el('xpath', "//div[@class='profile-actions']/button[contains(., 'Export')]"));
await b.wait(500);
const exported = await b.text(await b.el('css selector', '.export-modal code'));
ok('Export shows the profile', exported.includes(bunker.signerPubkey), exported.slice(0, 80));
ok('  without the client key', clientKey.length > 0 && !exported.includes(clientKey));
await b.openExt('options.html');

await b.click(await b.el('xpath', "//div[@class='profile-actions']/button[contains(., 'Import')]"));
await b.wait(300);
await b.type(await b.el('css selector', '.import-modal textarea'), JSON.stringify({
  privateKey: '', relays: {}, permissions: {},
  remote: { signerPubkey: 'ab'.repeat(32), relays: ['wss://elsewhere.example'], clientKey: 'cd'.repeat(32) }
}));
await b.click(await b.el('css selector', '.import-modal button'));
await b.wait(1000);
const afterImport = await stored();
ok('Import refuses a remote profile', JSON.stringify(afterImport.profiles[bunker.userPubkey].remote) === JSON.stringify(after.profiles[bunker.userPubkey].remote)
   && !JSON.stringify(afterImport).includes('elsewhere.example'));
await b.openExt('options.html');

console.log('\n=== disconnecting ===');
await b.click(await byText('button', 'Disconnect'));
await b.wait(300);
const accepted = await b.acceptAlert();
ok('Disconnect asks first', !accepted?.value?.error, accepted?.value?.error);
const gone = await waitFor(async () => {
  const d = await stored();
  return d.profiles && !d.profiles[bunker.userPubkey] ? d : null;
});
ok('the profile is deleted', !!gone);
ok('  with its client key', !JSON.stringify(gone ?? {}).includes(clientKey));
ok('the remote signer was logged out of', bunker.state.requests.some(r => r.method === 'logout'));

console.log(`\n${state.fail === 0 ? '✓' : '✗'} remote options: ${state.pass} passed, ${state.fail} failed`);
await done();
