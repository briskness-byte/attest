// What the extension's own pages write, and what they show.
//
// Both found in the audit of 11 September 2026 and shown in this browser before they were fixed:
//
//   - The options page loaded every profile once, when it opened, and wrote that copy back.
//     Revoke a site, rename the profile, and the site was answered again without a prompt. Save key
//     did the same for every profile. It also ran the other way: a site granted while the page was
//     open lost its grant.
//   - Answering the last of several queued prompts blanked the prompt window. The index pointed
//     past the end of the shrunken queue, and the only way out was closing the window, which
//     rejects everything still waiting.
//
//   node tests/extension-pages.mjs
//
// Requires: Firefox, geckodriver 0.36+ (in ~/tools or $GECKODRIVER), and a package in var/releases
// or at $QA_XPI.
import http from 'http';
import path from 'path';
import { createRequire } from 'module';
import { startBrowser, reporter, newestXpi, ROOT } from './harness.mjs';

const require = createRequire(path.join(ROOT, 'package.json'));
const { getPublicKey, nip19 } = require('nostr-tools');

const GD_PORT = Number(process.env.QA_PORT || 9740);
const SITE = Number(process.env.QA_SITE_PORT || 8740);
const OTHER = SITE + 1;

// Asks for the public key and reports what came back within three seconds. '__asked__' means
// nothing did: the request is waiting on a prompt, i.e. the site holds no grant.
const PAGE = `<!doctype html><html><head><title>QA</title></head><body><pre id="out"></pre><script>
const ready = () => new Promise(r => { const t = setInterval(() => { if (window.nostr) { clearInterval(t); r(); } }, 50); });
(async () => {
  await ready();
  const result = await Promise.race([
    window.nostr.getPublicKey().catch(e => 'rejected: ' + e.message),
    new Promise(r => setTimeout(() => r('__asked__'), 3000))
  ]);
  document.getElementById('out').textContent = JSON.stringify({ result });
})();
</script></body></html>`;

const serve = port => new Promise(resolve => {
  const server = http.createServer((_, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(PAGE);
  });
  server.listen(port, '127.0.0.1', () => resolve(server));
});

const hex = h => Uint8Array.from(Buffer.from(h, 'hex'));
const sk1 = '11'.repeat(32);
const pub1 = getPublicKey(hex(sk1));
const sk2 = '22'.repeat(32);

// Origins, since that is what permissions are keyed on (1.25.0) and what the prompt shows.
const granted = `http://127.0.0.1:${SITE}`; // granted from the start, revoked during the run
const later = `http://localhost:${SITE}`;   // granted through a prompt while the options page is open
const other = `http://127.0.0.1:${OTHER}`;  // only ever asks

const { ok, state } = reporter();
const xpi = newestXpi();
console.log(`\ntesting ${xpi.split('/').pop()}\n`);

const servers = [await serve(SITE), await serve(OTHER)];
const b = await startBrowser({ gdPort: GD_PORT, xpi });
const done = async () => { servers.forEach(s => s.close()); await b.finish(state.fail ? 1 : 0); };

/** What `origin` gets back for getPublicKey right now. */
async function ask(origin) {
  await b.goto(`${origin}/`);
  const end = Date.now() + 20000;
  while (Date.now() < end) {
    const e = await b.el('css selector', '#out');
    const t = e ? await b.text(e) : '';
    if (t) return JSON.parse(t).result;
    await b.wait(250);
  }
  return '(no result)';
}

async function findPromptWindow() {
  for (const h of await b.handles()) {
    await b.switchTo(h);
    if ((await b.url())?.includes('/prompt.html')) return h;
  }
  return null;
}

const byText = (tag, text) => b.el('xpath', `//${tag}[contains(., ${JSON.stringify(text)})]`);
const hostRow = host => b.el('css selector', `button[data-domain="${host}"]`);

async function rename(suffix) {
  await b.click(await byText('button', 'Rename'));
  await b.wait(300);
  await b.type(await b.el('css selector', '#profile-name'), suffix);
  await b.click(await b.el('css selector', '.rename-modal button'));
  await b.wait(1000);
}

async function saveNewKey(skHex) {
  await b.click(await b.el('xpath', "//div[@class='profile-actions']/button[contains(., 'New')]"));
  await b.wait(500);
  await b.type(await b.el('css selector', '#private-key'), nip19.nsecEncode(hex(skHex)));
  await b.click(await byText('button', 'Save key'));
}

// ---- a profile with a grant for one test site, through the options page's own Import ----
console.log('=== setup ===');
ok("the extension's own pages are reachable", !!b.base, b.base);
if (!b.base) await done();
await b.openExt('options.html');
const options = await b.window();
await b.click(await b.el('xpath', "//div[@class='profile-actions']/button[contains(., 'Import')]"));
await b.wait(300);
await b.type(await b.el('css selector', '.import-modal textarea'), JSON.stringify({
  privateKey: sk1, name: 'qa', relays: {},
  permissions: { [granted]: { condition: 'forever', level: 20, created_at: Math.floor(Date.now() / 1000), decision: 'allow' } }
}));
await b.click(await b.el('css selector', '.import-modal button'));
await b.wait(1500);
ok('a profile with a grant for the test site is in place', !!(await hostRow(granted)));

const sites = await b.newTab();
await b.switchTo(sites);
ok(`${granted} is answered from the start`, (await ask(granted)) === pub1);

// ---- the prompt queue ----
console.log('\n=== the prompt window, with two prompts queued ===');
ok(`${later} has to ask`, (await ask(later)) === '__asked__');
ok(`${other} has to ask`, (await ask(other)) === '__asked__');
const promptWin = await findPromptWindow();
ok('the prompt window is open', !!promptWin);
if (promptWin) {
  const counter = await b.el('css selector', '.prompt-navigator span');
  ok('it holds both prompts', counter && (await b.text(counter)).replace(/\s/g, '') === '1/2');
  await b.click(await b.el('css selector', '.prompt-navigator button[title="Next"]'));
  await b.wait(300);
  await b.click(await byText('button', 'Reject just this'));
  await b.wait(1500);
  const heading = await b.el('css selector', 'h1.prompt-host');
  const shown = heading ? await b.text(heading) : '';
  ok('answering the last prompt leaves the one before it on screen', shown === later,
     shown || '(blank window)');
  // Granted from the prompt, by the background, while the options page is open in another tab.
  if (heading) {
    await b.click(await byText('button', 'Authorize forever'));
    await b.wait(1500);
  }
}
await b.switchTo(sites);
ok(`${later} is answered once it is granted`, (await ask(later)) === pub1);

// ---- the options page writes only what it changes ----
console.log('\n=== the options page, open the whole time ===');
await b.switchTo(options);
await b.wait(500);
ok('a site granted while the page is open shows up in its table', !!(await hostRow(later)));
await b.click(await hostRow(granted));
await b.wait(300);
await b.acceptAlert();
await b.wait(1000);
ok('a revoked site leaves the table', !(await hostRow(granted)));

await rename(' renamed');
await b.switchTo(sites);
ok('after a rename the revoked site still has to ask', (await ask(granted)) === '__asked__');
ok('  and the site granted meanwhile is still answered', (await ask(later)) === pub1);

await b.switchTo(options);
await saveNewKey(sk2);
await b.wait(1500);
const profileCount = (await b.elements('css selector', '#selected-profile select option')).length;
ok('Save key adds a second profile', profileCount === 2, profileCount);
await b.switchTo(sites);
ok('after Save key the revoked site still has to ask', (await ask(granted)) === '__asked__');
ok('  and the site granted meanwhile is still answered', (await ask(later)) === pub1);

console.log('\n=== the Keys section for a saved profile ===');
await b.switchTo(options);
const keyField = await b.el('css selector', '#private-key');
ok('the stored key is shown, masked', !!keyField && (await b.attr(keyField, 'type')) === 'password');
ok('  and cannot be typed into', !!keyField && (await b.attr(keyField, 'readonly')) !== null);
await b.click(await b.el('css selector', "button[title='Show the key']"));
ok('the eye reveals it — it has something to reveal', (await b.attr(keyField, 'type')) === 'text');
await b.click(await byText('button', 'Add another key'));
await b.wait(500);
const pasteHere = await b.el('css selector', '#private-key');
ok('"Add another key" opens an editable field in this same section',
   !!pasteHere && (await b.attr(pasteHere, 'readonly')) === null);
await b.click(await byText('button', 'Cancel'));
await b.wait(300);
ok('Cancel puts the saved key back on screen',
   !!(await byText('button', 'Add another key')));

console.log('\n=== saving a key that already has a profile ===');
await b.switchTo(options);
await saveNewKey(sk1);
await b.wait(300);
const dismissed = await b.dismissAlert();
ok('asks before replacing that profile', !dismissed?.value?.error, dismissed?.value?.error);
await b.wait(500);
await b.switchTo(sites);
ok('  and saying no leaves its grants as they were', (await ask(later)) === pub1);

console.log('\n=== a new profile that was never saved ===');
// The dismissed Save key above leaves "(new profile)" selected, unsaved.
await b.switchTo(options);
const unsavedBefore = await b.el('xpath', "//option[contains(., '(new profile)')]");
ok('there is an unsaved new profile to delete', !!unsavedBefore);
await b.click(await b.el('xpath', "//div[@class='profile-actions']/button[contains(., 'Delete')]"));
await b.wait(500);
// Look for a dialog before anything else. With one open, WebDriver fails the next element lookup
// with "unexpected alert open", which reads as "not found" — so the check below would pass for the
// wrong reason. Dismissing answers both questions: an error here means there was no dialog.
const dialog = await b.dismissAlert();
ok('it asks nothing about a profile that was never saved', !!dialog?.value?.error,
   'a confirmation dialog opened');
ok('Delete discards it', !(await b.el('xpath', "//option[contains(., '(new profile)')]")));

console.log(`\n${state.fail === 0 ? '✓' : '✗'} extension pages: ${state.pass} passed, ${state.fail} failed`);
await done();
