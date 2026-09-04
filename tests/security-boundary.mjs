// What a web page may and may not ask this extension to do.
//
// This suite exists because the boundary it guards has been wrong twice in one week, in opposite
// directions, and neither failure announced itself.
//
// First: the content script forwarded whatever `type` a page put in a postMessage, and the
// background answered `getCachedPin` above every permission check. Any website could read the PIN
// that decrypts the private key. Reported upstream as nos2x-fox#68.
//
// Then the fix over-corrected. It refused those handlers to anything with a `sender.tab`, on the
// assumption that having a tab means being a web page. The options page is opened with
// tabs.create() and has one too, so the extension started refusing its own pages: Enable PIN
// Protection sent its message, got a refusal, and did nothing at all. No error, no prompt, no
// symptom except a button that did not work.
//
// So the boundary needs asserting from both sides, and one direction alone proves nothing. A suite
// that only checked that pages are refused would have passed happily while PIN setup was broken.
//
//   node tests/security-boundary.mjs
//
// Requires: Firefox, geckodriver (in ~/tools or $GECKODRIVER), and a build in var/releases.
import fs from 'fs';
import { startBrowser, startSite, reporter, newestXpi, EXT_CODE } from './harness.mjs';

const GD_PORT = Number(process.env.QA_PORT || 9720);
const SITE_PORT = Number(process.env.QA_SITE_PORT || 8720);

// Everything the background will answer that a page has no business asking for. Each one either
// hands over the PIN, changes it, or opens a window that can.
const PRIVILEGED = ['getCachedPin', 'verifyPin', 'setupPin', 'disablePin', 'openPinPrompt', 'encryptPrivateKey'];

// The NIP-07 surface. A guard that closed these would be worse than the hole it fixed — the
// extension would stop being a signer.
const NIP07 = ['getPublicKey', 'getRelays', 'signEvent',
               'nip04.encrypt', 'nip04.decrypt', 'nip44.encrypt', 'nip44.decrypt'];

const { ok, state } = reporter();
const xpi = newestXpi();
console.log(`\ntesting ${xpi.split('/').pop()}\n`);

const site = await startSite(SITE_PORT);
const b = await startBrowser({ gdPort: GD_PORT, xpi });

// Ask through the page's own bridge, exactly as a hostile site would.
const fromPage = type => b.jsAsync(`
  const cb = arguments[arguments.length - 1];
  const id = 'q' + Math.random().toString(36).slice(2);
  const to = setTimeout(() => cb('__silence__'), 4000);
  window.addEventListener('message', function h(m) {
    if (m.data && m.data.ext === ${JSON.stringify(EXT_CODE)} && m.data.id === id && m.data.response !== undefined) {
      clearTimeout(to); window.removeEventListener('message', h);
      cb(JSON.stringify(m.data.response));
    }
  });
  window.postMessage({ id, ext: ${JSON.stringify(EXT_CODE)}, type: ${JSON.stringify(type)}, params: {} }, '*');`);

await b.goto(`http://127.0.0.1:${SITE_PORT}/`);
await b.wait(2500);

console.log('=== a web page is refused the privileged calls ===');
for (const type of PRIVILEGED) {
    const res = String(await fromPage(type));
    // Refused by name, not merely failing. A handler that errored for some unrelated reason would
    // look identical from here, and would stop looking identical the day the reason went away.
    ok(`${type} is not callable from a page`, /not callable from a page/.test(res), res.slice(0, 90));
    // The belt-and-braces one: whatever else happens, a PIN must never come back to a page.
    ok(`  and no pin comes back`, !/"pin"\s*:\s*"/.test(res), res.slice(0, 90));
}

console.log('\n=== but the signer still answers what it is for ===');
for (const type of NIP07) {
    const res = String(await fromPage(type));
    ok(`${type} reaches the background`, res !== '__silence__' && !/not callable from a page/.test(res), res.slice(0, 70));
}

console.log('\n=== and the extension is not refused its own pages ===');
// This is the half the first fix broke, and it cannot be driven from out here: an extension page
// lives at moz-extension://<uuid>/, the uuid is random per profile, and Firefox will not tell an
// outside process what it assigned. Four ways were tried — the uuids preference, WebExtensionPolicy,
// AddonManager and Services from geckodriver's chrome sandbox — and none is reachable.
//
// So the decision is tested where it is made instead, by lifting it out of the shipped bundle. That
// is enough to catch the regression that happened, because the two implementations disagree on
// exactly one input: a sender that has BOTH a tab and an extension URL. The options page is opened
// with tabs.create(), so that is what it looks like — and a `sender.tab` check calls it a web page.
const bundle = fs.readFileSync(new URL('../dist/background.js', import.meta.url), 'utf8');
const BASE = 'moz-extension://11111111-2222-3333-4444-555555555555/';
const lifted = (() => {
    const at = bundle.indexOf('function fromOwnPage(');
    if (at < 0) return null;
    const body = bundle.slice(at, bundle.indexOf('\n  }', at) + 4);
    // The bundle reads the base URL through the polyfill; give it one that answers.
    const src = body.replace(/[\w.]*import_webextension_polyfill\d*\.default\.runtime/, 'RUNTIME');
    try { return new Function('RUNTIME', `${src}; return fromOwnPage;`)({ getURL: () => BASE }); }
    catch (e) { return null; }
})();

ok('fromOwnPage can be read out of the shipped bundle', typeof lifted === 'function');
if (typeof lifted === 'function') {
    // The regression, precisely. Both of these have a tab; only one is a web page.
    ok('the options page is recognised as our own, tab and all',
       lifted({ tab: { id: 7 }, url: BASE + 'options.html' }) === true);
    ok('a content script in a web page is not',
       lifted({ tab: { id: 8 }, url: 'https://example.com/article' }) === false);
    // The popup and the prompts have no tab, and must not be refused for that either.
    ok('the popup, which has no tab, is our own', lifted({ url: BASE + 'popup.html' }) === true);
    ok('a sender with no url at all is refused', lifted({ tab: { id: 9 } }) === false);
    // A page cannot fake it: startsWith on the real base is what decides.
    ok('a lookalike url does not pass', lifted({ url: 'https://moz-extension.example.com/options.html' }) === false);
}

console.log(`\n${state.fail === 0 ? '✓' : '✗'} security boundary: ${state.pass} passed, ${state.fail} failed`);
site.close();
await b.finish(state.fail ? 1 : 0);
