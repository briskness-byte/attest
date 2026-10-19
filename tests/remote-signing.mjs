#!/usr/bin/env node
// A page signing through a remote signer, as background.ts answers it.
//
//   node tests/remote-signing.mjs
//
// The real background, the real storage and the real NIP-46 client, against the fake relay and the
// fake remote signer; only the browser underneath is a stub. What is held here:
//
//   - nothing about it shows on the network until it is needed: no connection when the browser
//     starts, none when the profile becomes active, none for getPublicKey, which is answered from
//     storage — apps call it on every page load;
//   - the per-site permission still decides first: a page that may not ask never reaches the
//     remote signer;
//   - every failure ends in an answer the page can act on, worded the same every time: no answer in
//     time, a refusal, a login needed first, and too many requests waiting — that last one at once;
//   - the connection lives as long as the PIN does, and no longer, but is never cut under a request;
//   - and a local profile next to it signs exactly as before.
import { generateSecretKey, getPublicKey, nip44, verifyEvent } from 'nostr-tools';
import { rm } from 'node:fs/promises';

import { loadModule } from './load-background.mjs';
import { reporter } from './harness.mjs';
import stub, { control, reset, send, closeWindow } from './browser-stub.mjs';
import { startRelay } from './fake-relay.mjs';
import { startBunker } from './fake-bunker.mjs';

const { ok, state } = reporter();
process.on('unhandledRejection', error => {
  ok(`a promise was rejected with nobody listening (${error?.message ?? error})`, false);
});

const wait = ms => new Promise(r => setTimeout(r, ms));
const settle = async (rounds = 20) => { for (let i = 0; i < rounds; i++) await wait(0); };
const timed = async p => { const t = Date.now(); const value = await p; return { value, ms: Date.now() - t }; };
const now = () => Math.floor(Date.now() / 1000);
// verifyEvent throws on what is not an event, and an error answer is not one: false, not a crash.
const isSigned = e => { try { return verifyEvent(e); } catch { return false; } };
const hex = bytes => Buffer.from(bytes).toString('hex');

const HOST = 'https://example.com';
const HOST_B = 'https://other.example';
const PAGE = { url: 'https://example.com/page' }; // a content script's sender, not one of our pages
const PIN = '123456';
const LOCAL_SECRET = '5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a';
const LOCAL = getPublicKey(Buffer.from(LOCAL_SECRET, 'hex'));
const GRANT = { '20': { condition: 'forever', level: 20, created_at: now(), decision: 'allow' } };
const GRANTED = { [HOST]: GRANT, [HOST_B]: GRANT };

const { exports: background, outdir } = await loadModule('src/background.ts');
const { exports: nip46, outdir: nip46Dir } = await loadModule('src/nip46.ts');
const { exports: enc, outdir: encDir } = await loadModule('src/pinEncryption.ts');
const { REMOTE_LIMITS } = background;
const ask = (type, params = {}, host = HOST) => send({ type, params, host }, PAGE);
const local = async key => (await stub.storage.local.get(key))[key];

const relay = await startRelay();
const relay2 = await startRelay();
const bunker = startBunker({ relays: [relay.url], listen: [relay.url, relay2.url] });
await wait(300);
const baseline = relay.openSubscriptions(); // the bunker's own
const ours = () => relay.openSubscriptions() - baseline;

/** A client key the fake bunker has a session for: what connecting from the options page will do. */
async function pairedClientKey() {
  const key = generateSecretKey();
  const keyHex = hex(key);
  const signer = new nip46.RemoteSigner(key, bunker.signerPubkey, [relay.url]);
  await signer.connect(null, { timeoutMs: 5000 });
  signer.close(); // zeroes `key`, which is why the hex is taken first
  return keyHex;
}

async function clearWindows() {
  for (const id of [...control.windows.keys()]) await closeWindow(id);
  await settle();
}

/** A remote profile, active, and a local one next to it. Window ids carry on. */
async function profiles({ clientKey, pin = false, permissions = GRANTED, relays = [relay.url] }) {
  await clearWindows();
  const next = control.nextWindowId;
  reset();
  control.nextWindowId = next;
  await stub.storage.local.set({
    pin_enabled: pin,
    ...(pin ? { pin_kind: 'pin', pin_cache_duration: 2500 } : {}),
    active_public_key: bunker.userPubkey,
    profiles: {
      [bunker.userPubkey]: {
        privateKey: '', relays: {}, permissions,
        remote: { signerPubkey: bunker.signerPubkey, relays, clientKey }
      },
      [LOCAL]: { privateKey: pin ? await enc.encryptPrivateKey(PIN, LOCAL_SECRET) : LOCAL_SECRET, relays: {}, permissions: GRANTED }
    }
  });
  await settle();
}

const template = (content = 'hello') => ({ kind: 1, content, tags: [], created_at: now() });

// ---------------------------------------------------------------------------------------------
console.log('\nThe stable messages');
{
  const E = nip46.REMOTE_SIGNER_ERRORS;
  ok('no answer in time', E.timeout === 'the remote signer did not answer in time');
  ok('a refusal', E.refused === 'the remote signer refused');
  ok('a login needed first', E.loginNeeded === 'approve the login in your remote signer, then try again');
  ok('too many waiting', E.busy === 'too many requests are waiting for the remote signer, try again in a moment');
  ok('a page waits 30 s', REMOTE_LIMITS.timeoutMs === 30000, REMOTE_LIMITS.timeoutMs);
}
REMOTE_LIMITS.timeoutMs = 5000;

console.log('\nNothing goes out before it is needed');
{
  await profiles({ clientKey: await pairedClientKey() });
  await wait(300);
  ok('a remote profile stored and active opens no connection', ours() === 0, ours());

  const before = bunker.state.requests.length;
  const pk = await ask('getPublicKey');
  ok('getPublicKey is answered with the user key', pk === bunker.userPubkey, pk);
  ok('  from storage: the remote signer was not asked', bunker.state.requests.length === before);
  await wait(200);
  ok('  and still no connection', ours() === 0, ours());
  const relays = await ask('getRelays');
  ok('getRelays too', JSON.stringify(relays) === '{}' && bunker.state.requests.length === before && ours() === 0);

  const signed = await ask('signEvent', { event: template('first') });
  ok('the first signature connects, and is the user\'s', isSigned(signed) && signed.pubkey === bunker.userPubkey && signed.content === 'first', signed);
  ok('  there is a connection now', ours() === 1, ours());
}

console.log('\nWith no profile at all');
{
  await clearWindows();
  reset();
  await stub.storage.local.set({ pin_enabled: false });
  const answer = await ask('signEvent', { event: template('nobody to sign') });
  ok('the page is told there is no key yet', answer?.error?.message === background.NO_PROFILE_ERROR, answer);
  ok('  in words that say what to do', /no key in Attest yet, open it to create or connect one/.test(background.NO_PROFILE_ERROR));
  ok('  and no prompt is opened for it', control.created.length === 0, control.created.length);
  const pub = await ask('getPublicKey');
  ok('getPublicKey is told the same', pub?.error?.message === background.NO_PROFILE_ERROR, pub);
}

console.log('\nThe permission still decides first');
{
  await profiles({ clientKey: await pairedClientKey(), permissions: {} });
  const before = bunker.state.requests.length;
  const answer = ask('signEvent', { event: template() });
  await settle();
  const prompt = control.created.find(w => w.url.includes('prompt.html'));
  ok('a site with no permission gets the usual prompt', !!prompt);
  // The queue is stored as JSON, as in decisions.mjs.
  const [{ id }] = JSON.parse((await stub.storage.session.get('open_prompts')).open_prompts ?? '[]');
  await send({ prompt: true, id, condition: 'no', host: HOST }, { url: 'moz-extension://attest-test/prompt.html' });
  const refused = await answer;
  ok('refusing it refuses the page', /Insufficient permissions/.test(refused?.error?.message), refused);
  ok('  and the remote signer never heard of it', bunker.state.requests.length === before);
}

console.log('\nEvery call');
{
  await profiles({ clientKey: await pairedClientKey() });
  const peerKey = generateSecretKey();
  const peer = getPublicKey(peerKey);
  const c4 = await ask('nip04.encrypt', { peer, plaintext: 'note' });
  ok('nip04.encrypt', typeof c4 === 'string' && (await ask('nip04.decrypt', { peer, ciphertext: c4 })) === 'note', c4);
  const c44 = await ask('nip44.encrypt', { peer, plaintext: 'note 44' });
  ok('nip44.encrypt, readable by the peer', nip44.v2.decrypt(c44, nip44.v2.utils.getConversationKey(peerKey, bunker.userPubkey)) === 'note 44');
  ok('nip44.decrypt', (await ask('nip44.decrypt', { peer, ciphertext: c44 })) === 'note 44');

  const before = bunker.state.requests.length;
  const other = await ask('signEvent', { event: { ...template(), pubkey: LOCAL } });
  ok('an event naming another key is refused before it is sent', /doesn't match the active profile/.test(other?.error?.message) && bunker.state.requests.length === before, other);
  bunker.set({ mode: 'tamper', field: 'content' });
  const tampered = await ask('signEvent', { event: template() });
  ok('an event that comes back changed is refused', /the remote signer's event was refused: different content/.test(tampered?.error?.message), tampered);
  bunker.set({ mode: 'normal' });
}

console.log('\nWhen it fails, the page is told');
{
  await profiles({ clientKey: await pairedClientKey() });
  await ask('getPublicKey');

  REMOTE_LIMITS.timeoutMs = 1500;
  bunker.set({ mode: 'silent' });
  const silent = await timed(ask('signEvent', { event: template() }));
  ok('no answer: "the remote signer did not answer in time"', silent.value?.error?.message === 'the remote signer did not answer in time', silent.value);
  ok('  at the deadline', silent.ms >= 1400 && silent.ms < 3000, silent.ms);
  REMOTE_LIMITS.timeoutMs = 5000;

  bunker.set({ mode: 'refuse', error: 'not this one' });
  const no = await ask('signEvent', { event: template() });
  ok('a refusal: "the remote signer refused: <its reason>"', no?.error?.message === 'the remote signer refused: not this one', no);

  bunker.set({ mode: 'auth', url: 'https://signer.example/approve' });
  const tabsBefore = control.created.length;
  const login = await timed(ask('signEvent', { event: template() }));
  ok('a login needed: "approve the login in your remote signer, then try again"', login.value?.error?.message === 'approve the login in your remote signer, then try again', login.value);
  ok('  at once, not at the deadline', login.ms < 1500, login.ms);
  const opened = control.created.slice(tabsBefore).map(w => w.url);
  ok('  and the login page is opened in a tab', JSON.stringify(opened) === JSON.stringify(['https://signer.example/approve']), opened);
  await ask('signEvent', { event: template() });
  ok('  once, however many requests run into it', control.created.length === tabsBefore + 1, control.created.slice(tabsBefore).map(w => w.url));

  bunker.set({ mode: 'auth', url: 'http://signer.example/approve' });
  const before = control.created.length;
  const plain = await ask('signEvent', { event: template() });
  ok('a login page that is not https is not opened', control.created.length === before && /not https/.test(plain?.error?.message), plain);
  bunker.set({ mode: 'normal' });
}

console.log('\nMany at once, per site');
{
  await profiles({ clientKey: await pairedClientKey() });
  REMOTE_LIMITS.timeoutMs = 30000;
  const peerKey = generateSecretKey();
  const peer = getPublicKey(peerKey);
  const sealed = n => nip44.v2.encrypt('message ' + n, nip44.v2.utils.getConversationKey(peerKey, bunker.userPubkey));
  const decrypt = (n, host = HOST) => ask('nip44.decrypt', { peer, ciphertext: sealed(n) }, host);
  const busy = 'too many requests are waiting for the remote signer, try again in a moment';
  const late = 'the remote signer did not answer in time';
  ok('the limits are 8 at once and 50 queued per site, 200 queued in all',
     REMOTE_LIMITS.perSiteInFlight === 8 && REMOTE_LIMITS.perSiteQueue === 50 && REMOTE_LIMITS.totalQueued === 200, REMOTE_LIMITS);

  // A burst the size of a screenful of direct messages.
  bunker.set({ mode: 'slow', ms: 150 }, ['nip44_decrypt']);
  bunker.state.maxInProgress = 0;
  const burst = await Promise.all(Array.from({ length: 40 }, (_, n) => decrypt(n)));
  ok('a burst of 40 decrypts from one site all complete', burst.every((r, n) => r === 'message ' + n), burst.filter((r, n) => r !== 'message ' + n));
  ok('  never more than 8 of them at the remote signer at once', bunker.state.maxInProgress === 8, bunker.state.maxInProgress);

  // One site keeps the remote signer busy; another site is not stuck behind it.
  bunker.set({ mode: 'slow', ms: 2500 }, ['nip44_decrypt']);
  const busySite = Array.from({ length: 28 }, (_, n) => decrypt(n));
  await wait(200);
  ok('the badge says something is waiting', control.badgeText === '…', control.badgeText);
  const POPUP = { url: 'moz-extension://attest-test/popup.html' };
  const status = await send({ type: 'remoteSignerStatus' }, POPUP);
  ok('the popup is told how many', status?.waiting === 28, status);
  const fromPage = await send({ type: 'remoteSignerStatus' }, PAGE);
  ok('  and a page is not', fromPage?.waiting === undefined && !!fromPage?.error, fromPage);
  const other = await timed(ask('signEvent', { event: template('from elsewhere') }, HOST_B));
  ok('a second site is answered while the first keeps the remote signer busy with 28', isSigned(other.value) && other.ms < 2000, { ms: other.ms });
  const done = await Promise.all(busySite);
  ok('  and the first site\'s 28 all complete, queued ones included', done.every((r, n) => r === 'message ' + n), done.map(r => r?.error?.message ?? 'ok'));

  // Its queue full: refused at once, the rest still waiting.
  REMOTE_LIMITS.timeoutMs = 1500;
  bunker.set({ mode: 'silent' }, ['nip44_decrypt']);
  const filling = Array.from({ length: 8 + 50 }, (_, n) => decrypt(n));
  await wait(100);
  const over = await timed(decrypt(99));
  ok('a request that finds its site\'s queue full: "too many requests are waiting…"', over.value?.error?.message === busy, over.value);
  ok('  at once', over.ms < 200, over.ms);
  const filled = await Promise.all(filling);
  ok('  while the 58 it found there each got an answer of their own', filled.every(r => r?.error?.message === late), [...new Set(filled.map(r => r?.error?.message))]);

  // The queues of all sites together have a wall too.
  REMOTE_LIMITS.totalQueued = 60;
  const siteA = Array.from({ length: 8 + 50 }, (_, n) => decrypt(n));
  const siteB = Array.from({ length: 8 + 10 }, (_, n) => decrypt(n, HOST_B));
  await wait(100);
  const overall = await timed(decrypt(99, HOST_B));
  ok('a site with room in its own queue is refused when all queues together are full', overall.value?.error?.message === busy && overall.ms < 200, overall);
  await Promise.all([...siteA, ...siteB]);
  REMOTE_LIMITS.totalQueued = 200;
  await settle();
  ok('the badge clears when nothing waits', control.badgeText === '', control.badgeText);

  // The real deadline: 8 that time out at 30 s, and one queued 10 s later behind them. It must be
  // answered 30 s after it arrived — not 30 s after a slot came free, which would be 50 s.
  REMOTE_LIMITS.timeoutMs = 30000;
  const first = Array.from({ length: 8 }, (_, n) => decrypt(n));
  await wait(10000);
  const queuedLate = await timed(decrypt(9));
  ok('a queued request times out 30 s after it arrived', queuedLate.value?.error?.message === late && queuedLate.ms >= 29500 && queuedLate.ms < 31000, { ms: queuedLate.ms, m: queuedLate.value?.error?.message });
  await Promise.all(first);

  bunker.set({ mode: 'normal' });
  REMOTE_LIMITS.timeoutMs = 5000;
  const after = await ask('signEvent', { event: template() });
  ok('and the next request goes through', isSigned(after), after);
}

console.log('\nThe relays the remote signer asks for');
{
  const moving = startBunker({ relays: [relay.url], listen: [relay.url, relay2.url], switchTo: [relay2.url] });
  await wait(300);
  const key = generateSecretKey();
  const keyHex = hex(key);
  const pairing = new nip46.RemoteSigner(key, moving.signerPubkey, [relay.url]);
  await pairing.connect(null, { timeoutMs: 5000 });
  pairing.close();
  await profiles({ clientKey: keyHex });
  const p = await local('profiles');
  p[moving.userPubkey] = { privateKey: '', relays: {}, permissions: GRANTED, remote: { signerPubkey: moving.signerPubkey, relays: [relay.url], clientKey: keyHex } };
  await stub.storage.local.set({ profiles: p, active_public_key: moving.userPubkey });
  moving.state.publishTo = [relay.url];

  const signed = await ask('signEvent', { event: template() });
  ok('the first request is answered on the stored relay', isSigned(signed) && signed.pubkey === moving.userPubkey, signed);
  await wait(800);
  ok('switch_relays was asked after it', moving.state.requests.some(r => r.method === 'switch_relays'));
  ok('  and the new relays are stored on the profile', JSON.stringify((await local('profiles'))[moving.userPubkey].remote.relays) === JSON.stringify([relay2.url]));
  moving.state.publishTo = [relay2.url];
  const again = await ask('signEvent', { event: template() });
  ok('  and used', isSigned(again), again);
  moving.close();
}

console.log('\nWith a PIN, the connection lives as long as the PIN');
{
  const keyHex = await pairedClientKey();
  await profiles({ clientKey: await enc.encryptPrivateKey(PIN, keyHex), pin: true });
  ok('nothing connects before a request', ours() === 0, ours());

  const signing = ask('signEvent', { event: template('with a pin') });
  await settle(40);
  const win = control.created.at(-1);
  ok('the first request asks for the PIN', /pin\.html\?mode=unlock/.test(win?.url), win?.url);
  const id = new URL(win.url).searchParams.get('id');
  const unlocked = await send({ type: 'verifyPin', pin: PIN, id }, { url: 'moz-extension://attest-test/pin.html' });
  ok('  which unlocks with the PIN that opens the client key', unlocked?.success === true, unlocked);
  const signed = await signing;
  ok('  and then it is signed remotely', isSigned(signed) && signed.content === 'with a pin', signed);
  ok('  over a connection', ours() === 1, ours());

  const windowsBefore = control.created.length;
  const quick = await ask('signEvent', { event: template() });
  ok('while the PIN is cached, the next request needs no PIN', isSigned(quick) && control.created.length === windowsBefore, { quick, opened: control.created.slice(windowsBefore).map(w => w.url) });

  await wait(3000); // past the 2.5 s cache
  ok('when the PIN expires, the connection closes', ours() === 0, ours());

  // A request still in flight when the PIN expires keeps its connection until it is answered.
  const again = ask('signEvent', { event: template() });
  await settle(40);
  const win2 = control.created.at(-1);
  ok('the next request asks for the PIN again', /pin\.html\?mode=unlock/.test(win2?.url) && win2 !== win, win2?.url);
  bunker.set({ mode: 'slow', ms: 3500 }, ['sign_event']);
  await send({ type: 'verifyPin', pin: PIN, id: new URL(win2.url).searchParams.get('id') }, { url: 'moz-extension://attest-test/pin.html' });
  const slow = await again;
  ok('a request that outlives the PIN is still answered, not cut off', isSigned(slow), slow);
  bunker.set({ mode: 'normal' });
  await wait(300);
  ok('  and the connection closes after it', ours() === 0, ours());

  // Unlocked under a long cache, which is then shortened in the options: the timer set for the long
  // one has not fired, and the connection must not outlive the short one because of that.
  await stub.storage.local.set({ pin_cache_duration: 60000 });
  const third = ask('signEvent', { event: template() });
  await settle(40);
  await send({ type: 'verifyPin', pin: PIN, id: new URL(control.created.at(-1).url).searchParams.get('id') }, { url: 'moz-extension://attest-test/pin.html' });
  ok('unlocked again, under a long cache', isSigned(await third));
  await stub.storage.local.set({ pin_cache_duration: 1 });
  await wait(50);
  const windowsBefore2 = control.created.length;
  const fourth = ask('signEvent', { event: template() });
  await settle(40);
  ok('after the cache is shortened, the next request asks for the PIN again', /pin\.html\?mode=unlock/.test(control.created.at(-1)?.url) && control.created.length === windowsBefore2 + 1, control.created.slice(windowsBefore2).map(w => w.url));
  await closeWindow(control.created.at(-1).id);
  const refused = await fourth;
  ok('  and closing that window refuses the page with a reason', typeof refused?.error?.message === 'string', refused);
  await wait(300);
  ok('  and the old connection is gone', ours() === 0, ours());
}

console.log('\nA local profile beside it');
{
  await profiles({ clientKey: await pairedClientKey() });
  await ask('signEvent', { event: template() });
  ok('the remote profile is connected', ours() === 1, ours());
  await stub.storage.local.set({ active_public_key: LOCAL, private_key: LOCAL_SECRET });
  await wait(300);
  ok('switching to the local profile closes the remote connection', ours() === 0, ours());
  const before = bunker.state.requests.length;
  const signed = await ask('signEvent', { event: template('local') });
  ok('the local key signs, as before', isSigned(signed) && signed.pubkey === LOCAL, signed);
  ok('  without the remote signer', bunker.state.requests.length === before && ours() === 0);
  ok('getPublicKey answers the local key', (await ask('getPublicKey')) === LOCAL);
}

await clearWindows();
bunker.close();
await relay.close();
await relay2.close();
for (const dir of [outdir, nip46Dir, encDir]) await rm(dir, { recursive: true, force: true });

console.log(`\n${state.pass} passed, ${state.fail} failed`);
process.exit(state.fail ? 1 : 0);
