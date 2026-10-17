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
const PAGE = { url: 'https://example.com/page' }; // a content script's sender, not one of our pages
const PIN = '123456';
const LOCAL_SECRET = '5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a';
const LOCAL = getPublicKey(Buffer.from(LOCAL_SECRET, 'hex'));
const GRANTED = { [HOST]: { '20': { condition: 'forever', level: 20, created_at: now(), decision: 'allow' } } };

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

console.log('\nToo many at once');
{
  await profiles({ clientKey: await pairedClientKey() });
  REMOTE_LIMITS.timeoutMs = 2000;
  bunker.set({ mode: 'silent' });
  const waiting = Array.from({ length: REMOTE_LIMITS.maxInFlight }, () => ask('signEvent', { event: template() }));
  await wait(100);
  ok('the badge says something is waiting', control.badgeText === '…', control.badgeText);
  const over = await timed(ask('signEvent', { event: template() }));
  ok('one over the cap: "too many requests are waiting…"', over.value?.error?.message === 'too many requests are waiting for the remote signer, try again in a moment', over.value);
  ok('  at once', over.ms < 200, over.ms);
  const rest = await Promise.all(waiting);
  ok('those within the cap waited for their own answer', rest.every(r => r?.error?.message === 'the remote signer did not answer in time'), rest.map(r => r?.error?.message));
  await settle();
  ok('the badge clears when nothing waits', control.badgeText === '', control.badgeText);
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
