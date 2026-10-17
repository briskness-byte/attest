#!/usr/bin/env node
// Connecting a remote signer and disconnecting it, as background.ts does it for the options page.
//
//   node tests/remote-connect.mjs
//
// Connecting is where a user pastes a secret, so it is where the care goes:
//
//   - the one-time secret in the bunker:// address is sent once and stored nowhere;
//   - nothing is stored until the user has seen whose key the remote signer signs with, and said
//     yes; saying no, or saying nothing for ten minutes, tells the remote signer and forgets the key;
//   - a login the remote signer asks for while connecting is waited for (up to five minutes), with
//     its page opened — unlike a page's request, which is answered at once (remote-signing.mjs);
//   - with protection on, the client key is stored encrypted from the first write;
//   - none of it can be asked for by a web page.
//
// Disconnecting sends logout and deletes the profile and its key whatever the remote signer says.
import { getPublicKey } from 'nostr-tools';
import { rm } from 'node:fs/promises';

import { loadModule, OWN_PAGE } from './load-background.mjs';
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
const isSigned = (e, verify) => { try { return verify(e); } catch { return false; } };

const PIN = '123456';
const HOST = 'https://example.com';
const PAGE = { url: 'https://example.com/page' };
const LOCAL_SECRET = '5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a';
const LOCAL = getPublicKey(Buffer.from(LOCAL_SECRET, 'hex'));
const GRANT = { '20': { condition: 'forever', level: 20, created_at: now(), decision: 'allow' } };

const { exports: background, outdir } = await loadModule('src/background.ts');
const { exports: enc, outdir: encDir } = await loadModule('src/pinEncryption.ts');
const { verifyEvent } = await import('nostr-tools');
const { CONNECT_LIMITS } = background;
const DEFAULTS = { ...CONNECT_LIMITS };

const local = async key => (await stub.storage.local.get(key))[key];
const everything = async () => JSON.stringify([await stub.storage.local.get(null), await stub.storage.session.get(null)]);
const connect = uri => send({ type: 'connectRemoteSigner', uri }, OWN_PAGE);
const confirm = id => send({ type: 'confirmRemoteSigner', id }, OWN_PAGE);
const logouts = bunker => bunker.state.requests.filter(r => r.method === 'logout').length;

async function clearWindows() {
  for (const id of [...control.windows.keys()]) await closeWindow(id);
  await settle();
}

/** A local profile, active, and nothing else. Window ids carry on. */
async function withLocal(extra = {}) {
  await clearWindows();
  const next = control.nextWindowId;
  reset();
  control.nextWindowId = next;
  await stub.storage.local.set({
    pin_enabled: false,
    private_key: LOCAL_SECRET,
    active_public_key: LOCAL,
    profiles: { [LOCAL]: { privateKey: LOCAL_SECRET, relays: {}, permissions: { [HOST]: GRANT } } },
    ...extra
  });
}

const relay = await startRelay();
const relay2 = await startRelay();

// ---------------------------------------------------------------------------------------------
console.log('\nA web page cannot ask for any of it');
{
  // A working address, so a refusal cannot come from it failing to parse.
  await withLocal();
  const bunker = startBunker({ relays: [relay.url] });
  await wait(300);
  for (const type of ['connectRemoteSigner', 'confirmRemoteSigner', 'cancelRemoteSigner', 'disconnectRemoteSigner']) {
    const answer = await send({ type, uri: bunker.uri(), id: 'x', publicKey: LOCAL }, PAGE);
    ok(`${type} is refused to a page`, answer?.success === false && answer?.error === 'not available to pages', answer);
  }
  await wait(500);
  ok('  and the remote signer heard nothing', bunker.state.requests.length === 0, bunker.state.requests.map(r => r.method));
  ok('  and the local profile is still there', (await local('profiles'))[LOCAL]?.privateKey === LOCAL_SECRET);
  bunker.close();
}

console.log('\nConnecting with a secret');
{
  await withLocal();
  const bunker = startBunker({ relays: [relay.url], listen: [relay.url, relay2.url], secret: 'one-time-secret-123', switchTo: [relay.url, relay2.url] });
  await wait(300);
  const before = await local('profiles');

  const offer = await connect(bunker.uri());
  ok('answers with whose key the remote signer signs with', offer?.success === true && offer.userPubkey === bunker.userPubkey, offer);
  ok('  and the key it talks with, which is another one', offer?.signerPubkey === bunker.signerPubkey && offer.signerPubkey !== offer.userPubkey);
  ok('  and the relays it asked to move to', JSON.stringify(offer?.relays) === JSON.stringify([relay.url, relay2.url]), offer?.relays);
  ok('nothing is stored before the user says yes', JSON.stringify(await local('profiles')) === JSON.stringify(before) && (await local('active_public_key')) === LOCAL);
  ok('the secret is nowhere in storage', !(await everything()).includes('one-time-secret-123'));

  const used = await confirm(offer.id);
  ok('confirming stores the profile', used?.success === true && used.publicKey === bunker.userPubkey, used);
  const p = (await local('profiles'))[bunker.userPubkey];
  ok('  as a remote profile, with no private key', p?.privateKey === '' && p?.remote?.signerPubkey === bunker.signerPubkey);
  ok('  with the relays the signer asked for', JSON.stringify(p?.remote?.relays) === JSON.stringify([relay.url, relay2.url]));
  ok('  and a client key the remote signer knows', bunker.state.sessions.has(getPublicKey(Buffer.from(p.remote.clientKey, 'hex'))));
  ok('confirming is the choice: it is the profile that signs now', (await local('active_public_key')) === bunker.userPubkey);
  ok('  with no private key left in the active slot', (await local('private_key')) === undefined);
  ok('the secret is still nowhere in storage', !(await everything()).includes('one-time-secret-123'));
  ok('the local profile is untouched', (await local('profiles'))[LOCAL]?.privateKey === LOCAL_SECRET);

  const all = await local('profiles');
  all[bunker.userPubkey].permissions = { [HOST]: GRANT };
  await stub.storage.local.set({ profiles: all });
  const signed = await send({ type: 'signEvent', params: { event: { kind: 1, content: 'via bunker', tags: [], created_at: now() } }, host: HOST }, PAGE);
  ok('a page is then signed for through it', isSigned(signed, verifyEvent) && signed.pubkey === bunker.userPubkey, signed);

  const again = await connect(bunker.uri());
  ok('the same secret does not connect a second time', again?.success === false && /refused/.test(again?.error), again);
  ok('  and that leaves nothing behind', Object.keys(await local('profiles')).length === 2);

  const twice = await confirm(offer.id);
  ok('an offer cannot be confirmed twice', twice?.success === false && /no longer waiting/.test(twice?.error), twice);
  bunker.close();
}

console.log('\nAddresses that are not usable');
{
  await withLocal();
  for (const [what, uri] of [
    ['a nostrconnect:// address', `nostrconnect://${'ab'.repeat(32)}?relay=wss://r.example&secret=x`],
    ['an address without a relay', `bunker://${'ab'.repeat(32)}`],
    ['an unencrypted relay elsewhere', `bunker://${'ab'.repeat(32)}?relay=ws://relay.example`],
    ['nothing at all', '']
  ]) {
    const answer = await connect(uri);
    ok(`${what} is refused with a reason`, answer?.success === false && typeof answer.error === 'string' && answer.error.length > 5, answer);
  }
}

console.log('\nSaying no');
{
  await withLocal();
  const bunker = startBunker({ relays: [relay.url] });
  await wait(300);
  const offer = await connect(bunker.uri());
  const cancelled = await send({ type: 'cancelRemoteSigner', id: offer.id }, OWN_PAGE);
  await wait(500);
  ok('cancelling tells the remote signer', cancelled?.success === true && logouts(bunker) === 1 && bunker.state.sessions.size === 0, { logouts: logouts(bunker) });
  ok('  and stores nothing', !(await local('profiles'))[bunker.userPubkey]);

  CONNECT_LIMITS.unconfirmedMs = 500;
  const forgotten = await connect(bunker.uri());
  await wait(1200);
  ok('saying nothing: the offer is dropped after its time', logouts(bunker) === 2, logouts(bunker));
  const late = await confirm(forgotten.id);
  ok('  and cannot be confirmed afterwards', late?.success === false && /no longer waiting/.test(late?.error), late);
  CONNECT_LIMITS.unconfirmedMs = DEFAULTS.unconfirmedMs;
  bunker.close();
}

console.log('\nA key that already has a local profile here');
{
  await withLocal();
  const bunker = startBunker({ relays: [relay.url], userKey: Uint8Array.from(Buffer.from(LOCAL_SECRET, 'hex')) });
  await wait(300);
  const answer = await connect(bunker.uri());
  ok('is refused before the user is asked anything', answer?.success === false && /holds its private key/.test(answer?.error), answer);
  ok('  and the remote signer is told', logouts(bunker) === 1, logouts(bunker));
  ok('  and the local profile keeps its key', (await local('profiles'))[LOCAL]?.privateKey === LOCAL_SECRET && !(await local('profiles'))[LOCAL]?.remote);
  bunker.close();
}

console.log('\nA login while connecting');
{
  await withLocal();
  const bunker = startBunker({ relays: [relay.url] });
  await wait(300);
  CONNECT_LIMITS.timeoutMs = 1000;
  bunker.set({ mode: 'auth', url: 'https://signer.example/login', thenMs: 2500 }, ['connect']);
  const tabsBefore = control.created.length;
  const offer = await timed(connect(bunker.uri()));
  ok('is waited for, past the ordinary deadline', offer.value?.success === true && offer.ms > 2000, { ms: offer.ms, answer: offer.value });
  ok('  with the login page opened in a tab', control.created.slice(tabsBefore).some(w => w.url === 'https://signer.example/login'), control.created.slice(tabsBefore).map(w => w.url));
  ok('  for at most five minutes', DEFAULTS.authTimeoutMs === 5 * 60 * 1000, DEFAULTS.authTimeoutMs);
  if (offer.value?.id) await send({ type: 'cancelRemoteSigner', id: offer.value.id }, OWN_PAGE);

  bunker.set({ mode: 'silent' }, ['connect']);
  const silent = await timed(connect(bunker.uri()));
  ok('a remote signer that never answers: "the remote signer did not answer in time"', silent.value?.error === 'the remote signer did not answer in time' && silent.ms < 3000, silent);
  CONNECT_LIMITS.timeoutMs = DEFAULTS.timeoutMs;
  ok('connecting waits 30 s for a signer that does not ask for a login', DEFAULTS.timeoutMs === 30000);
  bunker.close();
}

console.log('\nWith a PIN');
{
  const sealedLocal = await enc.encryptPrivateKey(PIN, LOCAL_SECRET);
  await withLocal({ pin_enabled: true, pin_kind: 'pin', encrypted_private_key: sealedLocal, profiles: { [LOCAL]: { privateKey: sealedLocal, relays: {}, permissions: {} } } });
  await stub.storage.local.remove('private_key');
  const bunker = startBunker({ relays: [relay.url] });
  await wait(300);
  const offer = await connect(bunker.uri());
  const confirming = confirm(offer.id);
  await settle(40);
  const win = control.created.at(-1);
  ok('confirming asks for the PIN, to store the key encrypted', /pin\.html\?mode=unlock/.test(win?.url), win?.url);
  await send({ type: 'verifyPin', pin: PIN, id: new URL(win.url).searchParams.get('id') }, { url: 'moz-extension://attest-test/pin.html' });
  const used = await confirming;
  ok('  and then stores it', used?.success === true, used);
  const stored = (await local('profiles'))[bunker.userPubkey]?.remote?.clientKey ?? '';
  ok('the client key is encrypted from the first write', stored.startsWith('{'));
  const hexKey = await enc.decryptPrivateKey(PIN, stored);
  ok('  with the PIN', /^[0-9a-f]{64}$/.test(hexKey) && bunker.state.sessions.has(getPublicKey(Buffer.from(hexKey, 'hex'))));
  ok('  and never in plain text', !(await everything()).includes(hexKey));

  // Disconnecting with the PIN still cached: logout goes out with the decrypted key.
  const gone = await send({ type: 'disconnectRemoteSigner', publicKey: bunker.userPubkey }, OWN_PAGE);
  ok('disconnecting logs out of the remote signer', gone?.success === true && gone.loggedOut === true && bunker.state.sessions.size === 0, gone);
  ok('  deletes the profile and its key', !(await local('profiles'))[bunker.userPubkey] && !(await everything()).includes(stored));
  ok('  and the local profile signs again', (await local('active_public_key')) === LOCAL && (await local('encrypted_private_key')) === sealedLocal);
  bunker.close();
}

console.log('\nDisconnecting from a remote signer that does not answer');
{
  await withLocal();
  const bunker = startBunker({ relays: [relay.url] });
  await wait(300);
  const offer = await connect(bunker.uri());
  await confirm(offer.id);
  bunker.set({ mode: 'silent' }, ['logout']);
  const gone = await timed(send({ type: 'disconnectRemoteSigner', publicKey: bunker.userPubkey }, OWN_PAGE));
  ok('still deletes the profile and its key', gone.value?.success === true && !(await local('profiles'))[bunker.userPubkey], gone.value);
  ok('  and says the logout was not confirmed', gone.value?.loggedOut === false);
  ok('  within a few seconds', gone.ms < 7000, gone.ms);
  ok('  with the local profile signing again', (await local('active_public_key')) === LOCAL && (await local('private_key')) === LOCAL_SECRET);

  const notRemote = await send({ type: 'disconnectRemoteSigner', publicKey: LOCAL }, OWN_PAGE);
  ok('a local profile cannot be "disconnected"', notRemote?.success === false && (await local('profiles'))[LOCAL]?.privateKey === LOCAL_SECRET, notRemote);
  bunker.close();
}

await clearWindows();
await relay.close();
await relay2.close();
for (const dir of [outdir, encDir]) await rm(dir, { recursive: true, force: true });

console.log(`\n${state.pass} passed, ${state.fail} failed`);
process.exit(state.fail ? 1 : 0);
