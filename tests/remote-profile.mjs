#!/usr/bin/env node
// A profile that signs through a remote signer, as storage keeps it.
//
//   node tests/remote-profile.mjs
//
// Such a profile has no private key. It has a client key instead — Attest's side of the session
// with the remote signer — and that is as sensitive as a private key: whoever holds it can ask the
// remote signer for anything the connection was allowed. So it is held to the same rules: in plain
// text only while there is no PIN or passphrase, encrypted with it otherwise, decrypted when
// protection is turned off, and never handed out by the "copy my key" path.
//
// The other half is that nothing about local keys changes. Every place that makes a profile active
// used to put that profile's private key in the active slot with updateActivePrivateKey(), and
// for an empty key that function removes the active public key too — so a profile without a key
// would have left Attest with no active profile at all, or worse, the previous profile's key
// still in the slot. Each of those places is checked here, in both directions.
//
// A stub suite: storage and background.ts are the real ones, the browser underneath is not.
import { getPublicKey } from 'nostr-tools';
import { rm } from 'node:fs/promises';

import { loadBackground, loadModule, OWN_PAGE } from './load-background.mjs';
import { reporter } from './harness.mjs';
import stub, { control, reset, send, closeWindow } from './browser-stub.mjs';

const { ok, state } = reporter();
process.on('unhandledRejection', error => {
  ok(`a promise was rejected with nobody listening (${error?.message ?? error})`, false);
});

const settle = async (rounds = 20) => {
  for (let i = 0; i < rounds; i++) await new Promise(r => setTimeout(r, 0));
};
const rejects = async promise => { try { await promise; return null; } catch (e) { return e.message; } };

const LOCAL_SECRET = '5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a';
const LOCAL = getPublicKey(Buffer.from(LOCAL_SECRET, 'hex'));
const USER = getPublicKey(Buffer.from('22'.repeat(32), 'hex')); // the remote signer's user
const USER_2 = getPublicKey(Buffer.from('33'.repeat(32), 'hex'));
const SIGNER = getPublicKey(Buffer.from('44'.repeat(32), 'hex')); // the key it talks with
const CLIENT_KEY = '55'.repeat(32);
const RELAYS = ['wss://relay.example'];
const PIN = '123456';

const outdir = await loadBackground();
const { exports: storage, outdir: storageDir } = await loadModule('src/storage.ts');
const { exports: enc, outdir: encDir } = await loadModule('src/pinEncryption.ts');

const local = async key => (await stub.storage.local.get(key))[key];
const profiles = async () => (await local('profiles')) ?? {};
const remote = (clientKey = CLIENT_KEY) => ({ signerPubkey: SIGNER, relays: RELAYS, clientKey });

async function clearWindows() {
  for (const id of [...control.windows.keys()]) await closeWindow(id);
  await settle();
}

/** Empty storage; window ids carry on, so none is ever reused. */
async function fresh(items = {}) {
  await clearWindows();
  const next = control.nextWindowId;
  reset();
  control.nextWindowId = next;
  await stub.storage.local.set({ pin_enabled: false, ...items });
}

/** One local profile with a plain key, active. */
const withLocal = () => fresh({
  private_key: LOCAL_SECRET,
  active_public_key: LOCAL,
  profiles: { [LOCAL]: { privateKey: LOCAL_SECRET, relays: {}, permissions: {} } }
});

async function openWindow(mode) {
  send({ type: 'openPinPrompt', mode }, OWN_PAGE); // resolves only once answered, so not awaited
  await settle();
  return new URL(control.created[control.created.length - 1].url).searchParams.get('id');
}

// ---------------------------------------------------------------------------------------------
console.log('\nStoring a remote signer');
{
  await fresh();
  await storage.saveRemoteProfile(USER, remote());
  const p = (await profiles())[USER];
  ok('is stored under the user key, not the signer key', !!p && !(await profiles())[SIGNER]);
  ok('with no private key', p?.privateKey === '');
  ok('with its signer, relays and client key', p?.remote?.signerPubkey === SIGNER && p?.remote?.relays[0] === RELAYS[0] && p?.remote?.clientKey === CLIENT_KEY);
  ok('as the only profile, it becomes the active one', (await local('active_public_key')) === USER);
  ok('  with nothing in either private key slot', (await local('private_key')) === undefined && (await local('encrypted_private_key')) === undefined);
  ok('getActiveProfile finds it', (await storage.getActiveProfile())?.remote?.signerPubkey === SIGNER);

  for (const [what, call] of [
    ['a user key that is not one', () => storage.saveRemoteProfile('nope', remote())],
    ['a signer key that is not one', () => storage.saveRemoteProfile(USER, { ...remote(), signerPubkey: 'nope' })],
    ['no relays', () => storage.saveRemoteProfile(USER, { ...remote(), relays: [] })],
    ['a client key that is not one', () => storage.saveRemoteProfile(USER, remote('nope'))]
  ]) {
    ok(`refuses ${what}`, !!(await rejects(call())));
  }
}

console.log('\nNext to a local profile');
{
  await withLocal();
  await storage.saveRemoteProfile(USER, remote());
  ok('adding one does not make it active: that is an explicit choice', (await local('active_public_key')) === LOCAL);
  ok('  and leaves the local key where it was', (await local('private_key')) === LOCAL_SECRET);

  const clash = await rejects(storage.saveRemoteProfile(LOCAL, remote()));
  ok('a profile that holds the private key is never turned into a remote one', /Delete that profile first/.test(clash ?? ''), clash);
  ok('  and keeps its key', (await profiles())[LOCAL]?.privateKey === LOCAL_SECRET && !(await profiles())[LOCAL]?.remote);
}

console.log('\nConnecting the same identity again');
{
  await withLocal();
  await storage.saveRemoteProfile(USER, remote());
  await storage.renameProfile(USER, 'My bunker');
  const all = await profiles();
  all[USER].permissions = { 'https://example.com': { '10': { condition: 'forever', created_at: 1, level: 10 } } };
  all[USER].relays = { 'wss://mine.example': { read: true, write: true } };
  await stub.storage.local.set({ profiles: all });

  await storage.saveRemoteProfile(USER, { signerPubkey: SIGNER, relays: ['wss://other.example'], clientKey: '66'.repeat(32) });
  const p = (await profiles())[USER];
  ok('replaces the connection', p.remote.clientKey === '66'.repeat(32) && p.remote.relays[0] === 'wss://other.example');
  ok('keeps the name', p.name === 'My bunker');
  ok('keeps the site permissions', !!p.permissions['https://example.com']);
  ok('keeps the profile relays', !!p.relays['wss://mine.example']);
}

console.log('\nSwitching, without protection');
{
  await withLocal();
  await storage.saveRemoteProfile(USER, remote());
  let all = await profiles();
  await storage.switchActiveProfile(USER, all[USER]);
  ok('to the remote profile: it is the active one', (await local('active_public_key')) === USER);
  ok('  and the local key does not stay behind to sign', (await local('private_key')) === undefined);

  await storage.switchActiveProfile(LOCAL, all[LOCAL]);
  ok('back to the local profile: it is the active one', (await local('active_public_key')) === LOCAL);
  ok('  with its key in the slot again', (await local('private_key')) === LOCAL_SECRET);

  await storage.switchActiveProfile(USER, all[USER]);
  await storage.deleteProfile(USER);
  ok('deleting the active remote profile moves to the local one, key and all', (await local('active_public_key')) === LOCAL && (await local('private_key')) === LOCAL_SECRET);

  await storage.saveRemoteProfile(USER, remote());
  await storage.deleteProfile(LOCAL);
  ok('deleting the active local profile moves to the remote one', (await local('active_public_key')) === USER);
  ok('  and takes the local key with it', (await local('private_key')) === undefined);

  await storage.updateProfiles(await profiles());
  ok('writing the profiles back with a lone remote profile keeps it active', (await local('active_public_key')) === USER);
  await storage.addActivePermission('https://example.com', 'forever', 10);
  ok('a site permission is written to the remote profile', !!(await profiles())[USER].permissions['https://example.com']);
  ok('getRelays reads the remote profile', JSON.stringify(await storage.readActiveRelays()) === '{}');
}

console.log('\nTurning protection on while a remote profile is active');
{
  await withLocal();
  await storage.saveRemoteProfile(USER, remote());
  await storage.switchActiveProfile(USER, (await profiles())[USER]);

  // The PIN window sends no encrypted key when the active profile has none to encrypt.
  const answer = await send({ type: 'setupPin', pin: PIN, id: await openWindow('setup'), kind: 'pin' }, OWN_PAGE);
  ok('works', answer?.success === true, answer);
  const p = await profiles();
  const sealed = p[USER].remote.clientKey;
  ok('the client key is no longer stored in plain text', sealed !== CLIENT_KEY && !JSON.stringify(await stub.storage.local.get(null)).includes(CLIENT_KEY));
  ok('  it is encrypted with the PIN', (await enc.decryptPrivateKey(PIN, sealed)) === CLIENT_KEY);
  ok('the local profile key is encrypted too', (await enc.decryptPrivateKey(PIN, p[LOCAL].privateKey)) === LOCAL_SECRET);
  ok('  and no longer stored in plain text', !JSON.stringify(await stub.storage.local.get(null)).includes(LOCAL_SECRET));
  ok('the remote profile is still the active one', (await local('active_public_key')) === USER);
  ok('  with nothing in either private key slot', (await local('private_key')) === undefined && (await local('encrypted_private_key')) === undefined);

  const unlock = await openWindow('unlock');
  const wrong = await send({ type: 'verifyPin', pin: '000000', id: unlock }, OWN_PAGE);
  ok('unlocking checks the PIN against the client key: a wrong one fails', wrong?.success === false, wrong);
  const right = await send({ type: 'verifyPin', pin: PIN, id: unlock }, OWN_PAGE);
  ok('  and the right one opens', right?.success === true, right);

  const copy = await send({ type: 'copyNsec', pin: PIN, id: await openWindow('copy') }, OWN_PAGE);
  ok('"copy my key" hands out nothing for it: the client key is not the user key', copy?.success === false && !copy?.nsec && /remote signer holds this key/.test(copy?.error), copy);

  await storage.switchActiveProfile(LOCAL, p[LOCAL]);
  ok('switching to the local profile puts its encrypted key in the slot', (await local('encrypted_private_key')) === p[LOCAL].privateKey);
  await storage.switchActiveProfile(USER, p[USER]);
  ok('switching back takes it out again', (await local('encrypted_private_key')) === undefined);

  const off = await send({ type: 'disablePin', pin: PIN, id: await openWindow('disable') }, OWN_PAGE);
  ok('turning protection off works', off?.success === true, off);
  const q = await profiles();
  ok('  and gives the client key back in plain text', q[USER].remote.clientKey === CLIENT_KEY);
  ok('  and the local key', q[LOCAL].privateKey === LOCAL_SECRET);
  ok('  without putting a private key in the active slot', (await local('private_key')) === undefined);
  ok('  and the remote profile is still active', (await local('active_public_key')) === USER);
}

console.log('\nTurning protection on while a local profile is active');
{
  await withLocal();
  await storage.saveRemoteProfile(USER, remote());
  const encryptedKey = await enc.encryptPrivateKey(PIN, LOCAL_SECRET);
  const answer = await send({ type: 'setupPin', pin: PIN, encryptedKey, id: await openWindow('setup'), kind: 'pin' }, OWN_PAGE);
  ok('works as before', answer?.success === true, answer);
  ok('  and encrypts the remote signer\'s client key along with the keys', !JSON.stringify(await stub.storage.local.get(null)).includes(CLIENT_KEY));
  ok('the local key is in the encrypted slot, as before', (await enc.decryptPrivateKey(PIN, await local('encrypted_private_key'))) === LOCAL_SECRET);

  const plain = await rejects(storage.saveRemoteProfile(USER_2, remote()));
  ok('a new remote signer cannot be stored with a plain client key now', /plain-text client key/.test(plain ?? ''), plain);
  await storage.saveRemoteProfile(USER_2, remote(await enc.encryptPrivateKey(PIN, CLIENT_KEY)));
  ok('  an encrypted one can', !!(await profiles())[USER_2]?.remote);

  const off = await send({ type: 'disablePin', pin: PIN, id: await openWindow('disable') }, OWN_PAGE);
  ok('turning protection off works as before', off?.success === true, off);
  ok('  and the local key is back in the active slot', (await local('private_key')) === LOCAL_SECRET);
  ok('  and both client keys are plain again', (await profiles())[USER].remote.clientKey === CLIENT_KEY && (await profiles())[USER_2].remote.clientKey === CLIENT_KEY);
}

console.log('\nWhat a PIN window may not do');
{
  await withLocal();
  // A local profile active: an encrypted key is still required, as before.
  const answer = await send({ type: 'setupPin', pin: PIN, id: await openWindow('setup'), kind: 'pin' }, OWN_PAGE);
  ok('turning protection on without an encrypted key is refused for a local profile', answer?.success === false, answer);
  ok('  and leaves the plain key alone', (await local('pin_enabled')) === false && (await local('private_key')) === LOCAL_SECRET);
}

await clearWindows();
await rm(outdir, { recursive: true, force: true });
await rm(storageDir, { recursive: true, force: true });
await rm(encDir, { recursive: true, force: true });

console.log(`\n${state.pass} passed, ${state.fail} failed`);
process.exit(state.fail ? 1 : 0);
