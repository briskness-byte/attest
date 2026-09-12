#!/usr/bin/env node
// A PIN or a passphrase, and the keys encrypted before either choice existed.
//
//   node tests/passphrase.mjs
//
// A 4–6 digit PIN falls to anybody who copies the Firefox profile: about a million guesses, each one
// checked by the AES-GCM tag, done in minutes. No salt and no number of hash rounds changes that —
// the salt is stored right next to the ciphertext, and slower rounds slow the owner exactly as much
// as the attacker. So 1.25.0 lets people choose a passphrase, and derives with 600 000 rounds
// instead of 100 000.
//
// What must not happen on the way is anybody's existing key failing to open. The first case below
// builds a key the way 1.24 and earlier stored it — with node's own crypto, not the code under test,
// so the two cannot agree by sharing a mistake — and opens it with the new code.
import crypto from 'node:crypto';
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

const PRIVATE_KEY = '5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a';
const PUBLIC_KEY = getPublicKey(Buffer.from(PRIVATE_KEY, 'hex'));
const PIN = '123456';
const PASSPHRASE = 'correct horse battery staple';

const outdir = await loadBackground();
const { exports: enc, outdir: encDir } = await loadModule('src/pinEncryption.ts');
const { exports: common, outdir: commonDir } = await loadModule('src/common.ts');

/** A key as 1.24 and earlier wrote it: PBKDF2-SHA256 at 100 000 rounds, AES-256-GCM, no count. */
function legacyBlob(secret, plaintext) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(secret, salt, 100000, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  // WebCrypto puts the tag after the ciphertext; so does this.
  const sealed = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return JSON.stringify({
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    ciphertext: sealed.toString('base64')
  });
}

/** Open a blob with node's crypto at a given round count — independent of the code under test. */
function openWithNode(blob, secret, rounds) {
  const { salt, iv, ciphertext } = JSON.parse(blob);
  const sealed = Buffer.from(ciphertext, 'base64');
  const key = crypto.pbkdf2Sync(secret, Buffer.from(salt, 'base64'), rounds, 32, 'sha256');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
  decipher.setAuthTag(sealed.subarray(-16));
  return Buffer.concat([decipher.update(sealed.subarray(0, -16)), decipher.final()]).toString('utf8');
}

const rejects = async promise => { try { await promise; return false; } catch { return true; } };

// ------------------------------------------------------------------ 1. the encryption

console.log('\nKeys encrypted before 1.25.0');
{
  const old = legacyBlob(PIN, PRIVATE_KEY);
  ok('still open with their PIN', (await enc.decryptPrivateKey(PIN, old)) === PRIVATE_KEY);
  ok('and still refuse a wrong one', await rejects(enc.decryptPrivateKey('654321', old)));
}

console.log('\nWhat 1.25.0 writes');
{
  const blob = await enc.encryptPrivateKey(PASSPHRASE, PRIVATE_KEY);
  ok('records its round count', JSON.parse(blob).iterations === 600000, JSON.parse(blob).iterations);
  ok('opens with node at 600 000 rounds, so the count is real and not a label',
     openWithNode(blob, PASSPHRASE, 600000) === PRIVATE_KEY);
  ok('opens with the extension too', (await enc.decryptPrivateKey(PASSPHRASE, blob)) === PRIVATE_KEY);

  const absurd = JSON.stringify({ ...JSON.parse(blob), iterations: 1e12 });
  const started = Date.now();
  ok('a corrupt round count is refused instead of freezing the window',
     await rejects(enc.decryptPrivateKey(PASSPHRASE, absurd)) && Date.now() - started < 1000);
}

console.log('\nWhat each kind accepts');
for (const [kind, secret, fine] of [
  ['pin', '1234', true],
  ['pin', '123456', true],
  ['pin', '123', false],
  ['pin', '1234567', false],
  ['pin', 'abcd', false],
  ['passphrase', PASSPHRASE, true],
  ['passphrase', 'twelve chars', true],
  ['passphrase', 'too short', false],
  ['passphrase', ' '.repeat(20), false]
]) {
  ok(`${kind} ${JSON.stringify(secret)} → ${fine ? 'accepted' : 'refused'}`,
     (common.secretProblem(kind, secret) === null) === fine, common.secretProblem(kind, secret));
}

// ------------------------------------------------------------------ 2. the flow, through background.ts

/**
 * Close what is still open. background.ts keeps its own record of PIN prompts that no reset can
 * reach, and a prompt left waiting — a refused setup, here — is shared by the next request rather
 * than opening a second window it could never answer.
 */
async function clearWindows() {
  for (const id of [...control.windows.keys()]) await closeWindow(id);
  await settle();
}

/** A profile with a plain key and no protection; window ids carry on, so none is ever reused. */
async function unprotected() {
  await clearWindows();
  const next = control.nextWindowId;
  reset();
  control.nextWindowId = next;
  await stub.storage.local.set({
    private_key: PRIVATE_KEY,
    active_public_key: PUBLIC_KEY,
    pin_enabled: false,
    profiles: { [PUBLIC_KEY]: { privateKey: PRIVATE_KEY, permissions: {}, relays: {} } }
  });
}

/** Open a PIN window the way the options page does, and read its id the way the window does. */
async function openWindow(mode) {
  send({ type: 'openPinPrompt', mode }, OWN_PAGE); // resolves only once answered, so not awaited
  await settle();
  return new URL(control.created[control.created.length - 1].url).searchParams.get('id');
}

const stored = async key => (await stub.storage.local.get(key))[key];

async function setup(kind, secret, encryptWith = secret) {
  const id = await openWindow('setup');
  const encryptedKey = await enc.encryptPrivateKey(encryptWith, PRIVATE_KEY);
  return send({ type: 'setupPin', pin: secret, encryptedKey, id, kind }, OWN_PAGE);
}

console.log('\nTurning protection on is refused');
{
  await unprotected();
  const short = await setup('passphrase', 'too short');
  ok('for a passphrase that is too short', short?.success === false && /at least 12/.test(short?.error), short);
  const letters = await setup('pin', 'abcd');
  ok('for a PIN that is not digits', letters?.success === false, letters);
  const mismatched = await setup('passphrase', PASSPHRASE, 'a different passphrase');
  ok('for a key that does not open with the secret sent', mismatched?.success === false, mismatched);
  ok('and none of that switched protection on', (await stored('pin_enabled')) === false);
  ok('  or touched the plain key', (await stored('private_key')) === PRIVATE_KEY);
}

console.log('\nWith a passphrase');
{
  await unprotected();
  const answer = await setup('passphrase', PASSPHRASE);
  ok('protection is turned on', answer?.success === true, answer);
  ok('and remembers that it is a passphrase', (await stored('pin_kind')) === 'passphrase');
  ok('the plain key is gone from storage', !(await stored('private_key')));
  const blob = await stored('encrypted_private_key');
  ok('the stored key is encrypted at 600 000 rounds', JSON.parse(blob).iterations === 600000);
  ok('  and every profile key with it',
     JSON.parse((await stored('profiles'))[PUBLIC_KEY].privateKey).iterations === 600000);

  const unlock = await openWindow('unlock');
  const wrong = await send({ type: 'verifyPin', pin: 'not the passphrase', id: unlock }, OWN_PAGE);
  ok('a wrong passphrase does not unlock', wrong?.success === false, wrong);
  const right = await send({ type: 'verifyPin', pin: PASSPHRASE, id: unlock }, OWN_PAGE);
  ok('the passphrase does', right?.success === true, right);

  const off = await send({ type: 'disablePin', pin: PASSPHRASE, id: await openWindow('disable') }, OWN_PAGE);
  ok('turning protection off works with it', off?.success === true, off);
  ok('  gives the plain key back', (await stored('private_key')) === PRIVATE_KEY);
  ok('  and forgets the kind', (await stored('pin_kind')) === undefined);
}

console.log('\nWith a PIN');
{
  await unprotected();
  const answer = await setup('pin', PIN);
  ok('protection is turned on', answer?.success === true, answer);
  ok('and remembers that it is a PIN', (await stored('pin_kind')) === 'pin');
}

console.log('\nSomebody protected by an older version');
{
  await clearWindows();
  const next = control.nextWindowId;
  reset();
  control.nextWindowId = next;
  const old = legacyBlob(PIN, PRIVATE_KEY);
  await stub.storage.local.set({
    pin_enabled: true, // and no pin_kind: 1.24 never wrote one
    encrypted_private_key: old,
    active_public_key: PUBLIC_KEY,
    profiles: { [PUBLIC_KEY]: { privateKey: old, permissions: {}, relays: {} } }
  });
  const right = await send({ type: 'verifyPin', pin: PIN, id: await openWindow('unlock') }, OWN_PAGE);
  ok('unlocks with their PIN, as before', right?.success === true, right);
}

await rm(outdir, { recursive: true, force: true });
await rm(encDir, { recursive: true, force: true });
await rm(commonDir, { recursive: true, force: true });

console.log(`\n${state.pass} passed, ${state.fail} failed`);
process.exit(state.fail ? 1 : 0);
