#!/usr/bin/env node
// Getting a private key back out, and who is allowed to ask.
//
//   node tests/copy-key.mjs
//
// With PIN protection on, an encrypted key cannot be shown, so the options page has nothing to
// copy. The way out is a PIN window that decrypts and puts the key on the clipboard itself. That
// adds the one thing this extension had carefully avoided until now — a message that answers with
// a private key — so the conditions on it are the whole point and are pinned here:
//
//   - a web page cannot reach it. It is in EXTENSION_PAGES_ONLY, so the refusal happens before any
//     decryption is attempted, and the answer says nothing about whether a key even exists.
//   - it decrypts with the PIN typed into that window and nothing else. Riding the cached PIN would
//     turn "export my private key" into two clicks for anybody who reaches an unlocked browser, so
//     a request without a PIN is refused even while a cached one is sitting there.
//   - a wrong PIN says only "Incorrect PIN", and a right one answers only the window that asked.
//
// The clipboard write and the window that performs it are not covered here — that is browser
// behaviour, and tests/security-boundary.mjs is the suite that drives a real browser.
import { getPublicKey, nip19 } from 'nostr-tools';
import { rm } from 'node:fs/promises';

import { loadBackground, loadModule, OWN_PAGE } from './load-background.mjs';
import { reporter } from './harness.mjs';
import stub, { control, reset, send } from './browser-stub.mjs';

const { ok, state } = reporter();
process.on('unhandledRejection', error => {
  ok(`a promise was rejected with nobody listening (${error?.message ?? error})`, false);
});

const outdir = await loadBackground();

const PRIVATE_KEY = '5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a';
const PUBLIC_KEY = getPublicKey(Buffer.from(PRIVATE_KEY, 'hex'));
const PIN = '123456';

// The same routine the extension uses, imported rather than reimplemented.
const { exports: pinEncryption, outdir: cryptoDir } = await loadModule('src/pinEncryption.ts');
const { encryptPrivateKey } = pinEncryption;

const settle = async (rounds = 20) => {
  for (let i = 0; i < rounds; i++) await new Promise(r => setTimeout(r, 0));
};

/**
 * Open the copy prompt the way the options page does, and read back the id the way the PIN window
 * does — out of its own URL. Nothing here reaches into the background's bookkeeping.
 *
 * The openPinPrompt call is deliberately not awaited: it only resolves once a PIN has been
 * submitted, which is the thing these cases are about to do.
 */
async function openCopyPrompt() {
  send({ type: 'openPinPrompt', mode: 'copy' }, OWN_PAGE);
  await settle();
  const window = control.created[control.created.length - 1];
  return new URL(window.url).searchParams.get('id');
}

async function pinProtectedProfile() {
  reset();
  const encrypted = await encryptPrivateKey(PIN, PRIVATE_KEY);
  await stub.storage.local.set({
    pin_enabled: true,
    encrypted_private_key: encrypted,
    active_public_key: PUBLIC_KEY,
    profiles: { [PUBLIC_KEY]: { permissions: {}, relays: {}, privateKey: encrypted } }
  });
}

console.log('\nWho may ask for the key');
{
  await pinProtectedProfile();

  // No sender url at all is what a content script in a web page looks like to this listener.
  const fromPage = await send({ type: 'copyNsec', pin: PIN, id: 'x' }, null);
  ok('a page asking for the key is refused', fromPage?.error === 'not available to pages', fromPage);
  ok('and is told nothing else', !fromPage?.nsec && !fromPage?.npub, fromPage);
}

console.log('\nWhat the PIN window has to supply');
{
  await pinProtectedProfile();

  const noPin = await send({ type: 'copyNsec', id: await openCopyPrompt() }, OWN_PAGE);
  ok('a request with no PIN is refused', noPin?.error === 'Missing PIN', noPin);
  ok('and no key comes back with it', !noPin?.nsec, noPin);

  const wrongPin = await send({ type: 'copyNsec', pin: '999999', id: await openCopyPrompt() }, OWN_PAGE);
  ok('a wrong PIN is refused', wrongPin?.success === false, wrongPin);
  ok('and says only that the PIN is wrong', wrongPin?.error === 'Incorrect PIN', wrongPin);
  ok('and hands back no key either', !wrongPin?.nsec, wrongPin);
}

console.log('\nWith the right PIN');
{
  await pinProtectedProfile();

  const answer = await send({ type: 'copyNsec', pin: PIN, id: await openCopyPrompt() }, OWN_PAGE);
  ok('the key comes back', answer?.success === true && !!answer?.nsec, answer?.error ?? answer);
  ok(
    'as the nsec for this profile',
    answer?.nsec === nip19.nsecEncode(Buffer.from(PRIVATE_KEY, 'hex')),
    answer?.nsec
  );
  ok(
    'named by the npub it belongs to, so the window can say which key it copied',
    answer?.npub === nip19.npubEncode(PUBLIC_KEY),
    answer?.npub
  );
}

console.log('\nWhen there is nothing to decrypt');
{
  reset();
  await stub.storage.local.set({ pin_enabled: true });

  const answer = await send({ type: 'copyNsec', pin: PIN, id: await openCopyPrompt() }, OWN_PAGE);
  ok('the request fails rather than hanging', answer?.success === false, answer);
  ok('and says what is missing', answer?.error === 'No encrypted key found', answer);
}

await rm(outdir, { recursive: true, force: true });
await rm(cryptoDir, { recursive: true, force: true });

console.log(`\n${state.pass} passed, ${state.fail} failed`);
process.exit(state.fail ? 1 : 0);
