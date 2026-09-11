#!/usr/bin/env node
// One remembered decision per permission level, not one per site.
//
//   node tests/decisions.mjs
//
// A site used to hold a single decision, so a narrower answer replaced a broader one. Tell a site
// that signs "forever" that it may not decrypt for five minutes, and its signing grant was gone:
// five minutes later it had nothing and asked for everything again. Allow its request for the
// public key, and a "reject forever" on decrypting went with it. (Audit of 11 September 2026, B3.)
//
// Levels: 1 public key, 5 relays, 10 signing, 20 encrypting and decrypting. An allow covers its
// level and below, a refusal its level and above, and a refusal wins while it lasts.
import { getPublicKey } from 'nostr-tools';
import { rm } from 'node:fs/promises';

import { loadBackground, loadModule, OWN_PAGE } from './load-background.mjs';
import { reporter } from './harness.mjs';
import stub, { control, reset, send, closeWindow } from './browser-stub.mjs';

const { ok, state } = reporter();
process.on('unhandledRejection', error => {
  ok(`a promise was rejected with nobody listening (${error?.message ?? error})`, false);
});

const settle = async (rounds = 40) => {
  for (let i = 0; i < rounds; i++) await new Promise(r => setTimeout(r, 0));
};
const TIMEOUT = Symbol('timed out');
function within(ms, promise) {
  let timer;
  return Promise.race([
    Promise.resolve(promise).finally(() => clearTimeout(timer)),
    new Promise(r => { timer = setTimeout(() => r(TIMEOUT), ms); })
  ]);
}

const PRIVATE_KEY = '5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a';
const PUBLIC_KEY = getPublicKey(Buffer.from(PRIVATE_KEY, 'hex'));
const HOST = 'https://example.com';
const now = () => Math.floor(Date.now() / 1000);

const outdir = await loadBackground();
const { exports: storage, outdir: storageDir } = await loadModule('src/storage.ts');

/** A profile with a key and, optionally, what is already stored for the test site. */
async function freshProfile(stored) {
  for (const id of [...control.windows.keys()]) await closeWindow(id);
  await settle();
  const next = control.nextWindowId;
  reset();
  control.nextWindowId = next;
  await stub.storage.local.set({
    private_key: PRIVATE_KEY,
    active_public_key: PUBLIC_KEY,
    pin_enabled: false,
    profiles: {
      [PUBLIC_KEY]: { privateKey: PRIVATE_KEY, relays: {}, permissions: stored ? { [HOST]: stored } : {} }
    }
  });
}

const openPrompts = async () =>
  JSON.parse((await stub.storage.session.get('open_prompts')).open_prompts ?? '[]');
const storedFor = async () =>
  (await stub.storage.local.get('profiles')).profiles[PUBLIC_KEY].permissions[HOST];

const request = {
  pubkey: () => send({ type: 'getPublicKey', host: HOST, params: {} }),
  sign: () =>
    send({ type: 'signEvent', host: HOST, params: { event: { kind: 1, created_at: now(), tags: [], content: 'hi' } } }),
  encrypt: () => send({ type: 'nip44.encrypt', host: HOST, params: { peer: PUBLIC_KEY, plaintext: 'hi' } })
};

/** What a request gets when nobody answers a prompt: 'answered', 'refused' or 'asked'. */
async function outcome(make) {
  const before = (await openPrompts()).length;
  const answer = await within(300, make());
  if (answer === TIMEOUT) return (await openPrompts()).length > before ? 'asked' : 'hung';
  return answer?.error ? 'refused' : 'answered';
}

/** Make a request, and answer its prompt the way the prompt page does. */
async function decide(make, condition, decision, level) {
  const pending = make();
  await settle();
  const prompts = await openPrompts();
  const last = prompts[prompts.length - 1];
  await send({ prompt: true, id: last.id, condition, decision, level, host: HOST }, OWN_PAGE);
  await settle(); // the decision is written after the call is answered
  return within(500, pending);
}

/**
 * Let time pass for the decision at `level`. With no decision stored at that level — the old
 * one-per-site shape — that is a failed check rather than a crash, so the rest still runs and says
 * what else is wrong.
 */
async function age(level, seconds) {
  const { profiles } = await stub.storage.local.get('profiles');
  const entry = profiles[PUBLIC_KEY].permissions[HOST]?.[String(level)];
  if (!entry) {
    ok(`there is a decision stored at level ${level} to let time pass for`, false,
       profiles[PUBLIC_KEY].permissions[HOST]);
    return;
  }
  entry.created_at -= seconds;
  await stub.storage.local.set({ profiles });
}

console.log('\nA short refusal next to a standing grant (the case in the audit)');
{
  await freshProfile();
  const signed = await decide(request.sign, 'forever', 'allow', 10);
  ok('signing is allowed forever', !!signed?.sig, signed);
  const refused = await decide(request.encrypt, 'expirable_5m', 'deny', 20);
  ok('encrypting is refused for five minutes', !!refused?.error, refused);
  ok('both are kept, one per level', Object.keys((await storedFor()) ?? {}).sort().join() === '10,20',
     await storedFor());
  ok('signing is still answered without asking', (await outcome(request.sign)) === 'answered');
  ok('encrypting is refused without asking', (await outcome(request.encrypt)) === 'refused');

  await age(20, 6 * 60);
  ok('once the refusal runs out, encrypting asks again', (await outcome(request.encrypt)) === 'asked');
  ok('  and signing is still answered', (await outcome(request.sign)) === 'answered');
}

console.log('\nAllowing something small next to a refusal of something big');
{
  await freshProfile();
  await decide(request.encrypt, 'forever', 'deny', 20);
  const key = await decide(request.pubkey, 'forever', 'allow', 1);
  ok('the public key is allowed', key === PUBLIC_KEY, key);
  ok('encrypting is still refused without asking', (await outcome(request.encrypt)) === 'refused');
}

console.log('\nAllowing a level lifts the refusals it covers');
{
  await freshProfile();
  await decide(request.sign, 'forever', 'deny', 10);
  ok('signing is refused', (await outcome(request.sign)) === 'refused');
  // The public key sits below the refusal, so it still asks — and "authorize everything" is 20.
  const everything = await decide(request.pubkey, 'forever', 'allow', 20);
  ok('the public key is answered', everything === PUBLIC_KEY, everything);
  ok('and signing is allowed now: the grant lifted the refusal under it',
     (await outcome(request.sign)) === 'answered');
}

console.log('\nA decision stored before 1.26.0, as a single entry');
{
  await freshProfile({ condition: 'forever', level: 10, created_at: now(), decision: 'allow' });
  ok('is still honoured', (await outcome(request.sign)) === 'answered');
  await decide(request.encrypt, 'expirable_5m', 'deny', 20);
  ok('and survives a refusal at another level', (await outcome(request.sign)) === 'answered');
}

console.log('\nRevoking one decision leaves the others');
{
  await freshProfile();
  await decide(request.sign, 'forever', 'allow', 10);
  await decide(request.encrypt, 'forever', 'deny', 20);
  await storage.removePermissions(PUBLIC_KEY, HOST, 20);
  ok('the refusal is gone: encrypting asks again', (await outcome(request.encrypt)) === 'asked');
  ok('the grant stays: signing is answered', (await outcome(request.sign)) === 'answered');
  await storage.removePermissions(PUBLIC_KEY, HOST);
  ok('revoking the site removes the rest', (await outcome(request.sign)) === 'asked');
}

for (const id of [...control.windows.keys()]) await closeWindow(id);
await settle();
await rm(outdir, { recursive: true, force: true });
await rm(storageDir, { recursive: true, force: true });

console.log(`\n${state.pass} passed, ${state.fail} failed`);
process.exit(state.fail ? 1 : 0);
