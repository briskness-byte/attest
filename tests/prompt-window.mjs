#!/usr/bin/env node
// The prompt window, tested where it broke.
//
//   node tests/prompt-window.mjs
//
// WHAT THIS PINS
//
// A second permission request arriving while a prompt window is open is queued behind the first
// rather than opening a second popup. The window id it queues against can be stale — a window the
// user closed stays in the map until windows.onRemoved has run — and asking windows.get() about a
// window that no longer exists rejects. That rejection had no handler, so the promise it fed never
// settled: no popup, no error, no log line, and a page waiting forever for a signature.
//
// It is not theoretical. It is how a zap was paid out of a connected wallet with no signature on
// it: the client asked, the second prompt never came, and it fell back to a plain invoice.
//
// The rule the cases below hold the code to: **a request either shows a prompt or fails out loud.
// Never silence.** Each one asserts an answer arrives within a deadline, because "hangs forever"
// and "still working on it" look identical without one.
//
// WHY THIS ONE USES A STUB, when security-boundary.mjs deliberately does not
//
// That suite is right about its own subject: a boundary between a page and a background script
// only exists in a browser, and mocking it would prove the mock agrees with itself. This is a
// different subject. What fails here is a race between a window disappearing and the event that
// says so, and a real browser will not hold that gap open on request — windows.onRemoved fires
// when it fires. The stub exists to freeze exactly that moment, and nothing else: everything it
// does not fake (nostr-tools, storage, the permission model) is the real code, bundled by esbuild
// with only `webextension-polyfill` swapped out. It complements the browser suite rather than
// replacing it, and neither one covers the other's ground.

import { getPublicKey } from 'nostr-tools';
import { rm } from 'node:fs/promises';

import { loadBackground, OWN_PAGE } from './load-background.mjs';
import { reporter } from './harness.mjs';
import stub, { control, reset, killWindowSilently, closeWindow, send } from './browser-stub.mjs';

const { ok, state } = reporter();

// An unhandled rejection is the signature of the bug this file exists for: a promise nobody is
// listening to. Node would kill the run over it, which reads as a broken test rather than a broken
// extension, so it is reported as a failure like anything else.
process.on('unhandledRejection', error => {
  ok(`a promise was rejected with nobody listening (${error?.message ?? error})`, false);
});

const tick = () => new Promise(r => setTimeout(r, 0));
/** Let the code under test run its promise chain to a standstill. */
const settle = async (rounds = 20) => {
  for (let i = 0; i < rounds; i++) await tick();
};

const TIMEOUT = Symbol('timed out');
/** Resolve with the value, or with TIMEOUT — the difference between an answer and silence. */
function within(ms, promise) {
  let timer;
  return Promise.race([
    Promise.resolve(promise).finally(() => clearTimeout(timer)),
    new Promise(r => {
      timer = setTimeout(() => r(TIMEOUT), ms);
    })
  ]);
}

// ------------------------------------------------------------------ the extension under test

const outdir = await loadBackground();

// ------------------------------------------------------------------ fixtures

const PRIVATE_KEY = '5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a';
const PUBLIC_KEY = getPublicKey(Buffer.from(PRIVATE_KEY, 'hex'));
const HOST = 'https://example.com'; // an origin, as the content script sends since 1.25.0

/**
 * A wallet with a key, no PIN, and no permission granted to anyone yet — so every call prompts.
 *
 * background.ts keeps its prompt bookkeeping in module state that no reset can reach, so every
 * window still open is closed properly first: that is what makes the module let go of the
 * requests behind them. Window ids are never reused across scenarios for the same reason — a
 * recycled id would let a leftover entry pass for a live window.
 */
async function freshProfile() {
  for (const id of [...control.windows.keys()]) await closeWindow(id);
  await settle();

  const nextWindowId = control.nextWindowId;
  reset();
  control.nextWindowId = nextWindowId;

  await stub.storage.local.set({
    private_key: PRIVATE_KEY,
    active_public_key: PUBLIC_KEY,
    profiles: { [PUBLIC_KEY]: { permissions: {}, relays: {} } },
    pin_enabled: false
  });
}

const signRequest = (content = 'hello') =>
  send({
    type: 'signEvent',
    host: HOST,
    params: { event: { kind: 1, created_at: Math.floor(Date.now() / 1000), tags: [], content } }
  });

/** The prompt queue. Stored as a JSON string, not an array — storage.ts stringifies it. */
async function openPrompts() {
  const { open_prompts: raw } = await stub.storage.session.get('open_prompts');
  return JSON.parse(raw ?? '[]');
}

/**
 * Answer the newest prompt the way the prompt page does: from one of the extension's own pages, and
 * one with no tab, so no window is torn down.
 */
async function answerLatestPrompt(condition = 'single') {
  const prompts = await openPrompts();
  const last = prompts[prompts.length - 1];
  if (!last) throw new Error('no prompt was registered to answer');
  await send({ prompt: true, id: last.id, condition, host: HOST, level: 10 }, OWN_PAGE);
  await settle();
  return last.id;
}

const promptCount = async () => (await openPrompts()).length;

// ------------------------------------------------------------------ 1. the regression

console.log('\nA queued request whose window has silently gone away');
{
  await freshProfile();

  const first = signRequest('first');
  await settle();
  ok('the first request opens a prompt window', control.created.length === 1, control.created.length);
  ok('and registers a prompt', (await promptCount()) === 1);

  // The user closes the popup, and onRemoved has not run yet: the map still points at it.
  const firstWindow = control.created[0].id;
  killWindowSilently(firstWindow);

  const second = signRequest('second');
  await settle();

  ok(
    'the second request opens a new window instead of queueing against a dead one',
    control.created.length === 2,
    control.created.map(w => w.id)
  );
  ok('and is registered as its own prompt', (await promptCount()) === 2);

  await answerLatestPrompt();
  const answer = await within(500, second);
  ok('the second request is answered rather than left hanging', answer !== TIMEOUT);
  ok('and the answer is a signed event', answer?.pubkey === PUBLIC_KEY && !!answer?.sig, answer);

  // The first request is still outstanding; closing its window properly must refuse it, not
  // abandon it. A caller is entitled to an answer either way.
  await closeWindow(firstWindow);
  const firstAnswer = await within(500, first);
  ok('the abandoned first request is refused, not forgotten', firstAnswer !== TIMEOUT, firstAnswer);
  ok('and says it was a permission problem', !!firstAnswer?.error?.message, firstAnswer);
}

// ------------------------------------------------------------------ 2. two at once

console.log('\nTwo requests arriving in the same tick');
{
  await freshProfile();

  const a = signRequest('a');
  const b = signRequest('b'); // no await in between: both land before either window exists
  await settle();

  ok('exactly one window is opened for the pair', control.created.length === 1, control.created.length);
  ok('and both are registered as prompts', (await promptCount()) === 2, await promptCount());

  await answerLatestPrompt();
  ok('the second one is answered', (await within(500, b)) !== TIMEOUT);

  await closeWindow(control.created[0].id);
  ok('and the first one is not left hanging either', (await within(500, a)) !== TIMEOUT);
}

// ------------------------------------------------------------------ 3. no window at all

console.log('\nWhen no window can be opened at all');
{
  await freshProfile();
  control.failToOpen = true;

  const answer = await within(500, signRequest('nowhere'));
  ok('the request fails instead of hanging', answer !== TIMEOUT, answer);
  ok('and the caller is told why', !!answer?.error?.message, answer);
  ok('no prompt is left behind in storage', (await promptCount()) === 0);
}

// ------------------------------------------------------------------ 4. the ordinary path

console.log('\nThe ordinary path still works');
{
  await freshProfile();

  const one = signRequest('ordinary');
  await settle();
  ok('a window opens', control.created.length === 1);

  await answerLatestPrompt();
  const event = await within(500, one);
  ok('the event comes back signed', event?.pubkey === PUBLIC_KEY && !!event?.sig, event);

  const refused = signRequest('refused');
  await settle();
  await answerLatestPrompt('no');
  const refusal = await within(500, refused);
  ok('a rejection comes back as an error, not as silence', !!refusal?.error?.message, refusal);
}

// ------------------------------------------------------------------ 5. who answers, and where

console.log('\nWhere the queue is kept, and who may answer it');
{
  await freshProfile();

  const pending = signRequest('kept');
  await settle();
  ok('the queue is kept in session storage', (await promptCount()) === 1);
  ok(
    '  and not in storage.local, which is written to disk',
    (await stub.storage.local.get('open_prompts')).open_prompts === undefined
  );

  const [p] = await openPrompts();
  const fromPage = await send(
    { prompt: true, id: p.id, condition: 'forever', host: HOST, level: 10 },
    { url: 'https://example.com/', tab: { id: 99, windowId: 99 } }
  );
  await settle();
  ok('an answer from a web page is refused', !!fromPage?.error, fromPage);
  ok('  and the request is still waiting', (await within(100, pending)) === TIMEOUT);

  await answerLatestPrompt();
  const event = await within(500, pending);
  ok('the prompt page can still answer it', !!event?.sig, event);
}

// ------------------------------------------------------------------

await rm(outdir, { recursive: true, force: true });

console.log(`\n${state.pass} passed, ${state.fail} failed`);
process.exit(state.fail ? 1 : 0);
