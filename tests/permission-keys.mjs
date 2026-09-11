#!/usr/bin/env node
// Which key a site's permissions live under, and what happened to the ones stored before.
//
//   node tests/permission-keys.mjs
//
// Before 1.25.0 permissions were keyed on location.host, which has no scheme, so a grant made on
// https://example.com was honoured on http://example.com — for anybody able to serve that. They
// are keyed on the origin now, and the grants people already had are moved across once, when the
// new version first runs. These cases pin both halves: the key, and that nobody's grants are lost
// or widened on the way. The browser half (real pages, real schemes) is tests/origins.mjs.
//
// A stub suite, like prompt-window.mjs, and for a reason of the same kind: the move happens at the
// moment the background first loads, and only a stub lets a test put old-format data in storage
// before that moment.
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
const grant = (created_at, extra = {}) =>
  ({ condition: 'forever', level: 20, created_at, decision: 'allow', ...extra });

const perms = async () => (await stub.storage.local.get('profiles')).profiles[PUBLIC_KEY].permissions ?? {};
const openPrompts = async () => JSON.parse((await stub.storage.session.get('open_prompts')).open_prompts ?? '[]');
const ask = host => send({ type: 'getPublicKey', host, params: {} });

// ------------------------------------------------------------------ 1. the rules on their own

const { exports: common, outdir: commonDir } = await loadModule('src/common.ts');

console.log('\nWhich keys can hold a remembered answer');
for (const [key, want] of [
  ['https://example.com', true],
  ['http://localhost:3000', true],
  ['http://[::1]:8080', true],
  ['extension:somebody@example.com', true],
  ['example.com', false],
  ['file:///home/someone/page.html', false],
  ['sandboxed:https://example.com/page', false],
  ['null', false],
  ['', false],
  ['https://example.com/with/a/path', false]
]) {
  ok(`${JSON.stringify(key)} → ${want}`, common.isRememberableKey(key) === want);
}

console.log('\nWhere a grant stored under a bare host goes');
for (const [key, want] of [
  ['primal.net', 'https://primal.net'],
  ['example.com:8443', 'https://example.com:8443'],
  ['localhost:3000', 'http://localhost:3000'],
  ['app.localhost:5173', 'http://app.localhost:5173'],
  ['127.0.0.1:8080', 'http://127.0.0.1:8080'],
  ['[::1]:3000', 'http://[::1]:3000'],
  ['somesite.onion', 'http://somesite.onion'],
  ['https://already.example', 'https://already.example'],
  ['extension:somebody@example.com', 'extension:somebody@example.com'],
  ['', null]
]) {
  const got = common.originForLegacyKey(key);
  ok(`${JSON.stringify(key)} → ${want}`, got === want, got);
}

// ------------------------------------------------------------------ 2. the move, on first start

console.log('\nThe background moves what was stored before');
reset();
await stub.storage.local.set({
  private_key: PRIVATE_KEY,
  active_public_key: PUBLIC_KEY,
  pin_enabled: false,
  profiles: {
    [PUBLIC_KEY]: {
      privateKey: PRIVATE_KEY,
      relays: {},
      permissions: {
        'primal.net': grant(100),
        'localhost:3000': grant(200, { decision: 'deny', level: 10 }),
        'extension:somebody@example.com': grant(300),
        '': grant(400) // the one key every local file shared
      }
    }
  }
});
const outdir = await loadBackground(); // runs the move, as the first start of 1.25.0 does
await settle();

const moved = await perms();
ok('a grant on a public host moves to https', !!moved['https://primal.net'] && !moved['primal.net'],
   Object.keys(moved));
ok('  and is the same grant apart from its key',
   JSON.stringify(moved['https://primal.net']) === JSON.stringify(grant(100)));
ok('a denial on localhost moves to http, and is still a denial',
   moved['http://localhost:3000']?.decision === 'deny', moved['http://localhost:3000']);
ok('another extension keeps its key', !!moved['extension:somebody@example.com']);
ok('the key every local file shared is dropped', !('' in moved));
ok('the move is marked done',
   (await stub.storage.local.get('permissions_keyed_by')).permissions_keyed_by === 'origin');

// ------------------------------------------------------------------ 3. what a grant covers now

console.log('\nWhat the moved grant covers');
const overHttps = await within(500, ask('https://primal.net'));
ok('the https site is answered without asking', overHttps === PUBLIC_KEY, overHttps);
const overHttp = ask('http://primal.net');
await settle();
ok('the same name over plain http has to ask', (await openPrompts()).some(p => p.host === 'http://primal.net'));

console.log('\nA remembered answer is stored under the site that asked');
{
  const p = (await openPrompts()).find(x => x.host === 'http://primal.net');
  // The answer names another site. The prompt was opened for http://primal.net, and that is what
  // the grant must be stored under.
  await send({ prompt: true, id: p.id, condition: 'forever', level: 1, host: 'https://somewhere-else.example' }, OWN_PAGE);
  await settle();
  ok('the waiting request is answered', (await within(500, overHttp)) === PUBLIC_KEY);
  const after = await perms();
  ok('the grant is stored under the site that asked', !!after['http://primal.net'], Object.keys(after));
  ok('  and not under whatever the answer said', !after['https://somewhere-else.example']);
}

// ------------------------------------------------------------------ 4. no origin of its own

console.log('\nA page with no origin of its own');
{
  const file = 'file:///home/someone/Downloads/page.html';
  const first = ask(file);
  await settle();
  const p = (await openPrompts()).find(x => x.host === file);
  ok('may still ask', !!p);
  await send({ prompt: true, id: p.id, condition: 'forever', level: 1, host: file }, OWN_PAGE);
  await settle();
  ok('is answered this once', (await within(500, first)) === PUBLIC_KEY);
  ok('but "forever" is not stored for it', !(file in (await perms())), Object.keys(await perms()));

  ask(file);
  await settle();
  ok('so its next request asks again',
     (await openPrompts()).filter(x => x.host === file).length === 1);

  // An entry under such a key — from an old export, say — is not honoured either.
  const sandboxed = 'sandboxed:https://example.com/page';
  const { profiles } = await stub.storage.local.get('profiles');
  profiles[PUBLIC_KEY].permissions[sandboxed] = grant(500);
  await stub.storage.local.set({ profiles });
  const answer = await within(300, ask(sandboxed));
  ok('a stored grant under such a key is not honoured', answer === TIMEOUT, answer);
}

for (const id of [...control.windows.keys()]) await closeWindow(id);
await settle();
await rm(outdir, { recursive: true, force: true });
await rm(commonDir, { recursive: true, force: true });

console.log(`\n${state.pass} passed, ${state.fail} failed`);
process.exit(state.fail ? 1 : 0);
