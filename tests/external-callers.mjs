#!/usr/bin/env node
// What another extension is called when it asks this one to sign.
//
//   node tests/external-callers.mjs
//
// Whatever name a caller is given ends up in two places that matter: the headline of the
// authorization dialog, and the row in the permissions table that a "forever" grant is stored
// under. So the name is not cosmetic — it is the entire basis on which somebody decides to say yes.
//
// It used to be the host out of sender.url, which for an extension is moz-extension://<uuid>/, and
// in Firefox that UUID is generated per installation: it names nobody and differs on every machine.
// The dialog asked people to trust a random string forever.
//
// These cases pin the replacement: the add-on's real id, prefixed so it can never share a row with
// a website, and a refusal when there is no id to be had.
import { rm } from 'node:fs/promises';

import { loadBackground } from './load-background.mjs';
import { reporter } from './harness.mjs';
import stub, { reset, sendExternal } from './browser-stub.mjs';

const { ok, state } = reporter();
process.on('unhandledRejection', error => {
  ok(`a promise was rejected with nobody listening (${error?.message ?? error})`, false);
});

const outdir = await loadBackground();

const PRIVATE_KEY = '5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a';
const PUBLIC_KEY = '17d1e9e0b1e56d1e9f5ec8b96e7e6b0ee89b0b1e5f4b0f31e0f0d2b6a0f1c3d4';

const settle = async (rounds = 20) => {
  for (let i = 0; i < rounds; i++) await new Promise(r => setTimeout(r, 0));
};

const TIMEOUT = Symbol('timed out');
/**
 * Resolve with the answer, or with TIMEOUT. Without this, a request that is answered with a prompt
 * instead of a refusal — what happened before the switch existed — leaves the await hanging and
 * takes the whole suite down with it, reporting nothing.
 */
function within(ms, promise) {
  let timer;
  return Promise.race([
    Promise.resolve(promise).finally(() => clearTimeout(timer)),
    new Promise(r => { timer = setTimeout(() => r(TIMEOUT), ms); })
  ]);
}

async function freshProfile() {
  reset();
  await stub.storage.local.set({
    private_key: PRIVATE_KEY,
    pin_enabled: false,
    // Everything below is about what happens once other extensions are allowed; the switch itself
    // and its default are the first case.
    external_callers_allowed: true
  });
}

/** The host a prompt was registered under — the string the dialog will show. */
async function promptedHosts() {
  const { open_prompts: raw } = await stub.storage.session.get('open_prompts');
  return JSON.parse(raw ?? '[]').map(p => p.host);
}

const signRequest = { type: 'signEvent', params: { event: { kind: 1, tags: [], content: 'hi' } } };

console.log('\nWith the switch in the options left as it is');
{
  await freshProfile();
  await stub.storage.local.remove('external_callers_allowed'); // as on a new install, or 1.26.0

  const answer = await within(
    1000,
    sendExternal(signRequest, {
      id: 'somebody-else@example.com',
      url: 'moz-extension://4f9a2c1e-8b3d-4a2f-9c1e-77b0d5e6a1c2/page.html'
    })
  );
  await settle();
  ok('another extension is refused', !!answer?.error, answer === TIMEOUT ? 'no answer at all' : answer);
  ok('  and told where it can be turned on', /options/.test(answer?.error?.message ?? ''), answer);
  ok('  without a prompt being put in front of anybody', (await promptedHosts()).length === 0);
}

console.log('\nAn extension with an id of its own');
{
  await freshProfile();

  sendExternal(signRequest, {
    id: 'somebody-else@example.com',
    url: 'moz-extension://4f9a2c1e-8b3d-4a2f-9c1e-77b0d5e6a1c2/page.html'
  });
  await settle();

  const hosts = await promptedHosts();
  ok('the request reaches the permission prompt', hosts.length === 1, hosts);
  ok(
    'named by the add-on id rather than the per-install UUID',
    hosts[0] === 'extension:somebody-else@example.com',
    hosts[0]
  );
  ok(
    'and the UUID from sender.url appears nowhere',
    !String(hosts[0]).includes('4f9a2c1e'),
    hosts[0]
  );
  ok(
    'marked as an extension, so it cannot share a row with a website of the same name',
    String(hosts[0]).startsWith('extension:'),
    hosts[0]
  );
}

console.log('\nA caller with no id at all');
{
  await freshProfile();

  const answer = await sendExternal(signRequest, {
    url: 'moz-extension://4f9a2c1e-8b3d-4a2f-9c1e-77b0d5e6a1c2/page.html'
  });
  await settle();

  ok('is refused', !!answer?.error, answer);
  ok('and no prompt is raised on its behalf', (await promptedHosts()).length === 0);
}

console.log('\nA method that does not exist');
{
  await freshProfile();

  const answer = await sendExternal({ type: 'getSecretKey', params: {} }, { id: 'somebody-else@example.com' });
  await settle();
  ok('is refused by name', /unknown method/.test(answer?.error?.message ?? ''), answer);
  ok(
    'without a prompt — which used to list every capability, and never settled once answered',
    (await promptedHosts()).length === 0
  );
}

await rm(outdir, { recursive: true, force: true });

console.log(`\n${state.pass} passed, ${state.fail} failed`);
process.exit(state.fail ? 1 : 0);
