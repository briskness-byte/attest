#!/usr/bin/env node
// The NIP-46 client on its own, against a fake relay and a fake remote signer.
//
//   node tests/nip46-client.mjs
//
// The remote signer is the party this client trusts least after the page: it can be slow, silent,
// wrong or hostile, and every one of those has to end in an answer the caller can act on — never a
// promise that hangs, and never a signature over something other than what was asked for. Each way
// a returned event can differ from the requested one has its own check, because a check that covers
// "the event is wrong" in general passes as long as one of them is caught.
//
// No browser: the client is plain TypeScript over nostr-tools, and node has WebSocket built in.
import { generateSecretKey, getPublicKey, nip04, nip44, verifyEvent } from 'nostr-tools';
import { rm } from 'node:fs/promises';

import { loadModule } from './load-background.mjs';
import { reporter } from './harness.mjs';
import { startRelay } from './fake-relay.mjs';
import { startBunker } from './fake-bunker.mjs';

const { ok, state } = reporter();
process.on('unhandledRejection', error => {
  ok(`a promise was rejected with nobody listening (${error?.message ?? error})`, false);
});

const { exports: nip46, outdir } = await loadModule('src/nip46.ts');
const { parseBunkerUri, isOpenableAuthUrl, RemoteSigner, RemoteSignerTimeout, RemoteSignerAuthRequired } = nip46;

const SHORT = 1500; // deadline for requests that are meant to time out
const now = () => Math.floor(Date.now() / 1000);
const outcome = p => p.then(value => ({ value }), error => ({ error }));
const timed = async p => { const t = Date.now(); const r = await outcome(p); return { ...r, ms: Date.now() - t }; };

// ---------------------------------------------------------------------------------------------
console.log('\nparsing a bunker:// address');
{
  const pk = 'ab'.repeat(32);
  const p = parseBunkerUri(`  bunker://${pk.toUpperCase()}?relay=wss%3A%2F%2Fr1.example&relay=wss://r2.example&relay=wss://r1.example&secret=s3cr3t `);
  ok('reads the signer key, lower-cased', p.signerPubkey === pk, p.signerPubkey);
  ok('reads every relay, once each', JSON.stringify(p.relays) === JSON.stringify(['wss://r1.example', 'wss://r2.example']), p.relays);
  ok('reads the secret', p.secret === 's3cr3t');
  ok('no secret reads as null', parseBunkerUri(`bunker://${pk}?relay=wss://r.example`).secret === null);

  const refused = (input, why) => {
    let message = null;
    try { parseBunkerUri(input); } catch (e) { message = e.message; }
    ok(`refuses ${why}`, typeof message === 'string', message);
  };
  refused('nostrconnect://' + pk + '?relay=wss://r.example&secret=x', 'a nostrconnect:// address (not in v1)');
  refused('user@example.com', 'a NIP-05 name (dropped from the spec, and it would mean a web fetch)');
  refused(`bunker://${pk.slice(2)}?relay=wss://r.example`, 'a key that is too short');
  refused(`bunker://${pk}`, 'an address with no relay');
  refused(`bunker://${pk}?relay=ws://relay.example`, 'an unencrypted relay on another machine');
  refused(`bunker://${pk}?relay=https://relay.example`, 'a relay that is not a WebSocket');
  ok('accepts ws:// to this machine', parseBunkerUri(`bunker://${pk}?relay=ws://127.0.0.1:7777`).relays[0] === 'ws://127.0.0.1:7777');

  ok('opens an https auth_url', isOpenableAuthUrl('https://signer.example/login?x=1'));
  for (const bad of ['http://signer.example/', 'javascript:alert(1)', 'data:text/html,hi', 'not a url', 42, null]) {
    ok(`never opens ${JSON.stringify(bad)}`, !isOpenableAuthUrl(bad));
  }
}

// ---------------------------------------------------------------------------------------------
const relay = await startRelay();
const relay2 = await startRelay();
const bunker = startBunker({ relays: [relay.url], secret: 'pairing-secret', switchTo: [relay.url, relay2.url] });
await new Promise(r => setTimeout(r, 300)); // the bunker's subscription reaches the relay

const authUrls = [];
const clientKey = generateSecretKey();
const signer = new RemoteSigner(clientKey, bunker.signerPubkey, [relay.url], { onAuthUrl: url => authUrls.push(url) });

console.log('\nconnecting');
{
  const wrong = new RemoteSigner(generateSecretKey(), bunker.signerPubkey, [relay.url]);
  const r = await outcome(wrong.connect('not-the-secret', { timeoutMs: 5000 }));
  ok('a wrong secret is refused, with the signer\'s reason', /refused: invalid secret/.test(r.error?.message), r.error?.message);
  wrong.close();

  const c = await outcome(signer.connect(parseBunkerUri(bunker.uri()).secret, { timeoutMs: 5000 }));
  ok('the right secret connects', !c.error, c.error?.message);
  const sent = bunker.state.requests.find(q => q.method === 'connect' && q.client === getPublicKey(clientKey));
  ok('connect names the signer key and carries the secret', sent?.params[0] === bunker.signerPubkey && sent?.params[1] === 'pairing-secret');
  ok('connect asks for the forwarded calls only', sent?.params[2] === 'get_public_key,sign_event,nip04_encrypt,nip04_decrypt,nip44_encrypt,nip44_decrypt', sent?.params[2]);
  ok('connect says it is Attest', JSON.parse(sent?.params[3] ?? '{}').name === 'Attest');
  ok('requests are NIP-44 (the bunker decrypted them with nip44 only)', !!sent);

  const again = new RemoteSigner(generateSecretKey(), bunker.signerPubkey, [relay.url]);
  const r2 = await outcome(again.connect('pairing-secret', { timeoutMs: 5000 }));
  ok('the same secret does not connect a second client', !!r2.error, r2.value);
  again.close();
}

console.log('\nthe user key is not the signer key');
{
  const pk = await outcome(signer.getPublicKey());
  ok('get_public_key answers the user key', pk.value === bunker.userPubkey, pk.error?.message);
  ok('…which differs from the key the signer talks with', bunker.userPubkey !== bunker.signerPubkey);
}

console.log('\nswitching relays');
{
  const moved = await outcome(signer.switchRelays());
  ok('takes the relays the signer asks for', JSON.stringify(moved.value) === JSON.stringify([relay.url, relay2.url]), moved.value ?? moved.error?.message);
  const before = relay2.published.length;
  await signer.getPublicKey();
  ok('the next request also goes out on the new relay', relay2.published.length > before);
}

const template = () => ({ kind: 1, content: 'hello from a test', tags: [['t', 'qa'], ['p', 'cd'.repeat(32), 'wss://x.example']], created_at: now() });

console.log('\nsigning');
{
  const t = template();
  const r = await outcome(signer.signEvent(t, bunker.userPubkey));
  ok('an honest signature comes back', !r.error && verifyEvent(r.value), r.error?.message);
  ok('…by the user key', r.value?.pubkey === bunker.userPubkey);
  ok('…over exactly the requested event', r.value?.content === t.content && r.value?.kind === t.kind && r.value?.created_at === t.created_at && JSON.stringify(r.value?.tags) === JSON.stringify(t.tags));

  const sent = bunker.state.requests.at(-1);
  const fields = Object.keys(JSON.parse(sent.params[0])).sort().join(',');
  ok('only kind, content, tags and created_at are sent', fields === 'content,created_at,kind,tags', fields);

  const cases = [
    [{ mode: 'tamper', field: 'kind' }, 'a different kind'],
    [{ mode: 'tamper', field: 'content' }, 'different content'],
    [{ mode: 'tamper', field: 'tags' }, 'different tags'],
    [{ mode: 'tamper', field: 'created_at' }, 'a different created_at'],
    [{ mode: 'tamper', field: 'pubkey' }, 'signed by a different key'],
    [{ mode: 'tamper', field: 'sig' }, 'the signature does not verify'],
    [{ mode: 'tamper', field: 'resigned' }, 'different content'],
    [{ mode: 'other-key' }, 'signed by a different key'],
    [{ mode: 'not-json' }, 'not an event']
  ];
  for (const [behaviour, reason] of cases) {
    bunker.set(behaviour);
    const x = await outcome(signer.signEvent(template(), bunker.userPubkey));
    const label = behaviour.field ? `${behaviour.mode} ${behaviour.field}` : behaviour.mode;
    ok(`refused when the signer returns ${label}: "${reason}"`, !!x.error && x.error.message.includes(reason), x.error?.message ?? 'accepted');
  }
  bunker.set({ mode: 'normal' });

  const asked = bunker.state.requests.length;
  for (const [what, bad] of [
    ['no created_at', { kind: 1, content: 'x', tags: [] }],
    ['a kind that is not a number', { kind: '1', content: 'x', tags: [], created_at: now() }],
    ['tags that are not lists of strings', { kind: 1, content: 'x', tags: [['t', 1]], created_at: now() }],
    ['no content', { kind: 1, tags: [], created_at: now() }]
  ]) {
    const x = await outcome(signer.signEvent(bad, bunker.userPubkey));
    ok(`an event with ${what} is refused before it is sent`, !!x.error, x.value);
  }
  ok('…and none of them reached the signer', bunker.state.requests.length === asked);
}

console.log('\nencrypting and decrypting');
{
  const peerKey = generateSecretKey();
  const peer = getPublicKey(peerKey);
  const c4 = await signer.nip04Encrypt(peer, 'secret note');
  ok('nip04 encrypts for the peer', (await nip04.decrypt(peerKey, bunker.userPubkey, c4)) === 'secret note');
  ok('nip04 decrypts', (await signer.nip04Decrypt(peer, c4)) === 'secret note');
  const c44 = await signer.nip44Encrypt(peer, 'another note');
  ok('nip44 encrypts for the peer', nip44.v2.decrypt(c44, nip44.v2.utils.getConversationKey(peerKey, bunker.userPubkey)) === 'another note');
  ok('nip44 decrypts', (await signer.nip44Decrypt(peer, c44)) === 'another note');

  bunker.set({ mode: 'empty' });
  const e = await timed(signer.nip44Decrypt(peer, c44, { timeoutMs: SHORT }));
  ok('an empty result is an answer, not a hang', e.value === '' && e.ms < SHORT, e);
  bunker.set({ mode: 'normal' });
}

console.log('\nwhen the signer does not cooperate');
{
  bunker.set({ mode: 'silent' });
  const s = await timed(signer.getPublicKey({ timeoutMs: SHORT }));
  ok('silence ends in a timeout at the deadline', s.error instanceof RemoteSignerTimeout && s.ms >= SHORT - 50 && s.ms < SHORT + 1000, { ms: s.ms, m: s.error?.message });
  ok('…that says what happened', s.error?.message === 'the remote signer did not answer in time', s.error?.message);
  ok('…and leaves nothing waiting behind it', signer.pending.size === 0, signer.pending.size);

  bunker.set({ mode: 'slow', ms: 300 });
  const slow = await timed(signer.getPublicKey({ timeoutMs: 5000 }));
  ok('a slow answer inside the deadline is taken', slow.value === bunker.userPubkey, slow.error?.message);

  bunker.set({ mode: 'refuse', error: 'the user said no' });
  const no = await outcome(signer.signEvent(template(), bunker.userPubkey));
  ok('a refusal carries the signer\'s reason', no.error?.message === 'the remote signer refused: the user said no', no.error?.message);

  bunker.set({ mode: 'garbage' });
  const g = await timed(signer.getPublicKey({ timeoutMs: SHORT }));
  ok('an answer that does not decrypt is ignored, and the deadline still holds', g.error instanceof RemoteSignerTimeout, g.error?.message ?? g.value);

  bunker.set({ mode: 'no-result' });
  const nr = await outcome(signer.getPublicKey({ timeoutMs: SHORT }));
  ok('an answer with neither result nor error is an error', /no result/.test(nr.error?.message), nr.error?.message);
  bunker.set({ mode: 'normal' });
}

console.log('\nan answer from somebody else');
{
  // A relay can send anything. This one sends a well-formed, properly signed answer — by a key that
  // is not the signer's, past the authors filter the client asked for.
  const { finalizeEvent } = await import('nostr-tools');
  bunker.set({ mode: 'silent' });
  const pending = timed(signer.getPublicKey({ timeoutMs: SHORT }));
  await new Promise(r => setTimeout(r, 200));
  const req = bunker.state.requests.at(-1);
  const strangerKey = generateSecretKey();
  const key = nip44.v2.utils.getConversationKey(strangerKey, getPublicKey(clientKey));
  relay.inject(finalizeEvent({ kind: 24133, tags: [['p', getPublicKey(clientKey)]], created_at: now(),
    content: nip44.v2.encrypt(JSON.stringify({ id: req.id, result: getPublicKey(strangerKey) }), key) }, strangerKey));
  relay2.inject(finalizeEvent({ kind: 24133, tags: [['p', getPublicKey(clientKey)]], created_at: now(),
    content: nip44.v2.encrypt(JSON.stringify({ id: req.id, result: getPublicKey(strangerKey) }), key) }, strangerKey));
  const r = await pending;
  ok('is not taken as the signer\'s', r.error instanceof RemoteSignerTimeout, r.value);
  bunker.set({ mode: 'normal' });
}

console.log('\nauth_url during a page request');
{
  authUrls.length = 0;
  bunker.set({ mode: 'auth', url: 'https://signer.example/approve?req=1' });
  const a = await timed(signer.signEvent(template(), bunker.userPubkey, { timeoutMs: 30000 }));
  ok('fails at once rather than waiting out the deadline', a.ms < 2000, a.ms);
  ok('…with a message that says what to do', a.error instanceof RemoteSignerAuthRequired && a.error.message === 'approve the login in your remote signer, then try again', a.error?.message);
  ok('…and the address to open', a.error?.url === 'https://signer.example/approve?req=1');
  ok('the address is handed out to be opened, once', JSON.stringify(authUrls) === JSON.stringify(['https://signer.example/approve?req=1']), authUrls);

  authUrls.length = 0;
  bunker.set({ mode: 'auth', url: 'javascript:alert(document.domain)' });
  const j = await outcome(signer.getPublicKey({ timeoutMs: 5000 }));
  ok('an auth_url that is not https is refused', /not https/.test(j.error?.message), j.error?.message);
  ok('…and never handed out to be opened', authUrls.length === 0, authUrls);
}

console.log('\nauth_url while connecting');
{
  authUrls.length = 0;
  bunker.set({ mode: 'auth', url: 'https://signer.example/login', thenMs: SHORT + 500 });
  const a = await timed(signer.getPublicKey({ timeoutMs: SHORT, authTimeoutMs: 10000 }));
  ok('waits past the first deadline for the answer after the login', a.value === bunker.userPubkey && a.ms > SHORT, { ms: a.ms, e: a.error?.message });
  ok('the login address is handed out once', authUrls.length === 1, authUrls);

  bunker.set({ mode: 'auth', url: 'https://signer.example/login' });
  const b = await timed(signer.getPublicKey({ timeoutMs: SHORT, authTimeoutMs: SHORT }));
  ok('…but not for ever: the longer deadline holds too', b.error instanceof RemoteSignerTimeout, b.error?.message ?? b.value);
  bunker.set({ mode: 'normal' });
}

console.log('\nswitching relays while a request is waiting');
{
  // Fresh relays and a fresh signer, so the subscriptions counted below are only these. The bunker
  // reads on both relays and asks to move from the first to the second.
  const r1 = await startRelay();
  const r2 = await startRelay();
  const b = startBunker({ relays: [r1.url], listen: [r1.url, r2.url], switchTo: [r2.url] });
  await new Promise(r => setTimeout(r, 300));
  const baseline = r1.openSubscriptions(); // the bunker's own
  const baseline2 = r2.openSubscriptions();

  // The answer still comes on the old relay: the signer finishes what it started where it started.
  const s1 = new RemoteSigner(generateSecretKey(), b.signerPubkey, [r1.url]);
  await s1.connect(null, { timeoutMs: 5000 });
  b.set({ mode: 'slow', ms: 800 }, ['get_public_key']);
  const waiting = timed(s1.getPublicKey({ timeoutMs: 5000 }));
  await new Promise(r => setTimeout(r, 150));
  const moved = await outcome(s1.switchRelays({ timeoutMs: 5000 }));
  ok('the switch happens while the request waits', JSON.stringify(moved.value) === JSON.stringify([r2.url]), moved.value ?? moved.error?.message);
  const w = await waiting;
  ok('the waiting request gets its answer from the old relay, not a timeout', w.value === b.userPubkey && w.ms < 3000, { ms: w.ms, e: w.error?.message });
  await new Promise(r => setTimeout(r, 200));
  ok('…after which the old relay is let go', r1.openSubscriptions() === baseline, { open: r1.openSubscriptions(), baseline });
  b.state.publishTo = [r2.url]; // from here the signer answers where it moved to
  const next = await outcome(s1.getPublicKey({ timeoutMs: 5000 }));
  ok('…and the next request is answered on the new relay', next.value === b.userPubkey, next.error?.message);
  await s1.getPublicKey({ timeoutMs: 5000 });
  ok('…over one subscription there, not a new one per request', r2.openSubscriptions() === baseline2 + 1, { open: r2.openSubscriptions(), baseline2 });

  // The answer comes on the new relay: the signer moved before it answered.
  b.state.publishTo = [r1.url];
  const s2 = new RemoteSigner(generateSecretKey(), b.signerPubkey, [r1.url]);
  await s2.connect(null, { timeoutMs: 5000 });
  b.set({ mode: 'slow', ms: 800 }, ['get_public_key']);
  const waiting2 = timed(s2.getPublicKey({ timeoutMs: 5000 }));
  await new Promise(r => setTimeout(r, 150));
  await s2.switchRelays({ timeoutMs: 5000 });
  b.state.publishTo = [r2.url];
  const w2 = await waiting2;
  ok('the waiting request gets its answer from the new relay, not a timeout', w2.value === b.userPubkey && w2.ms < 3000, { ms: w2.ms, e: w2.error?.message });

  // Closing while the old subscription is still held fails the request instead of leaving it.
  b.state.publishTo = [r1.url];
  const s3 = new RemoteSigner(generateSecretKey(), b.signerPubkey, [r1.url]);
  await s3.connect(null, { timeoutMs: 5000 });
  b.set({ mode: 'silent' }, ['get_public_key']);
  const waiting3 = timed(s3.getPublicKey({ timeoutMs: 30000 }));
  await new Promise(r => setTimeout(r, 150));
  await s3.switchRelays({ timeoutMs: 5000 });
  s3.close();
  const w3 = await waiting3;
  ok('closing after a switch still fails what was waiting, at once', /closed/.test(w3.error?.message) && w3.ms < 2000, { ms: w3.ms, e: w3.error?.message });
  await new Promise(r => setTimeout(r, 200));
  ok('…and lets go of the old relay too', r1.openSubscriptions() === baseline, { open: r1.openSubscriptions(), baseline });

  s1.close(); s2.close();
  b.close();
  await r1.close();
  await r2.close();
}

console.log('\nrelays that cannot be reached');
{
  const dead = new RemoteSigner(generateSecretKey(), bunker.signerPubkey, ['ws://127.0.0.1:1']);
  const d = await timed(dead.getPublicKey({ timeoutMs: 10000 }));
  ok('fails with a reason, before the deadline', d.error?.message === "could not reach the remote signer's relays" && d.ms < 10000, { ms: d.ms, m: d.error?.message });
  dead.close();
}

console.log('\nclosing');
{
  bunker.set({ mode: 'silent' });
  const waiting = timed(signer.getPublicKey({ timeoutMs: 30000 }));
  await new Promise(r => setTimeout(r, 200));
  signer.close();
  const w = await waiting;
  ok('a request still waiting is failed, not left hanging', /closed/.test(w.error?.message) && w.ms < 2000, w);
  ok('the client key is zeroed', clientKey.every(b => b === 0));
  const after = await outcome(signer.getPublicKey());
  ok('nothing more can be sent', /closed/.test(after.error?.message), after.error?.message);
}

bunker.close();
await relay.close();
await relay2.close();
await rm(outdir, { recursive: true, force: true });

console.log(`\n${state.pass} passed, ${state.fail} failed`);
process.exit(state.fail ? 1 : 0);
