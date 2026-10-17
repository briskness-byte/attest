// A remote signer for tests: a NIP-46 bunker that can be told to misbehave in each way the client
// has to survive.
//
// It talks to the fake relay through nostr-tools, over a real socket, with real NIP-44 — the same
// path a real bunker's answers take. Its own key (the one it talks with) and the user's key (the one
// it signs with) are different on purpose: the spec allows that, and a client that mixes the two up
// passes every test where they happen to be equal.
//
// `behaviour` is read on every request, so a test can change it between calls:
//
//   { mode: 'normal' }            answer as a well-behaved signer would
//   { mode: 'silent' }            never answer
//   { mode: 'slow', ms }          answer after ms
//   { mode: 'refuse', error }     answer with an error
//   { mode: 'empty' }             answer with "" as the result
//   { mode: 'garbage' }           answer with content that does not decrypt
//   { mode: 'no-result' }         answer with neither result nor error
//   { mode: 'auth', url, thenMs } send an auth_url; if thenMs is set, the real answer after thenMs
//   { mode: 'tamper', field }     sign, then change kind | content | tags | created_at | pubkey | sig,
//                                 or 'resigned' — a different event, properly signed by the user key
//   { mode: 'other-key' }         sign with a key that is not the user's
//   { mode: 'not-json' }          answer sign_event with a string that is not JSON
//
// `methods`, if given, limits the behaviour to those methods; the rest answer normally.
import { SimplePool, finalizeEvent, generateSecretKey, getPublicKey, nip04, nip44 } from 'nostr-tools';

const KIND = 24133;

// `listen` is where it reads requests (default: `relays`); `state.publishTo` is where it sends its
// answers, `relays` until a test moves it — the way a signer that switched relays would.
// `userKey`, if given, is the key it signs with; a new one otherwise.
export function startBunker({ relays, listen = relays, secret = null, switchTo = null, userKey: given = null } = {}) {
  const signerKey = generateSecretKey();
  const userKey = given ?? generateSecretKey();
  const signerPubkey = getPublicKey(signerKey);
  const userPubkey = getPublicKey(userKey);
  const pool = new SimplePool();

  const state = {
    behaviour: { mode: 'normal' },
    methods: null,
    /** Every request received, decrypted, in order: { client, id, method, params }. */
    requests: [],
    /** Client pubkeys that connected successfully. */
    sessions: new Set(),
    secretUsed: false,
    /** Requests being answered slowly right now, and the most there have been at once. */
    inProgress: 0,
    maxInProgress: 0,
    publishTo: relays
  };

  const respond = async (client, payload) => {
    const key = nip44.v2.utils.getConversationKey(signerKey, client);
    const content = payload === '__garbage__' ? 'not nip44 at all' : nip44.v2.encrypt(JSON.stringify(payload), key);
    const event = finalizeEvent({ kind: KIND, tags: [['p', client]], content, created_at: Math.floor(Date.now() / 1000) }, signerKey);
    await Promise.any(pool.publish(state.publishTo, event));
  };

  const honest = (client, method, params) => {
    switch (method) {
      case 'connect': {
        if (secret) {
          if (params[1] !== secret || state.secretUsed) return { error: 'invalid secret' };
          state.secretUsed = true;
        }
        state.sessions.add(client);
        return { result: 'ack' };
      }
      case 'ping': return { result: 'pong' };
      case 'get_public_key': return { result: userPubkey };
      case 'switch_relays': return { result: JSON.stringify(switchTo) };
      case 'logout': state.sessions.delete(client); return { result: 'ack' };
      case 'sign_event': {
        const t = JSON.parse(params[0]);
        return { result: JSON.stringify(finalizeEvent(t, userKey)) };
      }
      case 'nip04_encrypt': return { result: nip04.encrypt(userKey, params[0], params[1]) };
      case 'nip04_decrypt': return { result: nip04.decrypt(userKey, params[0], params[1]) };
      case 'nip44_encrypt': return { result: nip44.v2.encrypt(params[1], nip44.v2.utils.getConversationKey(userKey, params[0])) };
      case 'nip44_decrypt': return { result: nip44.v2.decrypt(params[1], nip44.v2.utils.getConversationKey(userKey, params[0])) };
      default: return { error: `unknown method ${method}` };
    }
  };

  const tampered = (params, field) => {
    const t = JSON.parse(params[0]);
    if (field === 'resigned') return finalizeEvent({ ...t, content: t.content + ' (changed)' }, userKey);
    const e = finalizeEvent(t, userKey);
    if (field === 'kind') e.kind += 1;
    if (field === 'content') e.content += '!';
    if (field === 'tags') e.tags = [...e.tags, ['t', 'added']];
    if (field === 'created_at') e.created_at += 1;
    if (field === 'pubkey') e.pubkey = getPublicKey(generateSecretKey());
    if (field === 'sig') e.sig = (e.sig[0] === 'a' ? 'b' : 'a') + e.sig.slice(1);
    return e;
  };

  const sub = pool.subscribe(listen, { kinds: [KIND], '#p': [signerPubkey], limit: 0 }, {
    onevent: async event => {
      let request;
      try {
        request = JSON.parse(nip44.v2.decrypt(event.content, nip44.v2.utils.getConversationKey(signerKey, event.pubkey)));
      } catch { return; }
      const { id, method, params } = request;
      state.requests.push({ client: event.pubkey, id, method, params });

      const b = state.methods && !state.methods.includes(method) ? { mode: 'normal' } : state.behaviour;
      // Only sessions that connected get answers, as a real bunker would.
      const known = method === 'connect' || state.sessions.has(event.pubkey);
      const answer = known ? honest(event.pubkey, method, params) : { error: 'not connected' };

      switch (b.mode) {
        case 'silent': return;
        case 'slow':
          state.maxInProgress = Math.max(state.maxInProgress, ++state.inProgress);
          await new Promise(r => setTimeout(r, b.ms));
          state.inProgress--;
          return respond(event.pubkey, { id, ...answer });
        case 'refuse': return respond(event.pubkey, { id, result: '', error: b.error ?? 'user refused' });
        case 'empty': return respond(event.pubkey, { id, result: '' });
        case 'garbage': return respond(event.pubkey, '__garbage__');
        case 'no-result': return respond(event.pubkey, { id });
        case 'auth':
          await respond(event.pubkey, { id, result: 'auth_url', error: b.url });
          if (b.thenMs != null) {
            await new Promise(r => setTimeout(r, b.thenMs));
            return respond(event.pubkey, { id, ...honest(event.pubkey, method, params) });
          }
          return;
        case 'tamper':
          if (method !== 'sign_event') return respond(event.pubkey, { id, ...answer });
          return respond(event.pubkey, { id, result: JSON.stringify(tampered(params, b.field)) });
        case 'other-key':
          if (method !== 'sign_event') return respond(event.pubkey, { id, ...answer });
          return respond(event.pubkey, { id, result: JSON.stringify(finalizeEvent(JSON.parse(params[0]), generateSecretKey())) });
        case 'not-json':
          return respond(event.pubkey, { id, result: method === 'sign_event' ? 'not an event' : answer.result });
        default:
          return respond(event.pubkey, { id, ...answer });
      }
    }
  });

  return {
    signerPubkey,
    userPubkey,
    userKey,
    state,
    /** A bunker:// URI for this signer, with its secret if it has one. */
    uri: () => `bunker://${signerPubkey}?` +
      relays.map(r => `relay=${encodeURIComponent(r)}`).join('&') +
      (secret ? `&secret=${encodeURIComponent(secret)}` : ''),
    set(behaviour, methods = null) { state.behaviour = behaviour; state.methods = methods; },
    close() { sub.close(); pool.destroy(); }
  };
}
