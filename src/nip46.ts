/**
 * The client side of NIP-46: Attest asks a remote signer (a "bunker") to sign, encrypt and decrypt,
 * instead of doing it with a key it holds itself.
 *
 * Built from nostr-tools parts — SimplePool for the relays, nip44 for the messages, finalizeEvent
 * and verifyEvent for the events — and not from its BunkerSigner, which this replaces for five
 * reasons found reading it: a request had no deadline and its listener was never removed, so a
 * signer that did not answer held the caller forever; an empty result (the decryption of "") never
 * resolved; a malformed reply threw inside the relay's event handler; an auth_url was reported once
 * and then forgotten; and the event that came back was checked for a valid signature but not for
 * being the event that was asked for, by the key that was meant to sign it.
 *
 * Nothing here is crypto of its own. Everything secret goes through nostr-tools.
 */
import { SimplePool, finalizeEvent, getPublicKey, verifyEvent, nip44 } from 'nostr-tools';
import type { EventTemplate, VerifiedEvent } from 'nostr-tools';

import { clearUint8Array } from './memoryUtils';

export const NOSTR_CONNECT_KIND = 24133;

/** How long a request waits when the caller does not say. A page request uses this. */
export const DEFAULT_TIMEOUT_MS = 30 * 1000;

/** What `connect` asks the remote signer to allow: the calls Attest forwards, and no others. */
const REQUESTED_PERMISSIONS = [
  'get_public_key',
  'sign_event',
  'nip04_encrypt',
  'nip04_decrypt',
  'nip44_encrypt',
  'nip44_decrypt'
].join(',');

/** Shown by the remote signer next to this connection. A display hint only, per the spec. */
const CLIENT_METADATA = JSON.stringify({
  name: 'Attest',
  url: 'https://github.com/briskness-byte/attest'
});

//#region Parsing ----------------------

export type BunkerPointer = {
  /** The key the remote signer talks with. Not necessarily the key it signs with. */
  signerPubkey: string;
  relays: string[];
  /** One-time pairing secret. Sent once, with `connect`, and never stored. */
  secret: string | null;
};

const HEX_KEY = /^[0-9a-f]{64}$/;

/**
 * A relay this client will talk to: wss://, or ws:// to this machine only. A bunker running on the
 * same computer has no certificate to offer; anything further away gets an encrypted socket or
 * nothing, because the relay address is where every request and every answer goes.
 */
export function isRemoteSignerRelay(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol === 'wss:') return true;
  if (parsed.protocol !== 'ws:') return false;
  return ['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname);
}

/**
 * Reads a bunker:// URI. Throws with a message the user can act on, since this is where a pasted
 * string goes wrong.
 *
 * Not nostr-tools' parseBunkerInput: anything that is not a bunker URI it tries as a NIP-05 name and
 * fetches from the web, and the current NIP-46 has dropped that way of logging in.
 */
export function parseBunkerUri(input: string): BunkerPointer {
  const text = input.trim();
  if (!text.toLowerCase().startsWith('bunker://')) {
    throw new Error('This is not a bunker:// address.');
  }

  const rest = text.slice('bunker://'.length);
  const queryStart = rest.indexOf('?');
  const signerPubkey = (queryStart === -1 ? rest : rest.slice(0, queryStart))
    .replace(/\/$/, '')
    .toLowerCase();
  if (!HEX_KEY.test(signerPubkey)) {
    throw new Error('The bunker address does not start with a valid public key.');
  }

  const query = new URLSearchParams(queryStart === -1 ? '' : rest.slice(queryStart + 1));
  const given = query
    .getAll('relay')
    .map(relay => relay.trim())
    .filter(Boolean);
  const relays = [...new Set(given.filter(isRemoteSignerRelay))];
  if (!relays.length) {
    throw new Error(
      given.length
        ? 'The bunker address names no relay this can use: they must start with wss://.'
        : 'The bunker address names no relay.'
    );
  }

  return { signerPubkey, relays, secret: query.get('secret') || null };
}

/** An auth_url this will open: https only. A javascript: or data: address is never followed. */
export function isOpenableAuthUrl(url: unknown): url is string {
  if (typeof url !== 'string') return false;
  try {
    return new URL(url).protocol === 'https:';
  } catch {
    return false;
  }
}

//#endregion Parsing ----------------------

//#region Errors ----------------------

/** The remote signer did not answer in time. */
export class RemoteSignerTimeout extends Error {}

/**
 * The remote signer wants the user to log in or approve somewhere else first. `url` has been
 * checked with isOpenableAuthUrl.
 */
export class RemoteSignerAuthRequired extends Error {
  constructor(readonly url: string) {
    super('approve the login in your remote signer, then try again');
  }
}

//#endregion Errors ----------------------

export type RequestOptions = {
  /** Default DEFAULT_TIMEOUT_MS. */
  timeoutMs?: number;
  /**
   * What to do when an auth_url comes in. Absent: the request fails at once with
   * RemoteSignerAuthRequired, so a page is told now rather than after it stopped listening. Set:
   * the request keeps waiting, from that moment for this long — used while connecting, where the
   * user is looking at Attest and can take their time.
   */
  authTimeoutMs?: number;
};

export type RemoteSignerOptions = {
  /** Called with every auth_url that passes isOpenableAuthUrl, once per request. */
  onAuthUrl?: (url: string) => void;
};

type Pending = {
  resolve: (result: string) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
  authTimeoutMs?: number;
  authSeen: boolean;
};

/** A request id nobody can guess or collide with: 16 random bytes, as the page side uses. */
function newRequestId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * One connection to one remote signer, from one client key.
 *
 * The client key is the session: whoever holds it can ask the remote signer for anything this
 * connection was allowed. It is zeroed on close(), together with the conversation key made from it.
 */
export class RemoteSigner {
  private relays: string[];
  private readonly clientPubkey: string;
  private readonly conversationKey: Uint8Array;
  private readonly pending = new Map<string, Pending>();
  private pool: SimplePool | null = null;
  private subscription: { close: () => void } | null = null;
  /** Settles when the relays have the subscription, so no answer is sent before anyone listens. */
  private subscribed: Promise<void> | null = null;
  private closed = false;

  constructor(
    private readonly clientKey: Uint8Array,
    readonly signerPubkey: string,
    relays: string[],
    private readonly options: RemoteSignerOptions = {}
  ) {
    if (!HEX_KEY.test(signerPubkey)) throw new Error('invalid remote signer public key');
    this.relays = relays.filter(isRemoteSignerRelay);
    if (!this.relays.length) throw new Error('no usable relay for the remote signer');
    this.clientPubkey = getPublicKey(clientKey);
    this.conversationKey = nip44.v2.utils.getConversationKey(clientKey, signerPubkey);
  }

  /** The relays in use, which switchRelays may have changed. */
  get relayList(): string[] {
    return [...this.relays];
  }

  get isClosed(): boolean {
    return this.closed;
  }

  /**
   * The first message of a new session. Sends the one-time secret, the calls Attest will make and a
   * name to show. The answer is "ack", or the secret itself.
   */
  async connect(secret: string | null, options?: RequestOptions): Promise<void> {
    const result = await this.request(
      'connect',
      [this.signerPubkey, secret ?? '', REQUESTED_PERMISSIONS, CLIENT_METADATA],
      options
    );
    if (result !== 'ack' && !(secret && result === secret)) {
      throw new Error('the remote signer did not accept the connection');
    }
  }

  /** The key the remote signer signs with: the user's, which may differ from signerPubkey. */
  async getPublicKey(options?: RequestOptions): Promise<string> {
    const result = await this.request('get_public_key', [], options);
    if (!HEX_KEY.test(result)) throw new Error('the remote signer sent an invalid public key');
    return result;
  }

  /**
   * Asks which relays the remote signer wants, and moves to them. Returns the new list, or null if
   * nothing changed. Relays that are not wss:// are dropped; if none is left nothing changes.
   */
  async switchRelays(options?: RequestOptions): Promise<string[] | null> {
    const result = await this.request('switch_relays', [], options);
    if (!result || result === 'null') return null;

    let list: unknown;
    try {
      list = JSON.parse(result);
    } catch {
      return null;
    }
    if (!Array.isArray(list)) return null;
    const relays = [
      ...new Set(list.filter((r): r is string => typeof r === 'string' && isRemoteSignerRelay(r)))
    ];
    if (!relays.length) return null;
    if (relays.length === this.relays.length && relays.every(r => this.relays.includes(r))) {
      return null;
    }

    // Listen on the new relays from the next request on. This is called right after connecting,
    // with nothing else waiting; anything that were would lose its answer with the old relays.
    const old = this.relays.filter(r => !relays.includes(r));
    this.relays = relays;
    this.unsubscribe();
    if (old.length) this.pool?.close(old);
    return this.relayList;
  }

  /**
   * Signs `template` remotely, and returns the result only if it is exactly that event, signed by
   * `userPubkey`. A remote signer that returns anything else — another event, another key, a
   * signature that does not verify — is refused, whatever its reason.
   */
  async signEvent(
    template: EventTemplate,
    userPubkey: string,
    options?: RequestOptions
  ): Promise<VerifiedEvent> {
    const asked = eventTemplateOf(template);
    const result = await this.request('sign_event', [JSON.stringify(asked)], options);

    let signed: any;
    try {
      signed = JSON.parse(result);
    } catch {
      throw new Error('the remote signer sent something that is not an event');
    }
    const problem = signedEventProblem(asked, signed, userPubkey);
    if (problem) throw new Error(`the remote signer's event was refused: ${problem}`);
    return signed as VerifiedEvent;
  }

  nip04Encrypt(peer: string, plaintext: string, options?: RequestOptions) {
    return this.request('nip04_encrypt', [peer, plaintext], options);
  }

  nip04Decrypt(peer: string, ciphertext: string, options?: RequestOptions) {
    return this.request('nip04_decrypt', [peer, ciphertext], options);
  }

  nip44Encrypt(peer: string, plaintext: string, options?: RequestOptions) {
    return this.request('nip44_encrypt', [peer, plaintext], options);
  }

  nip44Decrypt(peer: string, ciphertext: string, options?: RequestOptions) {
    return this.request('nip44_decrypt', [peer, ciphertext], options);
  }

  /**
   * Tells the remote signer this session is over. A courtesy only: the spec lets the signer ignore
   * it, so whoever calls this deletes the client key whatever the answer.
   */
  async logout(options?: RequestOptions): Promise<void> {
    await this.request('logout', [], options);
  }

  /** Fails everything waiting, drops the relays, and zeroes the keys. Safe to call twice. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    for (const [id, entry] of this.pending) {
      clearTimeout(entry.timer);
      entry.reject(new Error('the connection to the remote signer was closed'));
      this.pending.delete(id);
    }
    this.unsubscribe();
    this.pool?.destroy();
    this.pool = null;
    clearUint8Array(this.clientKey);
    clearUint8Array(this.conversationKey);
  }

  /**
   * Sends one request and waits for its answer, its error, or its deadline — whichever comes first.
   * The listener is removed in every one of those cases.
   */
  async request(method: string, params: string[], options: RequestOptions = {}): Promise<string> {
    if (this.closed) throw new Error('the connection to the remote signer was closed');

    const id = newRequestId();
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

    const answer = new Promise<string>((resolve, reject) => {
      const entry: Pending = {
        resolve,
        reject,
        timer: setTimeout(() => this.fail(id, timeoutError(timeoutMs)), timeoutMs),
        authTimeoutMs: options.authTimeoutMs,
        authSeen: false
      };
      this.pending.set(id, entry);
    });

    try {
      await this.subscribe();
      const event = finalizeEvent(
        {
          kind: NOSTR_CONNECT_KIND,
          tags: [['p', this.signerPubkey]],
          content: nip44.v2.encrypt(JSON.stringify({ id, method, params }), this.conversationKey),
          created_at: Math.floor(Date.now() / 1000)
        },
        this.clientKey
      );
      const pool = this.pool;
      if (!pool || !this.pending.has(id)) return await answer;
      // One relay taking it is enough; the signer listens on all of them.
      await Promise.any(pool.publish(this.relays, event)).catch(() => {
        throw new Error("could not reach any of the remote signer's relays");
      });
    } catch (error) {
      this.fail(id, error instanceof Error ? error : new Error(String(error)));
    }

    return answer;
  }

  private fail(id: string, error: Error) {
    const entry = this.pending.get(id);
    if (!entry) return;
    clearTimeout(entry.timer);
    this.pending.delete(id);
    entry.reject(error);
  }

  private subscribe(): Promise<void> {
    if (this.subscribed) return this.subscribed;
    this.pool ??= new SimplePool({ enableReconnect: true });

    this.subscribed = new Promise<void>(resolve => {
      this.subscription = this.pool!.subscribe(
        this.relays,
        // limit 0: only what arrives from now on. Answers to earlier sessions are of no use, and a
        // relay that kept them would replay every one.
        {
          kinds: [NOSTR_CONNECT_KIND],
          authors: [this.signerPubkey],
          '#p': [this.clientPubkey],
          limit: 0
        },
        {
          onevent: event => this.receive(event),
          // Resolves once every relay has answered or given up. A relay that never answers is not
          // waited for past the request's own deadline, which is running already.
          oneose: () => resolve(),
          onclose: () => {
            resolve();
            this.subscription = null;
            this.subscribed = null;
          }
        }
      );
    });
    return this.subscribed;
  }

  private unsubscribe() {
    this.subscription?.close();
    this.subscription = null;
    this.subscribed = null;
  }

  /**
   * One event from a relay. Anything that cannot be read is dropped without a word: a relay is not
   * trusted to send only what was asked for, and one bad event must not stop the next good one.
   */
  private receive(event: { pubkey: string; content: string }) {
    // The relay was asked for these authors only, but a relay can send anything.
    if (event.pubkey !== this.signerPubkey) return;

    let message: any;
    try {
      message = JSON.parse(nip44.v2.decrypt(event.content, this.conversationKey));
    } catch {
      return;
    }
    if (!message || typeof message.id !== 'string') return;

    const entry = this.pending.get(message.id);
    if (!entry) return;

    if (message.result === 'auth_url') {
      this.authChallenge(message.id, entry, message.error);
      return;
    }

    if (message.error !== undefined && message.error !== null && message.error !== '') {
      this.fail(message.id, new Error(`the remote signer refused: ${String(message.error)}`));
      return;
    }
    if (typeof message.result !== 'string') {
      this.fail(message.id, new Error('the remote signer sent an answer with no result'));
      return;
    }

    clearTimeout(entry.timer);
    this.pending.delete(message.id);
    entry.resolve(message.result);
  }

  /**
   * The remote signer wants the user somewhere else first. Its address is opened once per request,
   * and only if it is https.
   */
  private authChallenge(id: string, entry: Pending, url: unknown) {
    if (!isOpenableAuthUrl(url)) {
      this.fail(
        id,
        new Error('the remote signer asked for a login at an address that is not https')
      );
      return;
    }

    if (!entry.authSeen) {
      entry.authSeen = true;
      try {
        this.options.onAuthUrl?.(url);
      } catch (error) {
        console.error('Could not open the remote signer login.', error);
      }
    }

    if (entry.authTimeoutMs === undefined) {
      this.fail(id, new RemoteSignerAuthRequired(url));
      return;
    }

    // Wait for the answer that follows the login, from now on, under the longer deadline.
    clearTimeout(entry.timer);
    const authTimeoutMs = entry.authTimeoutMs;
    entry.timer = setTimeout(() => this.fail(id, timeoutError(authTimeoutMs)), authTimeoutMs);
  }
}

function timeoutError(ms: number): RemoteSignerTimeout {
  return new RemoteSignerTimeout(
    `the remote signer did not answer within ${Math.round(ms / 1000)} s`
  );
}

//#region Checking what comes back ----------------------

/**
 * The four fields that are signed and that a page chooses: nothing else is sent. Refuses a template
 * these cannot be compared on, since the check below is what makes a remote signature safe to hand
 * back.
 */
export function eventTemplateOf(event: any): EventTemplate {
  if (!event || typeof event !== 'object') throw new Error('empty event');
  const { kind, content, tags, created_at } = event;
  if (!Number.isInteger(kind) || kind < 0) throw new Error('the event has no valid kind');
  if (typeof content !== 'string') throw new Error('the event has no valid content');
  if (!Number.isInteger(created_at) || created_at < 0) {
    throw new Error('the event has no valid created_at');
  }
  if (
    !Array.isArray(tags) ||
    !tags.every(tag => Array.isArray(tag) && tag.every(item => typeof item === 'string'))
  ) {
    throw new Error('the event has no valid tags');
  }
  return { kind, content, tags: tags.map(tag => [...tag]), created_at };
}

/**
 * Why `signed` is not `asked`, signed by `userPubkey` — or null if it is. One reason, the first
 * found, so each kind of mismatch has its own message and its own test.
 */
export function signedEventProblem(
  asked: EventTemplate,
  signed: any,
  userPubkey: string
): string | null {
  if (!signed || typeof signed !== 'object') return 'not an event';
  if (signed.kind !== asked.kind) return 'a different kind';
  if (signed.content !== asked.content) return 'different content';
  if (signed.created_at !== asked.created_at) return 'a different created_at';
  if (!sameTags(signed.tags, asked.tags)) return 'different tags';
  if (signed.pubkey !== userPubkey) return 'signed by a different key';
  // Checks the id against the fields above, and the signature against the id and the pubkey.
  if (!verifyEvent(signed)) return 'the signature does not verify';
  return null;
}

function sameTags(a: unknown, b: string[][]): boolean {
  return (
    Array.isArray(a) &&
    a.length === b.length &&
    a.every(
      (tag, i) =>
        Array.isArray(tag) && tag.length === b[i].length && tag.every((item, j) => item === b[i][j])
    )
  );
}

//#endregion Checking what comes back ----------------------
