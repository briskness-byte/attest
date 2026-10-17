/**
 * Answering a page through a remote signer (NIP-46), for a profile that has one instead of a key.
 *
 * The background has already decided the page may ask — the same permission check as for a local
 * key — and answered getPublicKey and getRelays from storage. Everything else comes here.
 *
 * When there is a connection, and for how long:
 *
 *   - Not before it is needed. Nothing connects when the browser starts or when the profile becomes
 *     the active one, only on the first request that has to reach the remote signer. Relays would
 *     otherwise learn when this browser is online on days nothing is signed.
 *   - With a PIN or passphrase, for as long as it stays cached — the client key is decrypted with it,
 *     and lives no longer than a local key's PIN does. Without one, for the browser session.
 *   - Never cut under a request: a connection due to close waits until nothing is in flight.
 */
import browser from 'webextension-polyfill';

import * as Storage from './storage';
import { generateSecretKey } from 'nostr-tools';
import {
  DEFAULT_TIMEOUT_MS,
  REMOTE_SIGNER_ERRORS,
  RemoteSigner,
  isOpenableAuthUrl,
  parseBunkerUri
} from './nip46';
import { getCachedPin, onPinCleared } from './pinCache';
import { decryptPrivateKey } from './pinEncryption';
import {
  convertHexToUint8Array,
  convertUint8ArrayToHex,
  isPrivateKeyEncrypted,
  isRemoteProfile,
  messageOf
} from './common';
import {
  ConfigurationKeys,
  ContentScriptMessageResponse,
  PromptParams,
  RemoteSignerConfig
} from './types';

/**
 * How long a page waits, and how many requests may wait. An object rather than constants only so
 * the tests can change them; nothing in the extension does.
 *
 * Each site has up to `perSiteInFlight` requests at the remote signer at once, and up to
 * `perSiteQueue` more waiting behind them — enough for an app that decrypts a screenful of messages
 * at once. A queued request keeps the deadline it had when it arrived, so it never waits longer than
 * `timeoutMs` in all. Only a request that finds its site's queue full, or the queues of all sites
 * together at `totalQueued`, is refused at once: that is the wall a page firing in a loop hits.
 */
export const REMOTE_LIMITS = {
  timeoutMs: DEFAULT_TIMEOUT_MS,
  perSiteInFlight: 8,
  perSiteQueue: 50,
  totalQueued: 200
};

/** A request waiting for a slot at its site. `start` hands it one, already counted as its own. */
type Waiter = { start: () => void };

/** One site's requests: how many are at the remote signer, and who waits behind them. */
type Site = { running: number; queue: Waiter[] };

type Session = {
  userPubkey: string;
  signerPubkey: string;
  /** The client key as stored, sealed or not: a different one is a different connection. */
  storedClientKey: string;
  signer: RemoteSigner;
  /** Opened with the cached PIN, so closed when it is cleared. */
  pinBound: boolean;
  /** Due to close as soon as nothing is in flight. */
  expired: boolean;
  /** Whether switch_relays has been asked on this connection yet. */
  relaysChecked: boolean;
};

let session: Session | null = null;
/** A connection being opened, shared by every request that arrives meanwhile. */
let opening: Promise<Session> | null = null;
/** Connections replaced while requests were still in flight on them. */
const retired: Session[] = [];
/** Requests at the remote signer, over all sites. */
let inFlight = 0;
/** Requests queued behind them, over all sites. */
let queued = 0;
const sites = new Map<string, Site>();
const waitingListeners: (() => void)[] = [];

/** How many page requests are waiting on a remote signer right now, queued ones included. */
export function remoteRequestsWaiting(): number {
  return inFlight + queued;
}

/** Runs `listener` whenever that number changes, for the toolbar badge. */
export function onRemoteWaitingChanged(listener: () => void): void {
  waitingListeners.push(listener);
}

function setInFlight(n: number) {
  inFlight = n;
  for (const listener of waitingListeners) listener();
  if (inFlight === 0) closeExpired();
}

/**
 * Answers one page request through the active profile's remote signer.
 *
 * @param site - Who asked: the permission key of the page, or of the extension. Limits are per site.
 * @param unlock - Asks the user for the PIN, as for a local key; null when they did not give it.
 */
export async function remoteRequest(
  site: string,
  type: string,
  params: PromptParams,
  userPubkey: string,
  remote: RemoteSignerConfig,
  unlock: () => Promise<string | null>
): Promise<ContentScriptMessageResponse> {
  // Everything below counts against this, waiting in the queue included. Time spent typing the PIN
  // is added back: that is the user at Attest, not the remote signer keeping a page waiting.
  let deadline = Date.now() + REMOTE_LIMITS.timeoutMs;

  const slot = await takeSlot(site, deadline);
  if (slot !== 'started') return { error: { message: REMOTE_SIGNER_ERRORS[slot] } };

  let current: Session | null = null;
  try {
    const unlocking = Date.now();
    current = await sessionFor(userPubkey, remote, unlock);
    deadline += Date.now() - unlocking;
    const timeoutMs = deadline - Date.now();
    if (timeoutMs <= 0) return { error: { message: REMOTE_SIGNER_ERRORS.timeout } };
    const options = { timeoutMs };
    const { signer } = current;

    switch (type) {
      case 'getPublicKey':
        return userPubkey;
      case 'signEvent':
        if (!params.event) return { error: { message: 'empty event' } };
        return await signer.signEvent(params.event, userPubkey, options);
      case 'nip04.encrypt':
        return await signer.nip04Encrypt(params.peer, params.plaintext as string, options);
      case 'nip04.decrypt':
        return await signer.nip04Decrypt(params.peer, params.ciphertext as string, options);
      case 'nip44.encrypt':
        return await signer.nip44Encrypt(params.peer, params.plaintext as string, options);
      case 'nip44.decrypt':
        return await signer.nip44Decrypt(params.peer, params.ciphertext as string, options);
      default:
        return { error: { message: `unknown method "${type}"` } };
    }
  } catch (error) {
    return { error: { message: messageOf(error) } };
  } finally {
    if (current && !current.relaysChecked && !current.signer.isClosed) {
      current.relaysChecked = true;
      checkRelays(current);
    }
    releaseSlot(site);
  }
}

/**
 * A slot at the remote signer for one of `site`'s requests: now if it has one free, otherwise after
 * a wait in its queue. 'busy' when the queue is full, 'timeout' when the deadline passes in it.
 */
function takeSlot(site: string, deadline: number): Promise<'started' | 'busy' | 'timeout'> {
  let entry = sites.get(site);
  if (!entry) sites.set(site, (entry = { running: 0, queue: [] }));
  const own = entry;

  if (own.running < REMOTE_LIMITS.perSiteInFlight) {
    own.running++;
    setInFlight(inFlight + 1);
    return Promise.resolve('started');
  }
  if (own.queue.length >= REMOTE_LIMITS.perSiteQueue || queued >= REMOTE_LIMITS.totalQueued) {
    forgetIfIdle(site, own);
    return Promise.resolve('busy');
  }

  return new Promise(resolve => {
    const waiter: Waiter = {
      start: () => {
        clearTimeout(timer);
        resolve('started');
      }
    };
    const timer = setTimeout(() => {
      const at = own.queue.indexOf(waiter);
      if (at === -1) return;
      own.queue.splice(at, 1);
      setQueued(queued - 1);
      forgetIfIdle(site, own);
      resolve('timeout');
    }, deadline - Date.now());
    own.queue.push(waiter);
    setQueued(queued + 1);
  });
}

/**
 * A request is done with its slot. The next one in the site's queue gets it as it is — counted
 * already — so a request arriving in between cannot take it from under the queue.
 */
function releaseSlot(site: string) {
  const own = sites.get(site);
  if (!own) return;
  const next = own.queue.shift();
  if (next) {
    setQueued(queued - 1);
    next.start();
    return;
  }
  own.running--;
  setInFlight(inFlight - 1);
  forgetIfIdle(site, own);
}

function forgetIfIdle(site: string, own: Site) {
  if (own.running === 0 && !own.queue.length && sites.get(site) === own) sites.delete(site);
}

function setQueued(n: number) {
  queued = n;
  for (const listener of waitingListeners) listener();
}

/** The open connection for this profile, or a new one. */
async function sessionFor(
  userPubkey: string,
  remote: RemoteSignerConfig,
  unlock: () => Promise<string | null>
): Promise<Session> {
  const current = session;
  if (current) {
    // Reading an expired PIN clears it, and clearing it expires the session bound to it — which may
    // retire it during this await. Hence `current`, and the check that it is still `session`.
    if (current.pinBound && !(await getCachedPin())) current.expired = true;
    const same =
      current.userPubkey === userPubkey &&
      current.signerPubkey === remote.signerPubkey &&
      current.storedClientKey === remote.clientKey;
    if (same && !current.expired && !current.signer.isClosed && session === current) return current;
    if (session === current) retire();
  }

  opening ??= open(userPubkey, remote, unlock).finally(() => {
    opening = null;
  });
  return opening;
}

async function open(
  userPubkey: string,
  remote: RemoteSignerConfig,
  unlock: () => Promise<string | null>
): Promise<Session> {
  let hexKey = remote.clientKey;
  const pinBound = isPrivateKeyEncrypted(remote.clientKey);
  if (pinBound) {
    const pin = (await getCachedPin()) ?? (await unlock());
    if (!pin) throw new Error('the PIN is needed to use the remote signer');
    hexKey = await decryptPrivateKey(pin, remote.clientKey);
  }

  const signer = new RemoteSigner(
    convertHexToUint8Array(hexKey),
    remote.signerPubkey,
    remote.relays,
    {
      onAuthUrl: openAuthUrl
    }
  );
  session = {
    userPubkey,
    signerPubkey: remote.signerPubkey,
    storedClientKey: remote.clientKey,
    signer,
    pinBound,
    expired: false,
    relaysChecked: false
  };
  return session;
}

/**
 * The spec asks a client to check for new relays on every new connection. Done after the first
 * answer rather than before it, so the page that caused the connection does not wait for this too.
 * A failure here changes nothing: the relays already stored keep working.
 */
async function checkRelays(current: Session) {
  try {
    const relays = await current.signer.switchRelays({ timeoutMs: REMOTE_LIMITS.timeoutMs });
    if (relays) await Storage.updateRemoteRelays(current.userPubkey, current.signerPubkey, relays);
  } catch (error) {
    console.debug('switch_relays did not complete.', messageOf(error));
  }
}

/** Puts the current connection aside, to be closed when nothing is in flight. */
function retire() {
  if (!session) return;
  session.expired = true;
  retired.push(session);
  session = null;
  if (inFlight === 0) closeExpired();
}

function closeExpired() {
  if (session?.expired) retire();
  if (inFlight !== 0) return;
  for (const old of retired.splice(0)) old.signer.close();
}

// The PIN that opened the client key has gone, so the connection goes too — once it is idle.
onPinCleared(() => {
  if (session?.pinBound) {
    session.expired = true;
    closeExpired();
  }
});

// A different active profile, another connection for it, or protection turned on or off: whatever is
// open no longer belongs to what is stored, and is closed once idle.
browser.storage.onChanged.addListener(async (changes, area) => {
  if (area !== 'local' || !session) return;
  if (
    !(ConfigurationKeys.ACTIVE_PUBLIC_KEY in changes) &&
    !(ConfigurationKeys.PROFILES in changes) &&
    !(ConfigurationKeys.PIN_ENABLED in changes)
  ) {
    return;
  }
  const active = await Storage.getActiveProfile().catch(() => null);
  const activePubkey = await Storage.getActivePublicKey();
  const stillThis =
    session &&
    isRemoteProfile(active) &&
    activePubkey === session.userPubkey &&
    active.remote.signerPubkey === session.signerPubkey &&
    active.remote.clientKey === session.storedClientKey;
  if (session && !stillThis) {
    session.expired = true;
    closeExpired();
  }
});

/** Login pages already opened, by address and when, so a burst of requests opens one tab. */
const authUrlsOpened = new Map<string, number>();
const AUTH_URL_REOPEN_MS = 60 * 1000;

/**
 * Opens the remote signer's login page in an ordinary tab, where its address can be seen. Only
 * https, which nip46.ts has checked already and which is checked here again: this is the one place
 * a remote party chooses an address that the browser goes to.
 */
function openAuthUrl(url: string) {
  if (!isOpenableAuthUrl(url)) return;
  const now = Date.now();
  if ((authUrlsOpened.get(url) ?? 0) > now - AUTH_URL_REOPEN_MS) return;
  authUrlsOpened.set(url, now);
  browser.tabs.create({ url, active: true }).catch(error => {
    console.error('Could not open the remote signer login.', error);
  });
}

//#region Connecting and disconnecting ----------------------

/**
 * How long connecting may take. The first deadline is for a remote signer that simply answers; the
 * second starts when it asks for a login (auth_url), and is long because the user is now on its
 * page, typing a password or approving on a phone — and is looking at Attest's options page, which
 * says it is waiting. A page's request never waits like this; see RequestOptions in nip46.ts.
 */
export const CONNECT_LIMITS = {
  timeoutMs: DEFAULT_TIMEOUT_MS,
  authTimeoutMs: 5 * 60 * 1000,
  /** A connection made but neither used nor cancelled is dropped after this. */
  unconfirmedMs: 10 * 60 * 1000
};

/** Answered by the remote signer, and waiting for the user to check the npub it signs as. */
type PendingConnection = {
  signer: RemoteSigner;
  clientKeyHex: string;
  userPubkey: string;
  signerPubkey: string;
  relays: string[];
  timer: ReturnType<typeof setTimeout>;
};

const pendingConnections = new Map<string, PendingConnection>();

export type ConnectionOffer = {
  id: string;
  userPubkey: string;
  signerPubkey: string;
  relays: string[];
};

/**
 * Connects to the remote signer a bunker:// address names, with a new client key, and asks which
 * key it signs with. Nothing is stored yet: the user first sees that key, and confirms it with
 * confirmConnection — or not.
 *
 * The one-time secret in the address is sent with `connect` and kept nowhere, not even here.
 */
export async function startConnection(uri: string): Promise<ConnectionOffer> {
  const pointer = parseBunkerUri(uri);
  const key = generateSecretKey();
  const clientKeyHex = convertUint8ArrayToHex(key);
  const signer = new RemoteSigner(key, pointer.signerPubkey, pointer.relays, {
    onAuthUrl: openAuthUrl
  });

  try {
    const options = {
      timeoutMs: CONNECT_LIMITS.timeoutMs,
      authTimeoutMs: CONNECT_LIMITS.authTimeoutMs
    };
    await signer.connect(pointer.secret, options);
    const userPubkey = await signer.getPublicKey(options);

    // A profile that holds this key's private key is never turned into a remote one; say so now,
    // not after the user has confirmed.
    const existing = (await Storage.readProfiles())[userPubkey];
    if (existing && !isRemoteProfile(existing)) {
      throw new Error(
        'This key already has a profile here that holds its private key. Delete that profile first to sign for it through a remote signer.'
      );
    }

    // The spec asks for this on every new connection. Its answer is stored with the profile; if it
    // does not come, the relays in the address stay.
    const moved = await signer.switchRelays({ timeoutMs: 10 * 1000 }).catch(() => null);
    const relays = moved ?? pointer.relays;

    const id = convertUint8ArrayToHex(crypto.getRandomValues(new Uint8Array(16)));
    pendingConnections.set(id, {
      signer,
      clientKeyHex,
      userPubkey,
      signerPubkey: pointer.signerPubkey,
      relays,
      timer: setTimeout(() => cancelConnection(id), CONNECT_LIMITS.unconfirmedMs)
    });
    return { id, userPubkey, signerPubkey: pointer.signerPubkey, relays };
  } catch (error) {
    // The remote signer may have made a session already; it is told it is not wanted.
    await signer.logout({ timeoutMs: 5000 }).catch(() => {});
    signer.close();
    throw error;
  }
}

/**
 * Stores the connection the user confirmed, as a profile, and makes it the one that signs: choosing
 * a remote signer is an explicit act, and this is it.
 *
 * @param seal - What the client key is stored as: encrypted with the PIN when protection is on.
 */
export async function confirmConnection(
  id: string,
  seal: (clientKeyHex: string) => Promise<string>
): Promise<string> {
  const pending = pendingConnections.get(id);
  if (!pending) throw new Error('That connection is no longer waiting. Connect again.');
  pendingConnections.delete(id);
  clearTimeout(pending.timer);
  // Requests open their own connection when one is needed; this one has done its job.
  pending.signer.close();

  const clientKey = await seal(pending.clientKeyHex);
  await Storage.saveRemoteProfile(pending.userPubkey, {
    signerPubkey: pending.signerPubkey,
    relays: pending.relays,
    clientKey
  });
  const profile = await Storage.getProfile(pending.userPubkey);
  await Storage.switchActiveProfile(pending.userPubkey, profile);
  return pending.userPubkey;
}

/** The user did not want it. The remote signer is told, and the client key is forgotten. */
export async function cancelConnection(id: string): Promise<void> {
  const pending = pendingConnections.get(id);
  if (!pending) return;
  pendingConnections.delete(id);
  clearTimeout(pending.timer);
  await pending.signer.logout({ timeoutMs: 5000 }).catch(() => {});
  pending.signer.close();
}

/**
 * Ends a remote profile: tells the remote signer (logout), then deletes the profile and its client
 * key whatever the answer — the spec makes logout a courtesy, and a key kept because a signer did not
 * answer would be a session nobody can see.
 *
 * @param open - The client key in hex, from what is stored: decrypted with the PIN when sealed, or
 *   null when the PIN was not given. Then no logout is sent, and the profile is deleted all the same.
 * @returns Whether the remote signer acknowledged the logout.
 */
export async function disconnect(
  publicKey: string,
  open: (storedClientKey: string) => Promise<string | null>
): Promise<boolean> {
  const profile = await Storage.getProfile(publicKey);
  if (!isRemoteProfile(profile)) throw new Error('That profile has no remote signer.');

  let loggedOut = false;
  const hexKey = await open(profile.remote.clientKey).catch(() => null);
  if (hexKey) {
    const signer = new RemoteSigner(
      convertHexToUint8Array(hexKey),
      profile.remote.signerPubkey,
      profile.remote.relays
    );
    try {
      await signer.logout({ timeoutMs: 5000 });
      loggedOut = true;
    } catch (error) {
      console.debug('The remote signer did not acknowledge the logout.', messageOf(error));
    } finally {
      signer.close();
    }
  }

  // An open connection for this profile closes on its own when the profile goes from storage.
  await Storage.deleteProfile(publicKey);
  return loggedOut;
}

//#endregion Connecting and disconnecting ----------------------
