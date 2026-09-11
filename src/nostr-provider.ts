import { Event, VerifiedEvent } from 'nostr-tools';
import {
  ContentScriptMessageResponseError,
  PromptParams,
  RelaysConfig
} from './types';

// Two extensions listening for the same key on the same page both answer, and the provider takes
// whichever reply arrives first — so a signature could come back from the other one. nos2x-fox and
// this can be installed side by side, which is exactly the case that breaks. Must match the value
// in the other file.
const EXTENSION_CODE = 'attest';

// Taken now, at document_start, before any page script has had the chance to replace it.
const getRandomValues = crypto.getRandomValues.bind(crypto);

/**
 * A request id nobody else can guess. Four decimal digits used to do this job, and failed at it two
 * ways: any window able to post to this one could answer all 10 000 and have its answer taken as the
 * extension's, and a page with a few hundred calls in flight handed one call's answer to another.
 * Not crypto.randomUUID(): that exists only in secure contexts, and plain-http pages sign too.
 */
function newRequestId(): string {
  const bytes = getRandomValues(new Uint8Array(16));
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

window.nostr = {
  _requests: {},
  _pubkey: null,

  async getPublicKey(): Promise<string | ContentScriptMessageResponseError> {
    if (this._pubkey) return this._pubkey;
    this._pubkey = await this._call('getPublicKey', {});
    return this._pubkey;
  },

  async signEvent(
    event: Event
  ): Promise<VerifiedEvent | ContentScriptMessageResponseError> {
    return this._call('signEvent', { event });
  },

  async getRelays(): Promise<RelaysConfig | ContentScriptMessageResponseError> {
    return this._call('getRelays', {});
  },

  nip04: {
    async encrypt(
      peer: string,
      plaintext: string
    ): Promise<string | ContentScriptMessageResponseError> {
      return window.nostr._call('nip04.encrypt', { peer, plaintext });
    },

    async decrypt(
      peer: string,
      ciphertext: string
    ): Promise<string | ContentScriptMessageResponseError> {
      return window.nostr._call('nip04.decrypt', { peer, ciphertext });
    }
  },

  nip44: {
    async encrypt(
      peer: string,
      plaintext: string
    ): Promise<string | ContentScriptMessageResponseError> {
      return window.nostr._call('nip44.encrypt', { peer, plaintext });
    },

    async decrypt(
      peer: string,
      ciphertext: string
    ): Promise<string | ContentScriptMessageResponseError> {
      return window.nostr._call('nip44.decrypt', { peer, ciphertext });
    }
  },

  _call(type: string, params: PromptParams) {
    const id = newRequestId();
    // The call is logged, its arguments are not. `params` is the whole event you are about to
    // sign, or the ciphertext you are about to decrypt, and this console belongs to the page.
    // The script that called knows them already — but every other script on the page can read
    // them here by wrapping console.log, and people paste consoles into bug reports.
    console.log(
      '%c[attest:%c' + id.slice(0, 8) + '%c]%c calling %c' + type,
      'background-color:#f1b912;font-weight:bold;color:white',
      'background-color:#f1b912;font-weight:bold;color:#a92727',
      'background-color:#f1b912;color:white;font-weight:bold',
      'color:auto',
      'font-weight:bold;color:#08589d;font-family:monospace'
    );

    return new Promise((resolve, reject) => {
      this._requests[id] = { resolve, reject };
      window.postMessage(
        {
          id,
          ext: EXTENSION_CODE,
          type,
          params
        },
        '*'
      );
    });
  }
};

window.addEventListener('message', message => {
  // Only this window's own messages. The content script answers by posting to this same window, but
  // any other window can post here too — a frame inside the page, or a site that opened this one and
  // kept the handle — and without this check its answer was taken as the extension's: a stranger's
  // public key, or a decrypted message the extension never produced. Scripts in the page itself are
  // not stopped by this and cannot be (they share this realm); every other window is.
  if (message.source !== window) return;
  if (
    !message.data ||
    message.data.response === null ||
    message.data.response === undefined ||
    message.data.ext !== EXTENSION_CODE ||
    !window.nostr._requests[message.data.id]
  )
    return;

  if (message.data.response.error) {
    const errorMessage =
      message.data.response.error.message ?? message.data.response.error;
    // No stack is copied across any more: the background's named moz-extension://<uuid>/, a
    // per-install identifier, and handing it to the page was the whole problem.
    let error = new Error(`${EXTENSION_CODE}: ` + errorMessage);
    window.nostr._requests[message.data.id].reject(error);
  } else {
    window.nostr._requests[message.data.id].resolve(message.data.response);
  }

  // Same reason: a decrypted direct message is a result, and it does not belong in a log the
  // page can read. Whether it succeeded is enough to debug against.
  console.log(
    '%c[attest:%c' + String(message.data.id).slice(0, 8) + '%c]%c ' +
      (message.data.response.error ? 'failed' : 'ok'),
    'background-color:#f1b912;font-weight:bold;color:white',
    'background-color:#f1b912;font-weight:bold;color:#a92727',
    'background-color:#f1b912;color:white;font-weight:bold',
    'color:auto'
  );

  delete window.nostr._requests[message.data.id];
});
