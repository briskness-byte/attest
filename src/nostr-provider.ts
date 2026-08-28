import { Event, VerifiedEvent } from 'nostr-tools';
import {
  ContentScriptMessageResponseError,
  PromptParams,
  RelaysConfig
} from './types';

const EXTENSION_CODE = 'nos2x-fox';

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
    const id = Math.random().toString().slice(-4);
    // The call is logged, its arguments are not. `params` is the whole event you are about to
    // sign, or the ciphertext you are about to decrypt, and this console belongs to the page.
    // The script that called knows them already — but every other script on the page can read
    // them here by wrapping console.log, and people paste consoles into bug reports.
    console.log(
      '%c[nos2x-fox:%c' + id + '%c]%c calling %c' + type,
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
    let error = new Error(`${EXTENSION_CODE}: ` + errorMessage);
    error.stack = message.data.response.error.stack;
    window.nostr._requests[message.data.id].reject(error);
  } else {
    window.nostr._requests[message.data.id].resolve(message.data.response);
  }

  // Same reason: a decrypted direct message is a result, and it does not belong in a log the
  // page can read. Whether it succeeded is enough to debug against.
  console.log(
    '%c[nos2x-fox:%c' + message.data.id + '%c]%c ' +
      (message.data.response.error ? 'failed' : 'ok'),
    'background-color:#f1b912;font-weight:bold;color:white',
    'background-color:#f1b912;font-weight:bold;color:#a92727',
    'background-color:#f1b912;color:white;font-weight:bold',
    'color:auto'
  );

  delete window.nostr._requests[message.data.id];
});
