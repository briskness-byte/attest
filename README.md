# Attest

A Nostr signer for Firefox. It holds your key so a website never has to, and it asks before it
signs anything on your behalf.

**This is a fork of [nos2x-fox](https://github.com/diegogurpegui/nos2x-fox) by Diego H. Gurpegui,**
which is itself a Firefox port of [nos2x](https://github.com/fiatjaf/nos2x) by fiatjaf. Almost all
of the code here is theirs. Like the original, this is released into the public domain under the
Unlicense.

## What is different from nos2x-fox

- **A global on/off switch.** One toggle that stops the signer answering any site, without
  uninstalling it or deleting per-site permissions.
- **Rejections that expire.** Refusing a site can be remembered for a while rather than forever or
  not at all, and an earlier refusal can be found and undone.
- **Authorize every capability for a site in one click**, instead of answering the same prompt
  once per capability.
- **Create your first key from the popup**, so a new user is not sent to the options page before
  anything works.
- **A page can no longer ask the extension for the PIN.** The bridge between a web page and the
  extension forwarded any message type it was given, and the background answered `getCachedPin`
  above every permission check, so any website could read the PIN that decrypts the private key.
  It now forwards an allow-list of the seven calls a page has any business making, and the
  background separately refuses the privileged ones to anything running in a tab.
- **No `'unsafe-eval'`.** The manifest allowed it while `eval` and `new Function` appear zero times
  in the shipped code.
- **Nothing is logged to the page console but the fact that a call happened.** It used to log the
  full event being signed and the plaintext coming back out of `nip04.decrypt`.
- **React's production build actually ships**, which halved four bundles.

The first four were offered upstream as pull requests. The security fix was reported privately.

## Signing through a remote signer (NIP-46)

A profile can hold a connection to a remote signer instead of a key: a bunker such as nsec.app,
Amber or `nak bunker`, where the key lives somewhere else and Attest only asks it to sign. Sites
see no difference; they keep talking NIP-07 to Attest.

- **Connecting.** Options → Profile → New → "Or sign through a remote signer", paste the
  `bunker://` address and press Connect. Attest shows whose key the remote signer signs with, and
  stores nothing until you choose "Use this remote signer". Only `bunker://` addresses are
  accepted, with `wss://` relays (`ws://` only to this machine).
- **Permissions stay local.** A site has to be allowed in Attest first, exactly as with a key of
  your own; only then is the request passed on.
- **Nothing connects until it is needed.** Not at browser start, and not when the profile becomes
  the active one: only on the first request that has to reach the remote signer, so relays do not
  learn when this browser is online on days nothing is signed.
- **What comes back is checked.** A signed event is used only if it is exactly the event that was
  asked for, signed by the profile's key.
- **Every request ends.** After 30 seconds without an answer it fails. A site that fires many
  requests at once is queued, eight at a time per site.

When a request fails, the page gets one of these errors, prefixed with `attest: `. Apps can match
on them; the wording does not change.

| Error | Meaning |
|---|---|
| `the remote signer did not answer in time` | no answer within 30 seconds |
| `the remote signer refused` | the remote signer said no; its reason may follow a colon |
| `approve the login in your remote signer, then try again` | the remote signer wants a login first |
| `too many requests are waiting for the remote signer, try again in a moment` | the queue is full |
| `could not reach the remote signer's relays` | the request could not be sent, even after reconnecting |

The text arrives through the page, which can forge it, so show your own message for each one rather
than the text itself.

## Building

```sh
yarn install
yarn run build      # into dist/
yarn run package    # a .xpi into var/releases/
```

There is no minifier and no obfuscation: the file that ships is the file in this repository.

## Install

Install it from [addons.mozilla.org](https://addons.mozilla.org/en-US/firefox/addon/attest/),
which keeps it updated, or load `dist/` as a temporary add-on from `about:debugging`.

## Licence

The Unlicense, as inherited. See `LICENSE`.
