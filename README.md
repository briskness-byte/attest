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

## Building

```sh
yarn install
yarn run build      # into dist/
yarn run package    # a .xpi into var/releases/
```

There is no minifier and no obfuscation: the file that ships is the file in this repository.

## Install

Load `dist/` as a temporary add-on from `about:debugging`, or install a signed build from
[addons.mozilla.org](https://addons.mozilla.org/).

## Licence

The Unlicense, as inherited. See `LICENSE`.
