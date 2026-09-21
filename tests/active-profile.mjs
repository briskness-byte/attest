#!/usr/bin/env node
// Which profile a screen opens on, and what switching profile actually changes.
//
//   node tests/active-profile.mjs
//
// The settings page opened on whichever profile was stored first, and its dropdown changed only
// what that page drew. With more than one key the page therefore described the relays, permissions
// and key of one profile while websites were signed for by another, and switching there looked
// like it had taken effect until the next signature came back under the old key.
//
// These cases pin both halves: what a page opens on, and that a switch moves the key material
// along with the pointer — into storage.local, which is what makes it survive a restart.
//
// A stub suite: storage is the real storage layer, the browser underneath it is not.
import { getPublicKey } from 'nostr-tools';
import { rm } from 'node:fs/promises';

import { loadModule } from './load-background.mjs';
import { reporter } from './harness.mjs';
import stub, { reset } from './browser-stub.mjs';

const { ok, state } = reporter();
process.on('unhandledRejection', error => {
  ok(`a promise was rejected with nobody listening (${error?.message ?? error})`, false);
});

const SECRET_A = '5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a';
const SECRET_B = '9f1e4a2b7c8d0e3f6a1b5c9d2e4f7a0b3c6d9e2f5a8b1c4d7e0f3a6b9c2d5e8f';
const KEY_A = getPublicKey(Buffer.from(SECRET_A, 'hex'));
const KEY_B = getPublicKey(Buffer.from(SECRET_B, 'hex'));
const KEY_GONE = getPublicKey(Buffer.from('11'.repeat(32), 'hex'));

// Encrypted keys are recognised by their leading '{' — the envelope protection writes.
const SEALED_A = '{"v":1,"ct":"aaaa","iv":"bbbb"}';
const SEALED_B = '{"v":1,"ct":"cccc","iv":"dddd"}';

const local = async key => (await stub.storage.local.get(key))[key];
const session = async key => (await stub.storage.session.get(key))[key];

const { exports: common, outdir: commonDir } = await loadModule('src/common.ts');
const { exports: Storage, outdir: storageDir } = await loadModule('src/storage.ts');

// ------------------------------------------------------- 1. which profile a screen opens on

console.log('\nWhich profile a settings page opens on');
{
  const profiles = { [KEY_A]: { privateKey: SECRET_A }, [KEY_B]: { privateKey: SECRET_B } };

  ok('the active profile, when it is the second one stored',
    common.profileToOpen(profiles, KEY_B) === KEY_B);
  ok('the active profile, when it is also the first one stored',
    common.profileToOpen(profiles, KEY_A) === KEY_A);
  ok('the first profile when none is active yet',
    common.profileToOpen(profiles, null) === KEY_A);
  ok('the first profile when the active one has been deleted',
    common.profileToOpen(profiles, KEY_GONE) === KEY_A);
  ok('nothing selected when there are no profiles',
    common.profileToOpen({}, null) === '');
  ok('an active key that matches no profile selects nothing here either',
    common.profileToOpen({}, KEY_B) === '');
}

// ------------------------------------------------------- 2. switching, protection off

console.log('\nSwitching profile with protection off');
{
  reset();
  // Seeded as if profile A were already the active one: the key in the slot is the thing that has
  // to move, and a test that starts with an empty slot cannot tell whether it did.
  await stub.storage.local.set({
    profiles: { [KEY_A]: { privateKey: SECRET_A }, [KEY_B]: { privateKey: SECRET_B } },
    active_public_key: KEY_A,
    private_key: SECRET_A
  });
  await Storage.switchActiveProfile(KEY_B, { privateKey: SECRET_B });

  ok('the stored active public key is the one switched to', await local('active_public_key') === KEY_B);
  ok('the private key in the active slot is that profile\'s', await local('private_key') === SECRET_B);

  const active = await Storage.getActiveProfile();
  ok('the active profile resolves to the one switched to', active?.privateKey === SECRET_B);

  // The bug this suite exists for would show as the pointer moving while the key stayed put.
  ok('no trace of the profile switched away from', await local('private_key') !== SECRET_A);
}

// ------------------------------------------------------- 3. it survives a restart

console.log('\nWhat a restart keeps');
{
  ok('the choice is in storage.local', await local('active_public_key') === KEY_B);
  ok('the choice is NOT in storage.session, which a restart empties',
    await session('active_public_key') === undefined);

  // A restart is this: session storage gone, local storage as it was, nothing else remembered.
  stub.storage.session.clear ? await stub.storage.session.clear() : null;
  const profiles = await Storage.readProfiles();
  ok('a page opening after the restart still opens on that profile',
    common.profileToOpen(profiles, await Storage.getActivePublicKey()) === KEY_B);
}

// ------------------------------------------------------- 4. switching, protection on

console.log('\nSwitching profile with protection on');
{
  reset();
  await stub.storage.local.set({
    pin_enabled: true,
    encrypted_private_key: SEALED_A,
    profiles: { [KEY_A]: { privateKey: SEALED_A }, [KEY_B]: { privateKey: SEALED_B } }
  });

  await Storage.switchActiveProfile(KEY_B, { privateKey: SEALED_B });
  ok('the pointer moves', await local('active_public_key') === KEY_B);
  ok('the encrypted key moves with it', await local('encrypted_private_key') === SEALED_B);
  ok('the previous profile\'s encrypted key is gone', await local('encrypted_private_key') !== SEALED_A);

  // A profile holding no encrypted key must not inherit the last one: signing should fail and say
  // so, rather than quietly sign under a key the user did not pick.
  await Storage.switchActiveProfile(KEY_A, { privateKey: '' });
  ok('switching to a profile with no key of its own clears the slot',
    await local('encrypted_private_key') === undefined);
  ok('and does not leave the previous profile\'s key behind',
    await local('encrypted_private_key') !== SEALED_B);

  ok('a plain-text key is never written while protection is on',
    await local('private_key') === undefined);
}

await rm(commonDir, { recursive: true, force: true });
await rm(storageDir, { recursive: true, force: true });

console.log(`\n${state.pass} passed, ${state.fail} failed`);
process.exit(state.fail ? 1 : 0);
