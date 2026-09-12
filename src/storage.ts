import browser from 'webextension-polyfill';
import { getPublicKey } from 'nostr-tools';

import {
  AuthorizationCondition,
  ConfigurationKeys,
  OpenPromptItem,
  PermissionConfig,
  PermissionDecision,
  ProfileConfig,
  ProfilesConfig,
  RelaysConfig,
  PermissionEntry,
  SecretKind
} from './types';
import {
  convertHexToUint8Array,
  isPrivateKeyEncrypted,
  derivePublicKeyFromPrivateKey,
  canDerivePublicKeyFromPrivateKey,
  migratePermissionKeys,
  messageOf,
  shouldRemoveStoredPermission,
  entriesOf,
  byLevel
} from './common';
import { encryptPrivateKey, decryptPrivateKey } from './pinEncryption';
import { clearStringReference } from './memoryUtils';

/**
 * Reads the active profile's plain-text private key from storage.
 * When PIN protection is enabled, the plain-text key is not stored and this returns an empty string.
 */
export async function readActivePrivateKey(): Promise<string> {
  const data = await browser.storage.local.get(ConfigurationKeys.PRIVATE_KEY);
  return data[ConfigurationKeys.PRIVATE_KEY] as string;
}

/**
 * Stores or removes the active profile's plain-text private key.
 * Also updates the stored active public key when a key is set.
 * @param privateKey - Hex private key, or empty string to clear the active profile
 * @throws Error when PIN protection is enabled and a non-empty key is provided
 */
export async function updateActivePrivateKey(privateKey: string) {
  // Critical: If PIN protection is enabled, reject plain-text storage
  const pinEnabled = await isPinEnabled();
  if (pinEnabled && privateKey) {
    throw new Error(
      'Cannot store plain-text private key when PIN protection is enabled. Use setEncryptedPrivateKey() instead.'
    );
  }

  if (privateKey == null || privateKey == '') {
    console.log('Removing active profile (private key)');
    await removeActivePublicKey();
  } else {
    console.log('Storing new active pubKey');
    // Always store active public key for consistent profile lookup
    const publicKey = derivePublicKeyFromPrivateKey(privateKey);
    await setActivePublicKey(publicKey);
  }

  return browser.storage.local.set({
    [ConfigurationKeys.PRIVATE_KEY]: privateKey
  });
}

//#region PIN Protection >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

/**
 * Checks if PIN protection is enabled
 */
export async function isPinEnabled(): Promise<boolean> {
  const data = await browser.storage.local.get(ConfigurationKeys.PIN_ENABLED);
  return (data[ConfigurationKeys.PIN_ENABLED] as boolean) ?? false;
}

/**
 * Sets PIN protection enabled/disabled state
 */
export async function setPinEnabled(enabled: boolean): Promise<void> {
  await browser.storage.local.set({
    [ConfigurationKeys.PIN_ENABLED]: enabled
  });
}

/** What the keys are protected with. Absent means a PIN: the only kind there was before 1.25.0. */
export async function getPinKind(): Promise<SecretKind> {
  const data = await browser.storage.local.get(ConfigurationKeys.PIN_KIND);
  return data[ConfigurationKeys.PIN_KIND] === 'passphrase' ? 'passphrase' : 'pin';
}

export async function setPinKind(kind: SecretKind): Promise<void> {
  await browser.storage.local.set({ [ConfigurationKeys.PIN_KIND]: kind });
}

/**
 * Gets the PIN cache duration in milliseconds
 * Default: 10 seconds (10000 ms)
 */
/**
 * Which theme to draw: follow the operating system, or override it.
 *
 * 'system' is the default because the browser already knows the answer and the user already told
 * it once. An explicit choice exists because that answer is sometimes wrong — a dark desktop with
 * one light window in it, or the other way round.
 */
export async function getTheme(): Promise<'system' | 'light' | 'dark'> {
  const data = await browser.storage.local.get(ConfigurationKeys.THEME);
  const v = data[ConfigurationKeys.THEME];
  return v === 'light' || v === 'dark' ? v : 'system';
}

export async function setTheme(theme: 'system' | 'light' | 'dark'): Promise<void> {
  await browser.storage.local.set({ [ConfigurationKeys.THEME]: theme });
}

export async function getPinCacheDuration(): Promise<number> {
  const data = await browser.storage.local.get(ConfigurationKeys.PIN_CACHE_DURATION);
  return (data[ConfigurationKeys.PIN_CACHE_DURATION] as number) ?? 10 * 1000; // Default: 10 seconds
}

/**
 * Sets the PIN cache duration in milliseconds
 */
export async function setPinCacheDuration(durationMs: number): Promise<void> {
  await browser.storage.local.set({
    [ConfigurationKeys.PIN_CACHE_DURATION]: durationMs
  });
}

/**
 * Gets the URL template for handling nostr: links. Empty string means disabled.
 */
export async function getNostrLinkHandlerUrlTemplate(): Promise<string> {
  const data = await browser.storage.local.get(ConfigurationKeys.NOSTR_LINK_HANDLER_URL);
  return (data[ConfigurationKeys.NOSTR_LINK_HANDLER_URL] as string) ?? '';
}

/**
 * Sets the URL template for handling nostr: links. Pass an empty string to disable.
 */
export async function setNostrLinkHandlerUrlTemplate(template: string): Promise<void> {
  await browser.storage.local.set({
    [ConfigurationKeys.NOSTR_LINK_HANDLER_URL]: template
  });
}

/**
 * Whether the signer answers websites at all. Defaults to enabled.
 */
export async function isSignerEnabled(): Promise<boolean> {
  const data = await browser.storage.local.get(ConfigurationKeys.SIGNER_ENABLED);
  return (data[ConfigurationKeys.SIGNER_ENABLED] as boolean) ?? true;
}

/**
 * Turns the signer on or off for every website at once. Stored keys and permissions are left untouched.
 */
export async function setSignerEnabled(enabled: boolean): Promise<void> {
  await browser.storage.local.set({
    [ConfigurationKeys.SIGNER_ENABLED]: enabled
  });
}

/**
 * Whether other installed extensions may ask this signer at all. Off unless turned on in the
 * options: few people use it, and until 1.27.0 it was an open door nobody could close.
 */
export async function isExternalCallersAllowed(): Promise<boolean> {
  const data = await browser.storage.local.get(ConfigurationKeys.EXTERNAL_CALLERS_ALLOWED);
  return data[ConfigurationKeys.EXTERNAL_CALLERS_ALLOWED] === true;
}

export async function setExternalCallersAllowed(allowed: boolean): Promise<void> {
  await browser.storage.local.set({
    [ConfigurationKeys.EXTERNAL_CALLERS_ALLOWED]: allowed
  });
}

/**
 * Whether a key was generated that the user has not confirmed backing up yet.
 */
export async function isKeyBackupPending(): Promise<boolean> {
  const data = await browser.storage.local.get(ConfigurationKeys.KEY_BACKUP_PENDING);
  return (data[ConfigurationKeys.KEY_BACKUP_PENDING] as boolean) ?? false;
}

export async function setKeyBackupPending(pending: boolean): Promise<void> {
  await browser.storage.local.set({
    [ConfigurationKeys.KEY_BACKUP_PENDING]: pending
  });
}

/**
 * Stores a freshly generated key as the first profile and flags it as not backed up yet.
 * Only valid while no key is stored, which also means PIN protection cannot be on.
 * @param privateKey - Hex private key
 */
export async function createFirstProfile(privateKey: string): Promise<void> {
  await updateActivePrivateKey(privateKey);
  // materializes the profile entry for the new key
  await readProfiles();
  await setKeyBackupPending(true);
}

/**
 * Gets the encrypted private key from storage
 */
export async function getEncryptedPrivateKey(): Promise<string | null> {
  const data = await browser.storage.local.get(ConfigurationKeys.ENCRYPTED_PRIVATE_KEY);
  return (data[ConfigurationKeys.ENCRYPTED_PRIVATE_KEY] as string) ?? null;
}

/**
 * Sets the encrypted private key in storage
 */
export async function setEncryptedPrivateKey(encryptedKey: string): Promise<void> {
  await browser.storage.local.set({
    [ConfigurationKeys.ENCRYPTED_PRIVATE_KEY]: encryptedKey
  });
}

/**
 * Enables PIN protection by encrypting all private keys
 * @param pin - The PIN to use for encryption
 */
export async function enablePinProtection(pin: string): Promise<void> {
  // Get all profiles
  const profiles = await readProfiles();
  const activePrivateKey = await readActivePrivateKey();

  if (!activePrivateKey) {
    throw new Error('No active private key to encrypt');
  }

  // Get active public key before encrypting (should already be stored, but ensure it)
  const activePublicKey = derivePublicKeyFromPrivateKey(activePrivateKey);
  await setActivePublicKey(activePublicKey);

  // Encrypt active private key
  const encryptedActiveKey = await encryptPrivateKey(pin, activePrivateKey);
  await setEncryptedPrivateKey(encryptedActiveKey);

  // Encrypt all profile private keys
  for (const pubKey in profiles) {
    const profile = profiles[pubKey];
    if (profile.privateKey) {
      profile.privateKey = await encryptPrivateKey(pin, profile.privateKey);
    }
  }
  await updateProfiles(profiles);

  // Clear plain-text private key
  await browser.storage.local.remove(ConfigurationKeys.PRIVATE_KEY);

  // Enable PIN protection
  await setPinEnabled(true);
}

/**
 * Enables PIN protection with an already encrypted key (used by background script)
 * @param pin - The PIN used for encryption
 * @param encryptedKey - The already encrypted private key
 */
export async function enablePinProtectionWithEncryptedKey(
  pin: string,
  encryptedKey: string
): Promise<void> {
  // Get all profiles
  const profiles = await readProfiles();
  const currentPrivateKey = await readActivePrivateKey();

  if (!currentPrivateKey) {
    throw new Error('No active private key found');
  }

  // Get active public key before encrypting (should already be stored, but ensure it)
  const activePublicKey = derivePublicKeyFromPrivateKey(currentPrivateKey);
  await setActivePublicKey(activePublicKey);

  // Store encrypted key
  await setEncryptedPrivateKey(encryptedKey);

  // Encrypt all profile private keys
  for (const pubKey in profiles) {
    const profile = profiles[pubKey];
    if (profile.privateKey && !isPrivateKeyEncrypted(profile.privateKey)) {
      // Encrypt profile private key
      profile.privateKey = await encryptPrivateKey(pin, profile.privateKey);
    }
  }
  await updateProfiles(profiles);

  // Clear plain-text private key
  await browser.storage.local.remove(ConfigurationKeys.PRIVATE_KEY);

  // Enable PIN protection
  await setPinEnabled(true);
}

/**
 * Gets the active public key (used when PIN protection is enabled)
 */
export async function getActivePublicKey(): Promise<string | null> {
  const data = await browser.storage.local.get(ConfigurationKeys.ACTIVE_PUBLIC_KEY);
  return (data[ConfigurationKeys.ACTIVE_PUBLIC_KEY] as string) ?? null;
}

/**
 * Sets the active public key (used when PIN protection is enabled)
 */
export async function setActivePublicKey(publicKey: string): Promise<void> {
  await browser.storage.local.set({
    [ConfigurationKeys.ACTIVE_PUBLIC_KEY]: publicKey
  });
}

/**
 * Removes the active public key
 */
export async function removeActivePublicKey(): Promise<void> {
  await browser.storage.local.remove(ConfigurationKeys.ACTIVE_PUBLIC_KEY);
}

/**
 * Disables PIN protection by decrypting all private keys
 * @param pin - The PIN to use for decryption
 */
export async function disablePinProtection(pin: string): Promise<void> {
  const encryptedKey = await getEncryptedPrivateKey();
  if (!encryptedKey) {
    throw new Error('No encrypted private key found');
  }

  // Decrypt active private key
  let decryptedActiveKey = await decryptPrivateKey(pin, encryptedKey);

  try {
    // Decrypt all profile private keys
    const profiles = await readProfiles();
    for (const pubKey in profiles) {
      const profile = profiles[pubKey];
      if (profile.privateKey) {
        try {
          profile.privateKey = await decryptPrivateKey(pin, profile.privateKey);
        } catch (error) {
          console.error(`Failed to decrypt profile ${pubKey}:`, error);
          throw new Error(`Failed to decrypt profile private key: ${messageOf(error)}`);
        }
      }
    }
    await updateProfiles(profiles);

    // Clear encrypted private key
    await browser.storage.local.remove(ConfigurationKeys.ENCRYPTED_PRIVATE_KEY);

    // Disable PIN protection BEFORE updating private key to allow plain-text storage
    await setPinEnabled(false);
    await browser.storage.local.remove(ConfigurationKeys.PIN_KIND);

    // Update active private key (this will also update active public key)
    // This must happen after disabling PIN protection to avoid the error
    await updateActivePrivateKey(decryptedActiveKey);
  } finally {
    // Clear decrypted active key reference from memory
    // Note: Strings are immutable, but we null the reference to minimize exposure
    decryptedActiveKey = clearStringReference(decryptedActiveKey) as any;
  }
}

/**
 * Gets the decrypted private key for a specific profile
 * This is used internally when PIN protection is enabled
 * @param pin - The PIN to decrypt with
 * @param publicKey - The public key of the profile (optional, defaults to active)
 */
export async function getDecryptedProfilePrivateKey(
  pin: string,
  publicKey?: string
): Promise<string> {
  const pinEnabled = await isPinEnabled();
  if (!pinEnabled) {
    // PIN not enabled, return plain key
    if (publicKey) {
      const profile = await getProfile(publicKey);
      return profile.privateKey;
    } else {
      return await readActivePrivateKey();
    }
  }

  // PIN enabled, decrypt
  if (publicKey) {
    const profile = await getProfile(publicKey);
    if (!profile.privateKey) {
      throw new Error('Profile private key not found');
    }
    return await decryptPrivateKey(pin, profile.privateKey);
  } else {
    const encryptedKey = await getEncryptedPrivateKey();
    if (!encryptedKey) {
      throw new Error('Encrypted private key not found');
    }
    return await decryptPrivateKey(pin, encryptedKey);
  }
}

//#endregion PIN Protection <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

/**
 * Reads the relay list configured on the active profile.
 */
export async function readActiveRelays(): Promise<RelaysConfig> {
  const activeProfile = await getActiveProfile();
  return activeProfile.relays || {};
}
/**
 * Updates the relay list for a profile.
 * @param profilePublicKey - Public key identifying the profile
 * @param newRelays - New relay configuration, or falsy to skip the update
 * @returns Updated profiles config, or undefined if the profile was not found
 */
export async function updateRelays(
  profilePublicKey: string,
  newRelays: RelaysConfig | undefined
): Promise<ProfilesConfig | undefined> {
  if (newRelays) {
    const profile = await getProfile(profilePublicKey);
    if (!profile) {
      console.warn(`There is no profile with the key '${profilePublicKey}'`);
      return;
    }
    profile.relays = newRelays;
    return updateProfile(profile, profilePublicKey);
  }
}

/**
 * Reads permissions for the active profile, dropping every decision that has run out, and persists
 * the result when anything was dropped. Each site's decisions come back keyed by level, whatever
 * shape they were stored in.
 */
export async function readActivePermissions(): Promise<PermissionConfig> {
  const activeProfile = await getActiveProfile();

  const stored = activeProfile.permissions;
  // if no permissions defined, return empty
  if (!stored) {
    return {};
  }

  // One decision can run out while another on the same site stands, so this goes entry by entry.
  const permissions: PermissionConfig = {};
  let needsUpdate = false;
  const nowSeconds = Math.round(Date.now() / 1000);
  for (const host in stored) {
    const entries = entriesOf(stored[host]);
    const live = entries.filter(
      e => !shouldRemoveStoredPermission(e.condition, e.created_at, nowSeconds, e.duration_seconds)
    );
    if (live.length !== entries.length) needsUpdate = true;
    if (live.length) permissions[host] = byLevel(live);
  }
  if (needsUpdate) {
    // Create a new profile object with only the permissions updated
    // Preserve the private key as-is (encrypted if PIN enabled)
    const updatedProfile: ProfileConfig = {
      ...activeProfile,
      permissions
    };
    const activePublicKey = await getActivePublicKey();
    if (!activePublicKey) {
      throw new Error('Cannot update profile: active public key not found');
    }
    await updateProfile(updatedProfile, activePublicKey);
  }

  return permissions;
}
/**
 * Remembers a decision about a site on the active profile — one per permission level.
 *
 * It used to be one per site, so a narrower answer replaced a broader one: "reject decrypting for
 * five minutes" wiped "sign forever", and five minutes later the site had nothing and asked for
 * everything again. A decision now replaces only the one at its own level. Allowing a level also
 * lifts any refusal at or below it, which would otherwise still win and leave the grant just given
 * doing nothing.
 * @param host - Origin host the permission applies to
 * @param condition - Authorization condition (e.g. always, expirable)
 * @param level - Permission level determining allowed capabilities
 * @param decision - Whether the conditions grant or refuse access
 * @param durationSeconds - TTL in seconds for custom expirable grants
 */
export async function addActivePermission(
  host: string,
  condition: string,
  level: number,
  decision: PermissionDecision = PermissionDecision.ALLOW,
  durationSeconds?: number
): Promise<ProfilesConfig> {
  const storedPermissions = await readActivePermissions();

  const entry: PermissionEntry = {
    condition,
    level,
    created_at: Math.round(Date.now() / 1000),
    decision
  };
  if (condition === AuthorizationCondition.EXPIRABLE_CUSTOM && durationSeconds != null) {
    entry.duration_seconds = durationSeconds;
  }

  let others = entriesOf(storedPermissions[host]).filter(e => e.level !== level);
  if (decision === PermissionDecision.ALLOW) {
    others = others.filter(e => !(e.decision === PermissionDecision.DENY && e.level <= level));
  }
  storedPermissions[host] = byLevel([...others, entry]);

  // update the active profile
  const profile = await getActiveProfile();
  profile.permissions = storedPermissions;
  const activePublicKey = await getActivePublicKey();
  if (!activePublicKey) {
    throw new Error('Cannot update profile: active public key not found');
  }
  return updateProfile(profile, activePublicKey);
}
/**
 * Removes a site's remembered decisions from a profile: the one at `level`, or all of them.
 * @param profilePublicKey - Public key identifying the profile
 * @param host - Origin host whose permission should be removed
 * @param level - Only the decision at this level; all of the site's when absent
 */
export async function removePermissions(
  profilePublicKey: string,
  host: string,
  level?: number
): Promise<ProfilesConfig> {
  const profile = await getProfile(profilePublicKey);
  let permissions = profile.permissions;
  if (permissions && permissions[host]) {
    const rest = level == null ? [] : entriesOf(permissions[host]).filter(e => e.level !== level);
    if (rest.length) permissions[host] = byLevel(rest);
    else delete permissions[host];
  }
  // update the profile
  profile.permissions = permissions;
  return updateProfile(profile, profilePublicKey);
}

/**
 * Moves every stored permission from its bare host to an origin. Runs once: the flag it leaves
 * behind makes every later call a no-op, and it is idempotent besides.
 *
 * Before 1.25.0 permissions were keyed on `location.host`, which carries no scheme, so a grant made
 * on https://example.com was honoured on http://example.com — and anybody able to put a user on the
 * plain-http version inherited it, signing and decrypting included.
 */
export async function migratePermissionsToOrigins(): Promise<void> {
  const data = await browser.storage.local.get([
    ConfigurationKeys.PROFILES,
    ConfigurationKeys.PERMISSIONS_KEYED_BY
  ]);
  if (data[ConfigurationKeys.PERMISSIONS_KEYED_BY] === 'origin') return;

  const profiles = data[ConfigurationKeys.PROFILES] as ProfilesConfig | undefined;
  for (const profile of Object.values(profiles ?? {})) {
    if (profile.permissions) profile.permissions = migratePermissionKeys(profile.permissions);
  }
  // One write, profiles and flag together, so a browser closed halfway cannot leave one without
  // the other.
  await browser.storage.local.set({
    ...(profiles ? { [ConfigurationKeys.PROFILES]: profiles } : {}),
    [ConfigurationKeys.PERMISSIONS_KEYED_BY]: 'origin'
  });
}

//#region Profiles >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

/**
 * Reads all stored profiles.
 * When no profiles exist and PIN is disabled, initializes one from the active private key if present.
 */
export async function readProfiles(): Promise<ProfilesConfig> {
  const { profiles = {} } = (await browser.storage.local.get(ConfigurationKeys.PROFILES)) as {
    [ConfigurationKeys.PROFILES]: ProfilesConfig;
  };

  const pubKeys = Object.keys(profiles);
  // if there are no profiles, check if there's an active profile
  if (pubKeys.length == 0) {
    const pinEnabled = await isPinEnabled();

    if (pinEnabled) {
      // With PIN enabled, we can't decrypt without PIN, so skip initialization
      // The profile will be created when needed after PIN is entered
      return profiles;
    }

    // Without PIN, try to initialize from private key
    const privateKey = await readActivePrivateKey();
    if (privateKey) {
      // there is a private key, so I need to initialize the profiles
      const pubKey = derivePublicKeyFromPrivateKey(privateKey);
      const profile: ProfileConfig = {
        privateKey,
        relays: {},
        permissions: {}
      };

      profiles[pubKey] = profile;
      // save it (this will also store active public key via updateActivePrivateKey)
      await updateProfiles(profiles);
    }
  }

  return profiles;
}
/**
 * Returns a single profile by public key.
 * @param publicKey - Hex public key of the profile
 */
export async function getProfile(publicKey: string): Promise<ProfileConfig> {
  const profiles = await readProfiles();
  return profiles[publicKey];
}
/**
 * Persists the full profiles map.
 * When there is exactly one profile and no active private key, sets it as the active profile.
 * @param profiles - Complete profiles configuration to store
 */
export async function updateProfiles(profiles: ProfilesConfig): Promise<ProfilesConfig> {
  await browser.storage.local.set({
    [ConfigurationKeys.PROFILES]: profiles
  });

  // if there's only one profile, then set it as the active one
  const activePrivateKey = await readActivePrivateKey();
  if (!activePrivateKey && Object.keys(profiles).length == 1) {
    const profilePubKey = Object.keys(profiles)[0];
    const profile = profiles[profilePubKey];
    const pinEnabled = await isPinEnabled();

    // Always store active public key first
    await setActivePublicKey(profilePubKey);

    // Then update private key based on PIN status
    if (pinEnabled) {
      // When PIN enabled, store encrypted private key if available
      if (profile.privateKey && isPrivateKeyEncrypted(profile.privateKey)) {
        await setEncryptedPrivateKey(profile.privateKey);
      }
    } else {
      // When PIN disabled, store private key
      await updateActivePrivateKey(profile.privateKey);
    }
  }

  return profiles;
}
/**
 * Adds a new profile to storage.
 * When it is the first profile, sets it as the active profile.
 * @param profile - Profile data to add
 * @param publicKey - Public key to use; required when the private key is encrypted
 * @throws Error when PIN protection is enabled and the private key is not encrypted
 */
export async function addProfile(
  profile: ProfileConfig,
  publicKey?: string
): Promise<ProfilesConfig> {
  const pinEnabled = await isPinEnabled();

  // If PIN is enabled, ensure private key is encrypted
  if (pinEnabled && profile.privateKey) {
    // Check if it's already encrypted (starts with {)
    if (!isPrivateKeyEncrypted(profile.privateKey)) {
      throw new Error(
        'Cannot add profile with plain-text private key when PIN protection is enabled'
      );
    }
  }

  const profiles = await readProfiles();

  // Derive public key: use provided publicKey, or derive from private key if not encrypted
  let profilePublicKey: string;
  if (publicKey) {
    profilePublicKey = publicKey;
  } else if (!canDerivePublicKeyFromPrivateKey(profile.privateKey, pinEnabled)) {
    // When PIN is enabled and private key is encrypted, we can't derive public key
    throw new Error('Public key must be provided when adding a profile with encrypted private key');
  } else {
    // Derive public key from plain-text private key
    profilePublicKey = derivePublicKeyFromPrivateKey(profile.privateKey);
  }

  profiles[profilePublicKey] = profile;

  await browser.storage.local.set({
    [ConfigurationKeys.PROFILES]: profiles
  });

  // if it's the first profile to be added, then set it as the active one
  const activePrivateKey = await readActivePrivateKey();
  if (!activePrivateKey && Object.keys(profiles).length == 1) {
    const profilePubKey = Object.keys(profiles)[0];

    // Always store active public key first
    await setActivePublicKey(profilePubKey);

    // Then update private key based on PIN status
    if (pinEnabled) {
      // If PIN enabled, store encrypted private key if available
      if (profile.privateKey && isPrivateKeyEncrypted(profile.privateKey)) {
        await setEncryptedPrivateKey(profile.privateKey);
      }
    } else {
      // If PIN disabled, store private key (which also ensures public key is stored)
      await updateActivePrivateKey(profile.privateKey);
    }
  }

  return profiles;
}
/**
 * Updates an existing profile in storage.
 * @param profile - Updated profile data
 * @param publicKey - Public key of the profile to update; required when multiple encrypted profiles exist
 * @throws Error when PIN protection is enabled and a plain-text private key is provided without a matching encrypted key in storage
 */
export async function updateProfile(
  profile: ProfileConfig,
  publicKey?: string
): Promise<ProfilesConfig> {
  const pinEnabled = await isPinEnabled();

  // If PIN is enabled, ensure private key is encrypted
  if (pinEnabled && profile.privateKey) {
    // Check if it's already encrypted (starts with {)
    if (!isPrivateKeyEncrypted(profile.privateKey)) {
      // If updating permissions/relays only, preserve the existing encrypted key from storage
      const existingProfiles = await readProfiles();
      let existingProfile: ProfileConfig | undefined;

      if (publicKey) {
        existingProfile = existingProfiles[publicKey];
      } else {
        // Try to find existing profile by matching other fields
        const activePublicKey = await getActivePublicKey();
        if (activePublicKey) {
          existingProfile = existingProfiles[activePublicKey];
        }
      }

      // If we found an existing profile with encrypted key, use it instead
      if (existingProfile?.privateKey && isPrivateKeyEncrypted(existingProfile.privateKey)) {
        profile.privateKey = existingProfile.privateKey;
      } else {
        throw new Error(
          'Cannot update profile with plain-text private key when PIN protection is enabled'
        );
      }
    }
  }

  const profiles = await readProfiles();

  // Determine which profile to update
  let profilePublicKey: string;
  if (publicKey) {
    profilePublicKey = publicKey;
  } else if (!canDerivePublicKeyFromPrivateKey(profile.privateKey, pinEnabled)) {
    // When PIN is enabled and private key is encrypted, try to find existing profile
    // by matching the encrypted private key (since we can't derive public key)
    const existingProfiles = Object.entries(profiles);
    const matchingProfile = existingProfiles.find(([_, p]) => p.privateKey === profile.privateKey);

    if (matchingProfile) {
      profilePublicKey = matchingProfile[0];
    } else if (existingProfiles.length === 1) {
      // If only one profile exists, update that one
      profilePublicKey = existingProfiles[0][0];
    } else {
      throw new Error(
        'Public key must be provided when updating a profile with encrypted private key and multiple profiles exist'
      );
    }
  } else {
    // Derive public key from plain-text private key
    profilePublicKey = derivePublicKeyFromPrivateKey(profile.privateKey);
  }

  profiles[profilePublicKey] = profile;

  await browser.storage.local.set({
    [ConfigurationKeys.PROFILES]: profiles
  });

  return profiles;
}
/**
 * Sets or clears a profile's name, and changes nothing else.
 *
 * Reads the profile here rather than taking one from the caller. The options page used to pass in
 * the copy it loaded when it opened, and writing that back undid everything decided since: a site
 * revoked on that page was answered again the moment the profile was renamed.
 * @param publicKey - Public key of the profile to rename
 * @param name - The new name, or undefined to remove it
 * @returns The updated profiles configuration
 */
export async function renameProfile(
  publicKey: string,
  name: string | undefined
): Promise<ProfilesConfig> {
  const profiles = await readProfiles();
  const profile = profiles[publicKey];
  if (!profile) {
    throw new Error(`There is no profile with the key '${publicKey}'`);
  }
  if (name) profile.name = name;
  else delete profile.name;

  await browser.storage.local.set({
    [ConfigurationKeys.PROFILES]: profiles
  });
  return profiles;
}
/**
 * Deletes a profile and switches the active profile if the deleted one was active.
 * @param profilePublicKey - Public key of the profile to delete
 * @returns The updated profiles configuration
 */
export async function deleteProfile(profilePublicKey: string): Promise<ProfilesConfig> {
  console.debug(`Deleting profile: ${profilePublicKey}...`);
  const profiles = await readProfiles();

  // Determine if the deleted profile was the active one
  // Always use active public key for comparison (it's always stored now)
  const activePublicKey = await getActivePublicKey();
  const isActiveProfile = activePublicKey === profilePublicKey;

  // delete from storage
  delete profiles[profilePublicKey];
  await browser.storage.local.set({
    [ConfigurationKeys.PROFILES]: profiles
  });

  // now change the active, if it was removed
  if (isActiveProfile) {
    const pinEnabled = await isPinEnabled();

    if (Object.keys(profiles).length > 0) {
      // Set the first remaining profile as active
      const newActivePublicKey = Object.keys(profiles)[0];
      const newActiveProfile = profiles[newActivePublicKey];

      // Always update active public key first
      await setActivePublicKey(newActivePublicKey);

      // Then update private key based on PIN status
      if (pinEnabled) {
        // When PIN enabled, update encrypted private key
        if (newActiveProfile.privateKey && isPrivateKeyEncrypted(newActiveProfile.privateKey)) {
          await setEncryptedPrivateKey(newActiveProfile.privateKey);
        } else {
          // No encrypted key in profile, clear encrypted key
          await browser.storage.local.remove(ConfigurationKeys.ENCRYPTED_PRIVATE_KEY);
        }
      } else {
        // When PIN disabled, update active private key
        await updateActivePrivateKey(newActiveProfile.privateKey || '');
      }
    } else {
      // No profiles left, clear active profile
      await removeActivePublicKey();
      if (pinEnabled) {
        await browser.storage.local.remove(ConfigurationKeys.ENCRYPTED_PRIVATE_KEY);
      } else {
        await updateActivePrivateKey('');
      }
    }
  }

  return profiles;
}
/**
 * Returns the currently active profile.
 * Resolves the active public key from storage, with fallbacks for legacy data.
 * @throws Error when the active profile cannot be determined or is missing from storage
 */
export async function getActiveProfile(): Promise<ProfileConfig> {
  // Always use stored active public key for consistent behavior
  let publicKey = await getActivePublicKey();

  if (!publicKey) {
    // Fallback: derive from private key if available (for migration)
    // Note: This fallback only works when PIN is disabled, as we can't derive from encrypted keys
    const privateKey = await readActivePrivateKey();
    if (privateKey) {
      publicKey = derivePublicKeyFromPrivateKey(privateKey);
      // Store it for future use
      await setActivePublicKey(publicKey);
    }

    // If still no public key, try single profile fallback
    if (!publicKey) {
      const profiles = await readProfiles();
      const profileKeys = Object.keys(profiles);
      if (profileKeys.length === 1) {
        publicKey = profileKeys[0];
        await setActivePublicKey(publicKey);
      } else {
        throw new Error('Cannot determine active profile.');
      }
    }
  }

  const profiles = await readProfiles();
  const profile = profiles[publicKey];
  if (!profile) {
    throw new Error(`Profile not found for public key: ${publicKey}`);
  }
  return profile;
}
//#endregion Profiles <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

/**
 * Where the prompt queue lives: session storage, which is held in memory and never written to disk.
 * The queue carries whole requests — the event about to be signed, the plaintext of a message about
 * to be encrypted — and in storage.local every one of them went into the profile on disk. Local
 * storage only where session storage does not exist.
 */
function promptQueueArea() {
  return browser.storage.session ?? browser.storage.local;
}

/**
 * Reads the queue of open signing prompts from storage.
 */
export async function readOpenPrompts(): Promise<OpenPromptItem[]> {
  const openPromptsData = await promptQueueArea().get(ConfigurationKeys.OPEN_PROMPTS);
  // parse from JSON string
  const openPromptStr = (openPromptsData[ConfigurationKeys.OPEN_PROMPTS] ?? '[]') as string;
  return JSON.parse(openPromptStr) as OpenPromptItem[];
}

/**
 * Persists the queue of open signing prompts.
 * @param openPrompts - Prompt items to store
 */
export async function updateOpenPrompts(openPrompts: OpenPromptItem[]) {
  // stringify to JSON to make the change listeners fire (Firefox bug?)
  const openPromptsStr = JSON.stringify(openPrompts);
  await promptQueueArea().set({
    [ConfigurationKeys.OPEN_PROMPTS]: openPromptsStr
  });

  return openPrompts;
}

/**
 * Registers a listener for changes to the open prompts queue.
 *
 * What storage listens with is a wrapper around `callback`, and that wrapper is what has to be
 * removed again, so it is handed back. Removing the callback itself took a different function:
 * nothing was ever removed, and every prompt page left one behind.
 *
 * @param callback - Called with the new prompt list when storage changes
 * @returns The listener to pass to {@link removeOpenPromptChangeListener}
 */
export function addOpenPromptChangeListener(callback: (newOpenPrompts: OpenPromptItem[]) => void) {
  const listener = (changes: Record<string, browser.Storage.StorageChange>) => {
    // only notify if there's a change with Open Prompts
    if (changes[ConfigurationKeys.OPEN_PROMPTS]) {
      const newValueStr = (changes[ConfigurationKeys.OPEN_PROMPTS].newValue ?? '[]') as string;
      callback(JSON.parse(newValueStr) as OpenPromptItem[]);
    }
  };
  browser.storage.onChanged.addListener(listener);
  return listener;
}
/**
 * Unregisters a listener previously added by {@link addOpenPromptChangeListener}.
 * @param listener - The listener function to remove
 */
export function removeOpenPromptChangeListener(
  listener: Parameters<typeof browser.storage.onChanged.removeListener>[0]
) {
  return browser.storage.onChanged.removeListener(listener);
}

/**
 * Clears all extension configuration from local storage.
 */
export async function empty(): Promise<void> {
  return await browser.storage.local.clear();
}

/** Removes legacy storage keys that are no longer used. */
async function clearUnused(): Promise<void> {
  const unused: string[] = [
    'relays', // no longer used
    'permissions' // no longer used
  ];
  // The prompt queue moved to session storage; a copy an older version left on disk goes.
  if (browser.storage.session) unused.push(ConfigurationKeys.OPEN_PROMPTS);
  return await browser.storage.local.remove(unused);
}

// clear unused
clearUnused()
  .then(() => console.debug('Storage cleared from unused.'))
  .catch(error => console.warn('There was a problem clearing the storage from unused.', error));
