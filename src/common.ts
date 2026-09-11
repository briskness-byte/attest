import browser from 'webextension-polyfill';
import { getPublicKey, nip19 } from 'nostr-tools';

import {
  AuthorizationCondition,
  PermissionConfig,
  PermissionDecision,
  PermissionEntry,
  ProfilesConfig,
  SecretKind
} from './types';

export const PERMISSIONS_REQUIRED = {
  getPublicKey: 1,
  getRelays: 5,
  signEvent: 10,
  'nip04.encrypt': 20,
  'nip04.decrypt': 20,
  'nip44.encrypt': 20,
  'nip44.decrypt': 20
};

/** The highest level any method asks for; granting it covers every capability. */
export const MAX_PERMISSION_LEVEL = Math.max(...Object.values(PERMISSIONS_REQUIRED));

const ORDERED_PERMISSIONS: [number, (keyof typeof PERMISSIONS_REQUIRED)[]][] = [
  [1, ['getPublicKey']],
  [5, ['getRelays']],
  [10, ['signEvent']],
  [20, ['nip04.encrypt', 'nip04.decrypt', 'nip44.encrypt', 'nip44.decrypt']]
];

const PERMISSION_NAMES: Record<keyof typeof PERMISSIONS_REQUIRED, string> = {
  getPublicKey: 'read your public key',
  getRelays: 'read your list of preferred relays',
  signEvent: 'sign events using your private key',
  'nip04.encrypt': 'encrypt messages to peers',
  'nip04.decrypt': 'decrypt messages from peers',
  'nip44.encrypt': 'encrypt messages to peers (nip44)',
  'nip44.decrypt': 'decrypt messages from peers (nip44)'
};

export type AuthorizationTimeUnit = 'minutes' | 'hours' | 'days';

const AUTHORIZATION_TIME_UNIT_SECONDS: Record<AuthorizationTimeUnit, number> = {
  minutes: 60,
  hours: 60 * 60,
  days: 24 * 60 * 60
};

/** Minimum custom grant length (one minute). */
export const MIN_CUSTOM_AUTHORIZATION_SECONDS = 60;

/** Maximum custom grant length (366 days). */
export const MAX_CUSTOM_AUTHORIZATION_SECONDS = 366 * 24 * 60 * 60;

/**
 * Returns a list of capabilities that are allowed based on the provided
 * permission level. The capabilities correspond to methods that a host
 * can perform if granted the specified permission.
 *
 * @param permission - The permission level to evaluate.
 * @returns An array of strings describing the allowed capabilities.
 *          If no capabilities are allowed, returns ['nothing'].
 */
export function getAllowedCapabilities(permission: number): string[] {
  let requestedMethods: string[] = [];
  for (let i = 0; i < ORDERED_PERMISSIONS.length; i++) {
    let [perm, methods] = ORDERED_PERMISSIONS[i];
    if (perm > permission) break;
    requestedMethods = requestedMethods.concat(methods);
  }

  if (requestedMethods.length === 0) return ['nothing'];

  return requestedMethods.map(method => PERMISSION_NAMES[method]);
}

/**
 * Given a permission level, returns a string describing the capabilities
 * that the host will have if the user grants this permission.
 *
 * The string will be in English, and will be one of the following:
 * - 'nothing' if the permission level is 0
 * - a single capability (e.g. 'read your public key')
 * - a comma-separated list of capabilities, with an 'and' between the
 *   last two (e.g. 'read your public key, read your list of preferred
 *   relays, and sign events using your private key')
 */
export function getPermissionsString(permission: number) {
  let capabilities = getAllowedCapabilities(permission);

  if (capabilities.length === 0) return 'none';
  if (capabilities.length === 1) return capabilities[0];

  return (
    (capabilities.slice(0, -1) as string[]).join(', ') +
    ' and ' +
    capabilities[capabilities.length - 1]
  );
}

/**
 * Whole-number amount × unit → seconds for a custom time-limited grant, or null if out of range / invalid.
 */
export function customAuthorizationDurationSeconds(
  amount: number,
  unit: AuthorizationTimeUnit
): number | null {
  if (!Number.isFinite(amount) || amount <= 0 || !Number.isInteger(amount)) {
    return null;
  }
  const unitSeconds = AUTHORIZATION_TIME_UNIT_SECONDS[unit];
  const totalSeconds = amount * unitSeconds;
  if (
    totalSeconds < MIN_CUSTOM_AUTHORIZATION_SECONDS ||
    totalSeconds > MAX_CUSTOM_AUTHORIZATION_SECONDS
  ) {
    return null;
  }
  return totalSeconds;
}

/** TTL in seconds for fixed expiring conditions; null if not a fixed expiring kind. */
export function fixedExpiringPermissionTtlSeconds(condition: string): number | null {
  switch (condition) {
    case AuthorizationCondition.EXPIRABLE_5M:
      return 5 * 60;
    case AuthorizationCondition.EXPIRABLE_1H:
      return 60 * 60;
    case AuthorizationCondition.EXPIRABLE_8H:
      return 8 * 60 * 60;
    default:
      return null;
  }
}

/**
 * Whether a stored permission row should be removed as expired or invalid.
 * `nowSeconds` is Unix time in seconds (same basis as `created_at`).
 */
export function shouldRemoveStoredPermission(
  condition: string,
  createdAtSeconds: number,
  nowSeconds: number,
  durationSeconds?: number
): boolean {
  if (condition === AuthorizationCondition.EXPIRABLE_CUSTOM) {
    if (
      durationSeconds == null ||
      !Number.isFinite(durationSeconds) ||
      durationSeconds < MIN_CUSTOM_AUTHORIZATION_SECONDS ||
      durationSeconds > MAX_CUSTOM_AUTHORIZATION_SECONDS
    ) {
      return true;
    }
    return createdAtSeconds < nowSeconds - durationSeconds;
  }
  const fixedTtl = fixedExpiringPermissionTtlSeconds(condition);
  if (fixedTtl == null) {
    return false;
  }
  return createdAtSeconds < nowSeconds - fixedTtl;
}

/** The decisions stored for one site, whatever shape they were stored in. */
export function entriesOf(value: PermissionConfig[string] | undefined): PermissionEntry[] {
  if (!value || typeof value !== 'object') return [];
  // A single entry, as every site held before 1.26.0.
  if ('condition' in value) return [value as PermissionEntry];
  return Object.values(value).filter(
    (e): e is PermissionEntry => !!e && typeof e === 'object' && 'condition' in e
  );
}

/** The same decisions keyed by level, as written from 1.26.0 on. At one level the newer one wins. */
export function byLevel(entries: PermissionEntry[]): { [level: string]: PermissionEntry } {
  const out: { [level: string]: PermissionEntry } = {};
  for (const entry of entries) {
    const key = String(entry.level);
    if (!out[key] || (out[key].created_at ?? 0) <= (entry.created_at ?? 0)) out[key] = entry;
  }
  return out;
}

/**
 * Applies a site's stored decisions to an incoming request.
 *
 * An `allow` covers every request up to its level, a `deny` refuses every request from its level
 * upward, and a refusal wins while it lasts. That also makes the most recent word the one that
 * counts: allowing a level removes the refusals it covers (see addActivePermission), so a refusal
 * still standing was given after any grant it overlaps. Anything not covered is asked again.
 *
 * @param value - The stored decisions for the host, if any, in either shape
 * @param requiredLevel - Level the requested method needs
 */
export function resolveStoredPermission(
  value: PermissionConfig[string] | undefined,
  requiredLevel: number
): 'allow' | 'deny' | 'ask' {
  const entries = entriesOf(value);
  const refused = entries.some(
    e => e.decision === PermissionDecision.DENY && e.level <= requiredLevel
  );
  if (refused) return 'deny';
  const allowed = entries.some(
    e => (e.decision ?? PermissionDecision.ALLOW) === PermissionDecision.ALLOW && e.level >= requiredLevel
  );
  return allowed ? 'allow' : 'ask';
}

/**
 * Whether an answer may be remembered under this permission key.
 *
 * Keys are origins — `https://example.com`, scheme included, so a grant made over https says
 * nothing about the same name over plain http — or `extension:<id>` for another add-on. Anything
 * else is a page with no origin of its own: a local file, or a page its server sandboxed. All of
 * those share the origin "null", so an answer remembered for one would be an answer for every file
 * anybody downloads. They may still ask; their answers are never remembered.
 */
export function isRememberableKey(key: string | null | undefined): boolean {
  return (
    typeof key === 'string' && (/^https?:\/\/[^/\s]+$/.test(key) || key.startsWith('extension:'))
  );
}

/**
 * The origin a permission stored under a bare host (before 1.25.0) most likely came from.
 *
 * https, because that is almost certainly where the grant was made — and a wrong guess fails safe:
 * the site asks again. The exceptions are addresses where plain http is normal and no network sits
 * in between to exploit it: loopback, for local development, and .onion, which Tor encrypts
 * already. Returns null for what cannot be carried over, such as the one key every local file
 * shared.
 */
export function originForLegacyKey(key: string): string | null {
  if (isRememberableKey(key)) return key;
  if (!key || key === 'null' || key.includes('/')) return null;
  const hostname = key
    .replace(/:\d+$/, '')
    .replace(/^\[(.*)\]$/, '$1')
    .toLowerCase();
  const plainHttp =
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    /^127\./.test(hostname) ||
    hostname === '::1' ||
    hostname.endsWith('.onion');
  return `${plainHttp ? 'http' : 'https'}://${key}`;
}

/** A permissions map with every key moved to an origin; see originForLegacyKey. */
export function migratePermissionKeys(permissions: PermissionConfig | undefined): PermissionConfig {
  const out: PermissionConfig = {};
  for (const [key, entry] of Object.entries(permissions ?? {})) {
    const origin = originForLegacyKey(key);
    if (!origin) continue;
    // Two keys can only land on one origin if that origin was already stored. Keep the decisions of
    // both, one per level, the newer winning where they share one.
    out[origin] = out[origin] ? byLevel([...entriesOf(out[origin]), ...entriesOf(entry)]) : entry;
  }
  return out;
}

/** The shortest passphrase accepted: twelve characters, which three or four words clear easily. */
export const MIN_PASSPHRASE_LENGTH = 12;

/**
 * Why `secret` will not do as a PIN or passphrase of this kind, or null if it will.
 *
 * Shared by the PIN window and the background, so the rule holds whatever sends the setup message.
 * A passphrase is what makes a copied profile hard to open; one that is short, or only spaces, is a
 * PIN by another name.
 */
export function secretProblem(kind: SecretKind, secret: string): string | null {
  if (kind === 'pin') {
    return /^\d{4,6}$/.test(secret) ? null : 'A PIN is 4 to 6 digits';
  }
  return secret.trim().length >= MIN_PASSPHRASE_LENGTH
    ? null
    : `A passphrase needs at least ${MIN_PASSPHRASE_LENGTH} characters`;
}

/** Human-readable label for the options permissions table. */
export function formatPermissionDecisionLabel(decision?: PermissionDecision): string {
  return decision === PermissionDecision.DENY ? 'deny' : 'allow';
}

/** Human-readable label for the options permissions table. */
export function formatPermissionConditionLabel(
  condition: string,
  durationSeconds?: number
): string {
  switch (condition) {
    case AuthorizationCondition.FOREVER:
      return 'forever';
    case AuthorizationCondition.EXPIRABLE_5M:
      return '5 minutes';
    case AuthorizationCondition.EXPIRABLE_1H:
      return '1 hour';
    case AuthorizationCondition.EXPIRABLE_8H:
      return '8 hours';
    case AuthorizationCondition.EXPIRABLE_CUSTOM:
      return durationSeconds != null
        ? `custom (${formatAuthorizationDurationHuman(durationSeconds)})`
        : 'custom';
    default:
      return condition;
  }
}

function formatAuthorizationDurationHuman(totalSeconds: number): string {
  const days = Math.floor(totalSeconds / (24 * 60 * 60));
  const hours = Math.floor((totalSeconds % (24 * 60 * 60)) / (60 * 60));
  const minutes = Math.floor((totalSeconds % (60 * 60)) / 60);
  const parts: string[] = [];
  if (days > 0) {
    parts.push(`${days} day${days === 1 ? '' : 's'}`);
  }
  if (hours > 0) {
    parts.push(`${hours} hour${hours === 1 ? '' : 's'}`);
  }
  if (minutes > 0 || parts.length === 0) {
    parts.push(`${minutes} minute${minutes === 1 ? '' : 's'}`);
  }
  return parts.join(', ');
}

/**
 * Validates seconds for a custom grant (e.g. from a prompt message). Returns null if invalid.
 */
export function normalizeCustomAuthorizationDurationSeconds(
  durationSeconds: unknown
): number | null {
  if (typeof durationSeconds !== 'number' || !Number.isFinite(durationSeconds)) {
    return null;
  }
  const rounded = Math.round(durationSeconds);
  if (rounded < MIN_CUSTOM_AUTHORIZATION_SECONDS || rounded > MAX_CUSTOM_AUTHORIZATION_SECONDS) {
    return null;
  }
  return rounded;
}

export function truncatePublicKeys(
  publicKey: String,
  startCount: number = 15,
  endCount: number = 15
): String {
  return `${publicKey.substring(0, startCount)}…${publicKey.substring(
    publicKey.length - endCount
  )}`;
}

/**
 * Checks wether the URL is valid
 * @param url Relay websocket URL
 * @returns {boolean}
 */
export function isValidRelayURL(url: string): boolean {
  return url != null && url.trim() != '' && url.startsWith('wss://');
}

/**
 * Validates a nostr link handler URL template. Empty is valid (feature disabled).
 * Non-empty templates must contain a %s placeholder and form a parseable URL.
 */
export function isValidNostrLinkHandlerTemplate(template: string): boolean {
  const trimmed = template.trim();
  if (!trimmed) return true;
  if (!trimmed.includes('%s')) return false;
  return isWebAddress(trimmed.replace('%s', 'npub1test'));
}

/**
 * http or https, and nothing else. A handler template is typed in by the user, but a javascript:
 * or data: one would run on whatever page a nostr: link was clicked on.
 */
function isWebAddress(address: string): boolean {
  try {
    return /^https?:$/.test(new URL(address).protocol);
  } catch {
    return false;
  }
}

/**
 * Builds the destination URL from a template and a nostr: href. Checked again here, not only when
 * the template is saved, so a template stored before that rule existed cannot slip past it.
 */
export function buildNostrLinkUrl(template: string, nostrHref: string): string | null {
  const colonIndex = nostrHref.indexOf(':');
  if (colonIndex === -1) return null;

  const payload = nostrHref.slice(colonIndex + 1);
  if (!payload) return null;

  const destination = template.replace('%s', encodeURIComponent(payload));
  return isWebAddress(destination) ? destination : null;
}

/**
 * Where the ext+nostr: protocol handler page should go, from its own query string. URLSearchParams
 * has already decoded `uri`; decoding it a second time turned any % in a link into an exception and
 * left a blank tab.
 */
export function handlerDestination(template: string, search: string): string | null {
  const uri = new URLSearchParams(search).get('uri');
  if (!template.trim() || !uri) return null;
  return buildNostrLinkUrl(template, uri);
}

export function isHexadecimal(value: string) {
  return /^[0-9A-Fa-f]+$/g.test(value);
}

export function convertHexToUint8Array(hexData: string): Uint8Array {
  // ensure even number of characters
  if (hexData.length % 2 != 0) {
    throw new Error('WARNING: expecting an even number of characters in the hexString');
  }

  // check for some non-hex characters
  const hasInvalidChars = hexData.match(/[G-Z\s]/i);
  if (hasInvalidChars) {
    throw new Error(`WARNING: found non-hex characters: ${hasInvalidChars.toString()}`);
  }

  // split the string into pairs of octets
  const octectPairs = hexData.match(/[\dA-F]{2}/gi);

  if (!octectPairs) {
    throw Error('Cannot extract octect pairs.');
  }

  // convert the octets to integers
  const integers = octectPairs.map(pair => {
    return parseInt(pair, 16);
  });

  const array = new Uint8Array(integers);
  return array;
}

export function convertUint8ArrayToHex(arrayData: Uint8Array): string {
  let hexData = '';
  for (let i = 0; i < arrayData.length; i++) {
    const value = arrayData[i];
    hexData = hexData + ('0' + value.toString(16)).slice(-2);
  }
  return hexData;
}

export function openPopupWindow(
  pageUrl: string,
  windowSize: { width: number; height: number } = { width: 600, height: 400 }
): Promise<browser.Windows.Window | browser.Tabs.Tab> {
  const promptPageURL = browser.runtime.getURL(pageUrl);

  // open the popup window

  let openPromptPromise: Promise<browser.Windows.Window | browser.Tabs.Tab>;
  if (browser.windows) {
    openPromptPromise = browser.windows.create({
      url: promptPageURL,
      type: 'popup',
      width: windowSize.width,
      height: windowSize.height
    });
  } else {
    // Android Firefox
    openPromptPromise = browser.tabs.create({
      url: promptPageURL,
      active: true
    });
  }

  return openPromptPromise;
}

//#region Private Key Utilities

/**
 * Checks if a private key is encrypted (starts with '{')
 * @param privateKey - The private key to check
 * @returns true if the private key is encrypted, false otherwise
 */
export function isPrivateKeyEncrypted(privateKey: string): boolean {
  return privateKey != null && privateKey.startsWith('{');
}

/**
 * Derives a public key from a plain-text private key
 * @param privateKey - The plain-text private key (hex string)
 * @returns The derived public key
 * @throws Error if the private key is encrypted or invalid
 */
export function derivePublicKeyFromPrivateKey(privateKey: string): string {
  if (!privateKey) {
    throw new Error('Private key is empty');
  }
  if (isPrivateKeyEncrypted(privateKey)) {
    throw new Error('Cannot derive public key from encrypted private key');
  }
  return getPublicKey(convertHexToUint8Array(privateKey));
}

/**
 * Checks if a public key can be derived from a private key
 * @param privateKey - The private key to check
 * @param pinEnabled - Whether PIN protection is enabled
 * @returns true if public key can be derived, false otherwise
 */
export function canDerivePublicKeyFromPrivateKey(privateKey: string, pinEnabled: boolean): boolean {
  if (!privateKey) return false;
  return !(pinEnabled && isPrivateKeyEncrypted(privateKey));
}

/**
 * Finds an existing profile that uses the same private key as the one being imported.
 * @returns The public key of the matching profile, or undefined if none found
 */
export function findExistingProfileByPrivateKey(
  importedPrivateKey: string | undefined,
  existingProfiles: ProfilesConfig,
  pinEnabled: boolean,
  derivedPublicKey?: string
): string | undefined {
  if (!importedPrivateKey) return undefined;

  const exactMatch = Object.entries(existingProfiles).find(
    ([, profile]) => profile.privateKey === importedPrivateKey
  );
  if (exactMatch) return exactMatch[0];

  if (
    pinEnabled &&
    derivedPublicKey &&
    !isPrivateKeyEncrypted(importedPrivateKey) &&
    existingProfiles[derivedPublicKey]
  ) {
    return derivedPublicKey;
  }

  return undefined;
}

/**
 * Formats a private key for display in the UI
 * @param privateKey - The private key to format
 * @param pinEnabled - Whether PIN protection is enabled
 * @returns Empty string if encrypted, otherwise nsec-encoded string
 */
export function formatPrivateKeyForDisplay(privateKey: string, pinEnabled: boolean): string {
  if (!privateKey) return '';
  if (pinEnabled && isPrivateKeyEncrypted(privateKey)) {
    // Private key is encrypted, can't display it
    return '';
  }
  // Private key is plain-text, encode it for display
  return nip19.nsecEncode(convertHexToUint8Array(privateKey));
}

/**
 * Validates if a private key has a valid format (hex or nsec)
 * @param privateKey - The private key to validate
 * @returns true if the format is valid, false otherwise
 */
export function validatePrivateKeyFormat(privateKey: string): boolean {
  if (privateKey === '') return true;
  if (privateKey.match(/^[a-f0-9]{64}$/)) return true;
  try {
    if (nip19.decode(privateKey).type === 'nsec') return true;
  } catch (err) {
    // Invalid format
  }
  return false;
}

//#endregion Private Key Utilities
