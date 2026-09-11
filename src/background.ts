import browser from 'webextension-polyfill';
import { validateEvent, finalizeEvent, getPublicKey, nip44 } from 'nostr-tools';
import { nip04, nip19 } from 'nostr-tools';

import * as Storage from './storage';
import {
  AuthorizationCondition,
  ConfigurationKeys,
  ContentMessageArgs,
  ContentScriptMessageResponse,
  OpenPromptItem,
  PermissionDecision,
  PinMessage,
  PinMessageResponse,
  PinMode,
  PromptParams,
  PromptResponse,
  SecretKind
} from './types';
import {
  PERMISSIONS_REQUIRED,
  convertHexToUint8Array,
  openPopupWindow,
  derivePublicKeyFromPrivateKey,
  normalizeCustomAuthorizationDurationSeconds,
  isRememberableKey,
  resolveStoredPermission,
  secretProblem
} from './common';
import PromptManager from './PromptManager';
import { getCachedPin, setCachedPin, clearCachedPin } from './pinCache';
import { decryptPrivateKey, encryptPrivateKey } from './pinEncryption';
import { clearUint8Array, clearStringReference } from './memoryUtils';

/** Map to keep track of open prompts so we can properly capture the responses and close them */
const openPromptMap: Record<
  string,
  { id: string; host: string; windowId?: number; resolve: Function; reject: Function }
> = {};

/**
 * Windows that have been asked for but do not exist yet, per kind of prompt. Without this a
 * request cannot see a window that is still opening, and opens a second one.
 */
const windowsOpening = new Map<string, Promise<browser.Windows.Window | browser.Tabs.Tab>>();

/** Map to keep track of PIN prompts */
const pinPromptMap: Record<
  string,
  { id: string; windowId?: number; resolve: Function; reject: Function; mode: string }
> = {};

/**
 * Stored permissions move from bare hosts to origins once, when this version first runs. Requests
 * wait for it: a grant written while the move is half done would be lost in its single write.
 */
const permissionsReady = Storage.migratePermissionsToOrigins().catch(error =>
  console.error('Could not move stored permissions to origins.', error)
);

/** Handlers that must never answer something living in a tab. */
const EXTENSION_PAGES_ONLY = new Set([
  'setupPin',
  'verifyPin',
  'disablePin',
  'openPinPrompt',
  'encryptPrivateKey',
  'getCachedPin',
  'copyNsec'
]);

/**
 * Did this come from one of our own pages, rather than from a content script in a web page?
 *
 * NOT `sender.tab`. The options page is opened with tabs.create(), so it has a tab like any web
 * page does — checking for one blocked the extension from talking to itself, and PIN protection
 * silently stopped working with nothing on screen to say why.
 *
 * `sender.url` is the discriminator that actually holds. For a content script it is the address of
 * the page it was injected into, never a moz-extension:// one; content scripts do not run on
 * extension pages, and a web page cannot reach this listener at all.
 */
function fromOwnPage(sender: browser.Runtime.MessageSender): boolean {
  const base = browser.runtime.getURL('');
  return typeof sender?.url === 'string' && sender.url.startsWith(base);
}

browser.runtime.onMessage.addListener(async (message, sender) => {
  // The content script's allow-list is not the only thing that should be refusing these — this is
  // the half that survives somebody adding a second bridge later and forgetting.
  if (!fromOwnPage(sender) && EXTENSION_PAGES_ONLY.has(message?.type)) {
    return { success: false, error: 'not available to pages' };
  }

  // Check if it's a PIN message
  if (
    message.type === 'setupPin' ||
    message.type === 'verifyPin' ||
    message.type === 'disablePin' ||
    message.type === 'copyNsec'
  ) {
    return handlePinMessage(message as PinMessage, sender);
  }

  // Check if it's a request to open a PIN prompt
  if (message.type === 'openPinPrompt') {
    const mode = message.mode as PinMode;
    if (mode && ['setup', 'unlock', 'disable', 'copy'].includes(mode)) {
      await promptPin(mode);
      return { success: true };
    }
    return { success: false, error: 'Invalid PIN mode' };
  }

  // Check if it's a request to encrypt a private key
  if (message.type === 'encryptPrivateKey') {
    const pinEnabled = await Storage.isPinEnabled();
    if (!pinEnabled) {
      return { success: false, error: 'PIN protection is not enabled' };
    }

    const { privateKey } = message;
    if (!privateKey) {
      return { success: false, error: 'Private key is required' };
    }

    // Check if PIN is cached, if not prompt for it
    let pin = await getCachedPin();
    if (!pin) {
      pin = await promptPin('unlock');
      if (!pin) {
        return { success: false, error: 'PIN is required to encrypt private key' };
      }
      await setCachedPin(pin);
    }

    try {
      const encryptedKey = await encryptPrivateKey(pin, privateKey);
      return { success: true, encryptedKey };
    } catch (error) {
      return { success: false, error: error.message };
    } finally {
      // Clear PIN reference after use (strings are immutable, but we null the reference)
      pin = clearStringReference(pin) as any;
    }
  }

  // Check if it's a request to get cached PIN status
  if (message.type === 'getCachedPin') {
    const pin = await getCachedPin();
    return { success: true, pin };
  }

  let { prompt } = message as PromptResponse;

  if (prompt) {
    // An answer to a permission prompt, which only the prompt page gives. The content script cannot
    // send one today — it does not copy `prompt` across — but that is the same kind of accident the
    // PIN handlers once relied on, so it is refused here as well.
    if (!fromOwnPage(sender)) {
      return { error: { message: 'not available to pages' } };
    }
    handlePromptMessage(message as PromptResponse, sender);
  } else {
    return handleContentScriptMessage(message as ContentMessageArgs);
  }
});

/**
 * Another installed extension asking this one to sign, rather than a web page.
 *
 * The caller has to be named, because whatever name it gets is what the authorization dialog puts
 * in its headline and what ends up in the permissions table under "forever". This used to take the
 * host out of `sender.url`, which for an extension is `moz-extension://<uuid>/` — and in Firefox
 * that UUID is generated per installation. It identifies nobody, it differs on every machine, and
 * a permanent grant to it is a permanent grant to something the user cannot look up.
 *
 * `sender.id` is the add-on's real id: the one on its listing, the same everywhere. It is prefixed
 * so that an extension can never land in the same row of the permissions table as a website with a
 * matching name, and so the dialog can say plainly that the request is not coming from a page.
 *
 * Grants made under the old UUID no longer match and are simply asked again, which is the right
 * direction for a permission to fail in.
 */
browser.runtime.onMessageExternal.addListener(async (message, sender) => {
  const { type, params } = message as ContentMessageArgs;

  if (!sender?.id) {
    return { error: { message: 'the caller could not be identified' } };
  }

  return handleContentScriptMessage({ type, params, host: `extension:${sender.id}` });
});

// Clear any stale open prompts on browser startup
// This handles the case where prompts were pending when browser crashed/closed
browser.runtime.onStartup.addListener(async () => {
  console.debug('Browser startup detected. Clearing stale open prompts.');
  await PromptManager.clear();
});

// Clear stale open prompts on extension install/update/reload
browser.runtime.onInstalled.addListener(async () => {
  console.debug('Extension installed/updated. Clearing stale open prompts.');
  await PromptManager.clear();
});

/**
 * Shows the on/off state of the signer on the toolbar icon, so it is visible without
 * opening the popup. Badge APIs are unavailable on some platforms (Android Firefox).
 */
async function updateToolbarState() {
  const enabled = await Storage.isSignerEnabled();

  try {
    await browser.browserAction.setBadgeText({ text: enabled ? '' : 'OFF' });
    await browser.browserAction.setBadgeBackgroundColor({ color: '#b91c1c' });
    await browser.browserAction.setTitle({
      title: enabled ? 'Attest' : 'Attest (disabled)'
    });
  } catch (error) {
    console.debug('Could not update the toolbar state.', error);
  }
}

// Keep the toolbar in sync with the stored on/off state, whoever changed it
browser.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === 'local' && ConfigurationKeys.SIGNER_ENABLED in changes) {
    updateToolbarState();
  }
});

updateToolbarState();

/**
 * Handles the closing of a prompt or PIN popup window.
 * Rejects all pending prompts associated with the closed window.
 *
 * @param closedId - The ID of the closed window (or tab on Android).
 */
function handlePromptPopupClosed(closedId: number) {
  // Search the open prompts with this window ID
  const openPrompts = Object.values(openPromptMap).filter(({ windowId }) => windowId === closedId);

  console.debug(`Prompt popup ${closedId} closed. Closing ${openPrompts.length} prompts.`);

  // Handle the rejection on all of them
  // We need to do it sequentially, hence the async trick
  const closeAllAsync = async () => {
    for (const openPrompt of openPrompts) {
      await handlePromptMessage(
        {
          id: openPrompt.id,
          prompt: true,
          condition: AuthorizationCondition.REJECT,
          host: null
        },
        null
      );
    }
  };
  closeAllAsync(); // now run

  // Also handle PIN prompts
  const pinPrompts = Object.values(pinPromptMap).filter(({ windowId }) => windowId === closedId);
  for (const pinPrompt of pinPrompts) {
    pinPrompt.reject(new Error('PIN prompt window closed'));
    delete pinPromptMap[pinPrompt.id];
  }
}

// Listen for popup closing, with support for both Desktop and Android Firefox
if (browser.windows) {
  browser.windows.onRemoved.addListener(windowId => {
    handlePromptPopupClosed(windowId);
  });
} else {
  // Android Firefox — popups are tabs, not windows
  browser.tabs.onRemoved.addListener(tabId => {
    handlePromptPopupClosed(tabId);
  });
}

/**
 * Handles a message from the content script by processing the specified type and parameters.
 *
 * @param type - The type of operation to be performed.
 * @param params - The prompt parameters required for the operation.
 * @param host - The host from which the message originated.
 * @returns A response object which can be an Error, a pubkey, a VerifiedEvent or a RelaysConfig.
 *
 * Errors go back as a message and nothing else. They used to carry `stack` too, and a stack from
 * here reads `handleContentScriptMessage@moz-extension://<uuid>/background.js` — the per-install
 * identifier, handed to any site with signing permission that sent an event with the wrong pubkey.
 */
async function handleContentScriptMessage({
  type,
  params,
  host
}: ContentMessageArgs): Promise<ContentScriptMessageResponse> {
  await permissionsReady;

  if (!(await Storage.isSignerEnabled())) {
    // the signer is switched off for every site, so don't even prompt
    return { error: { message: 'Attest is disabled' } };
  }

  // Only the methods there are. An unknown one used to get a prompt that listed every capability,
  // and answering it with a remembered decision never settled the call.
  if (!Object.prototype.hasOwnProperty.call(PERMISSIONS_REQUIRED, type)) {
    return { error: { message: `unknown method "${type}"` } };
  }

  const requiredLevel = PERMISSIONS_REQUIRED[type];
  const insufficientPermissions = {
    error: { message: `Insufficient permissions, required ${requiredLevel}` }
  };
  const permissions = await Storage.readActivePermissions();
  // Nothing is looked up for a page with no origin of its own; see isRememberableKey.
  const storedPermission = isRememberableKey(host) ? permissions[host] : undefined;

  switch (resolveStoredPermission(storedPermission, requiredLevel)) {
    case 'allow':
      // authorized, proceed
      break;
    case 'deny':
      // refused earlier for this long, stop here without prompting
      return insufficientPermissions;
    case 'ask':
      try {
        const isAllowed = await promptPermission(host, requiredLevel, params);
        if (!isAllowed) {
          // not authorized, stop here
          return insufficientPermissions;
        }
      } catch (error) {
        console.error('Error asking for permission.', error);
        return { error: { message: error.message } };
      }
      break;
  }

  // Neither of these needs the private key: the public key is stored as the active one, and the
  // relays sit on the profile. Decrypting for them meant a PIN prompt for a question with no secret
  // in it.
  if (type === 'getPublicKey') {
    const stored = await Storage.getActivePublicKey();
    if (stored) return stored;
  }
  if (type === 'getRelays') {
    return (await Storage.readActiveRelays()) || {};
  }

  // Get decrypted private key (handles PIN protection automatically)
  let privateKey = await getDecryptedPrivateKey();
  if (!privateKey) {
    return { error: { message: 'no private key found' } };
  }

  // Minimize private key exposure: convert to Uint8Array immediately
  // Derive public key before clearing private key string
  const activePubKey = derivePublicKeyFromPrivateKey(privateKey);

  // Convert private key string to Uint8Array and clear string reference immediately
  const sk = convertHexToUint8Array(privateKey);
  // Clear private key string reference (strings are immutable, but we null the reference)
  privateKey = clearStringReference(privateKey) as any;

  try {
    switch (type) {
      case 'getPublicKey': {
        return activePubKey;
      }
      case 'getRelays': {
        let relays = await Storage.readActiveRelays();
        return relays || {};
      }
      case 'signEvent': {
        if (!params.event) {
          return { error: { message: 'empty event' } };
        }

        // check if the pubkey used corresponds to the active profile
        // only do it when pubkey is not empty, since some sites don't specify it
        if (params.event?.pubkey && params.event.pubkey !== activePubKey) {
          console.warn(
            `Pubkey used (${params.event.pubkey}) doesn't match the active profile (${activePubKey}).`
          );
          throw new Error(`Public key used doesn't match the active profile.`);
        }

        const event = finalizeEvent(params.event, sk);

        return validateEvent(event) ? event : { error: { message: 'invalid event' } };
      }
      case 'nip04.encrypt': {
        let { peer, plaintext } = params;
        return nip04.encrypt(sk, peer, plaintext as string);
      }
      case 'nip04.decrypt': {
        let { peer, ciphertext } = params;
        return nip04.decrypt(sk, peer, ciphertext as string);
      }
      case 'nip44.encrypt': {
        const { peer, plaintext } = params;
        const key = getSharedSecret(sk, peer);
        return nip44.v2.encrypt(plaintext as string, key);
      }
      case 'nip44.decrypt': {
        const { peer, ciphertext } = params;
        const key = getSharedSecret(sk, peer);
        return nip44.v2.decrypt(ciphertext as string, key);
      }
      default: {
        return { error: { message: `unknown method "${type}"` } };
      }
    }
  } catch (error) {
    return { error: { message: error.message } };
  } finally {
    // Clear private key Uint8Array from memory after operations complete
    clearUint8Array(sk);
  }
}

async function handlePromptMessage(
  {
    id,
    condition,
    level,
    durationSeconds,
    decision = PermissionDecision.ALLOW
  }: PromptResponse,
  sender
): Promise<void> {
  const openPrompt = openPromptMap[id];
  if (!openPrompt) {
    console.warn('Message from unrecognized prompt: ', id);
    // Still remove from storage to prevent stale entries accumulating
    await PromptManager.remove(id);
    return;
  }

  // The site this prompt was opened for, recorded when it was opened — not the `host` in the
  // answer, which is whatever the answering page says it was.
  const host = openPrompt.host;
  // A page with no origin of its own may be allowed or refused, but only this once.
  const remember = isRememberableKey(host);

  // a remembered denial resolves the pending call negatively, just like a plain rejection
  const isAllowed = decision === PermissionDecision.ALLOW;

  try {
    switch (condition) {
      case AuthorizationCondition.FOREVER:
      case AuthorizationCondition.EXPIRABLE_5M:
      case AuthorizationCondition.EXPIRABLE_1H:
      case AuthorizationCondition.EXPIRABLE_8H:
        if (level) {
          openPrompt.resolve?.(isAllowed);
          if (remember) Storage.addActivePermission(host, condition, level, decision);
        } else {
          console.warn('No authorization level provided');
        }
        break;
      case AuthorizationCondition.EXPIRABLE_CUSTOM: {
        const normalizedSeconds = normalizeCustomAuthorizationDurationSeconds(durationSeconds);
        if (level && normalizedSeconds != null) {
          openPrompt.resolve?.(isAllowed);
          if (remember) {
            Storage.addActivePermission(host, condition, level, decision, normalizedSeconds);
          }
        } else {
          console.warn('Invalid custom authorization duration or missing level');
          openPrompt.resolve?.(false);
        }
        break;
      }
      case AuthorizationCondition.SINGLE:
        openPrompt.resolve?.(isAllowed);
        break;
      case AuthorizationCondition.REJECT:
        openPrompt.resolve?.(false);
        break;
    }

    // remove the prompt from the map
    delete openPromptMap[id];

    // close prompt — only a page that lives in a window has a window to close
    if (sender?.tab) {
      const openPrompts = await PromptManager.get();

      // only close the prompt window if there is no other prompt pending
      if (openPrompts.length == 1) {
        if (browser.windows) {
          await browser.windows.remove(sender.tab.windowId);
        } else {
          // Android Firefox
          await browser.tabs.remove(sender.tab.id);
        }
      }
    }
    // remove the prompt from the storage
    await PromptManager.remove(id);
  } catch (error) {
    console.error('Error handling prompt response.', error);
    openPrompt.reject?.(error);
  }
}

/**
 * A window to hang a prompt on: the one already open if it still exists, a new one otherwise.
 *
 * Reusing the open window is what queues a second request behind the first instead of stacking
 * popups, and that part was right. What was missing is that the id can be stale. A window the user
 * closed leaves its entry in the map until windows.onRemoved has run, and a request arriving in
 * that gap asked windows.get() about a window that no longer existed. The rejection had no handler,
 * so the promise it fed never settled: no popup, no error, nothing in any log, and the caller
 * waiting forever for an answer that was never coming.
 *
 * That is not a hypothetical. It is why a zap could leave the wallet with no signature on it: the
 * page asked for one, the second prompt never appeared, and the client fell back to paying a plain
 * invoice. A refusal you cannot see is worse than a refusal.
 */
async function promptWindow(
  slot: string,
  existingWindowId: number | undefined,
  open: () => Promise<browser.Windows.Window | browser.Tabs.Tab>
): Promise<browser.Windows.Window | browser.Tabs.Tab> {
  const live = async (id: number) =>
    browser.windows ? await browser.windows.get(id) : await browser.tabs.get(id);

  if (existingWindowId != null) {
    try {
      return await live(existingWindowId);
    } catch {
      // Gone, and the map has not caught up yet. Opening a new one is the whole point of asking.
      console.debug(`Prompt window ${existingWindowId} no longer exists. Opening a new one.`);
    }
  }

  // A window that has been asked for but does not exist yet is invisible to the map, because an
  // entry only gets its id once the window is open. Two requests in the same tick therefore both
  // used to open one — the popup nobody asked for twice. They wait for the same window instead.
  const opening = windowsOpening.get(slot);
  if (opening) {
    try {
      return await live((await opening).id as number);
    } catch {
      // It opened and was closed again while we waited, or it never opened at all.
    }
  }

  const own = open();
  windowsOpening.set(slot, own);
  try {
    return await own;
  } finally {
    if (windowsOpening.get(slot) === own) windowsOpening.delete(slot);
  }
}

function promptPermission(host: string, level: number, params: PromptParams): Promise<boolean> {
  const id = Math.random().toString().slice(4);
  const promptPageURL = `${browser.runtime.getURL('prompt.html')}`;

  return new Promise((resolve, reject) => {
    // Registered before there is a window, on purpose: two requests arriving in the same tick both
    // used to find an empty map and both open a popup of their own. The second one now sees this.
    openPromptMap[id] = { id, host, resolve, reject };

    const inFlight = Object.values(openPromptMap).find(({ windowId }) => windowId != null);
    if (inFlight) console.debug('There is already a prompt popup window open.');

    promptWindow('permission', inFlight?.windowId, () =>
      browser.windows
        ? browser.windows.create({
            url: promptPageURL,
            type: 'popup',
            width: 600,
            // 520, not the 400 upstream uses: this branch's prompt shows more.
            height: 520
          })
        : // Android Firefox
          browser.tabs.create({
            url: promptPageURL,
            active: true
          })
    ).then(
      win => {
        const entry = openPromptMap[id];
        // Answered or cleaned up while the window was still opening.
        if (!entry) return;
        entry.windowId = win.id;
        PromptManager.add({ id, windowId: win.id, host, level, params });
      },
      error => {
        // Nothing can be shown, so this has to fail where the caller can see it rather than hang.
        delete openPromptMap[id];
        reject(error instanceof Error ? error : new Error('could not open a prompt window'));
      }
    );
  });
}

/**
 * Gets the decrypted private key, handling PIN protection automatically
 * This encapsulates all PIN logic - the rest of the code doesn't need to know about PIN
 * - Checks if PIN protection is enabled
 * - If enabled: checks cache, prompts if needed, decrypts
 * - If disabled: returns plain key from storage
 */
async function getDecryptedPrivateKey(): Promise<string | null> {
  const pinEnabled = await Storage.isPinEnabled();

  if (!pinEnabled) {
    // PIN protection disabled, return plain key
    return await Storage.readActivePrivateKey();
  }

  // PIN protection enabled, check cache first
  let pin = await getCachedPin();
  if (!pin) {
    // Cache expired or not set, prompt for PIN
    pin = await promptPin('unlock');
    if (!pin) {
      return null; // User cancelled or error
    }
    await setCachedPin(pin);
  }

  // Decrypt private key using PIN
  let decryptedKey: string | null = null;
  try {
    const encryptedKey = await Storage.getEncryptedPrivateKey();
    if (!encryptedKey) {
      throw new Error('Encrypted private key not found');
    }
    decryptedKey = await decryptPrivateKey(pin, encryptedKey);
    return decryptedKey;
  } catch (error) {
    // Decryption failed, clear cache and return error
    clearCachedPin();
    throw error;
  } finally {
    // Clear PIN reference after use (strings are immutable, but we null the reference)
    // Note: pin may still be cached, but we clear the local reference
    pin = clearStringReference(pin) as any;
  }
}

/**
 * Prompts the user for PIN entry
 * @param mode - 'setup', 'unlock', 'disable', or 'copy'
 * @returns The entered PIN, or null if cancelled/error
 */
function promptPin(mode: PinMode): Promise<string | null> {
  const id = Math.random().toString().slice(4);

  return new Promise((resolve, reject) => {
    // Same reasoning as promptPermission: registered first, so a second request in the same tick
    // finds it instead of opening a second window.
    pinPromptMap[id] = { id, resolve, reject, mode };

    const inFlight = Object.values(pinPromptMap).find(
      p => p.id !== id && p.mode === mode && p.windowId != null
    );
    if (inFlight) console.debug('There is already a PIN prompt window open.');
    else console.debug('Opening PIN prompt window.');

    promptWindow(`pin:${mode}`, inFlight?.windowId, () =>
      // Setup has a choice to make and an explanation of it to show, the other modes one field.
      openPopupWindow(`pin.html?mode=${mode}&id=${id}`, {
        width: 460,
        height: mode === 'setup' ? 520 : 340
      })
    ).then(
      win => {
        const entry = pinPromptMap[id];
        // Answered or cleaned up while the window was still opening.
        if (!entry) return;
        entry.windowId = win.id;
      },
      error => {
        delete pinPromptMap[id];
        reject(error instanceof Error ? error : new Error('could not open a PIN prompt window'));
      }
    );
  });
}

/**
 * Handles PIN-related messages from the PIN prompt UI
 */
async function handlePinMessage(
  message: PinMessage,
  sender: browser.Runtime.MessageSender
): Promise<PinMessageResponse> {
  const { type, pin, encryptedKey, id, kind } = message;
  const pinPrompt = id ? pinPromptMap[id] : pinPromptMap[Object.keys(pinPromptMap)[0]];

  if (!pinPrompt) {
    return { success: false, error: 'PIN prompt not found' };
  }

  // Extract PIN to local variable for clearing after use
  let localPin = pin;

  try {
    switch (type) {
      case 'setupPin': {
        if (!localPin || !encryptedKey) {
          return { success: false, error: 'Missing PIN or encrypted key' };
        }

        // The rule is checked here as well as in the window: it is what makes a passphrase worth
        // having, and the window is not the only thing that could send this message.
        const secretKind: SecretKind = kind === 'passphrase' ? 'passphrase' : 'pin';
        const problem = secretProblem(secretKind, localPin);
        if (problem) {
          return { success: false, error: problem };
        }

        // The window encrypted the key itself. Before anything is written, make sure what it sent
        // opens with what it says: storing a key that does not would lock its owner out of it.
        try {
          await decryptPrivateKey(localPin, encryptedKey);
        } catch (error) {
          return { success: false, error: 'The encrypted key does not open with that secret' };
        }

        // Enable PIN protection with the provided encrypted key
        await Storage.setEncryptedPrivateKey(encryptedKey);

        // Encrypt all profile keys and store active public key
        await Storage.enablePinProtectionWithEncryptedKey(localPin, encryptedKey);
        await Storage.setPinKind(secretKind);

        // Cache PIN
        await setCachedPin(localPin);

        // Resolve PIN prompt
        if (pinPrompt) {
          pinPrompt.resolve(localPin);
          delete pinPromptMap[pinPrompt.id];
        }

        // Close PIN window
        if (sender && sender.tab) {
          if (browser.windows && sender.tab.windowId !== undefined) {
            await browser.windows.remove(sender.tab.windowId);
          } else if (sender.tab.id !== undefined) {
            await browser.tabs.remove(sender.tab.id);
          }
        }

        return { success: true };
      }

      case 'verifyPin': {
        if (!localPin) {
          return { success: false, error: 'Missing PIN' };
        }

        // Verify PIN by attempting to decrypt
        const encryptedKey = await Storage.getEncryptedPrivateKey();
        if (!encryptedKey) {
          return { success: false, error: 'No encrypted key found' };
        }

        try {
          await decryptPrivateKey(localPin, encryptedKey);
          // PIN is correct, cache it
          await setCachedPin(localPin);

          // Resolve PIN prompt
          if (pinPrompt) {
            pinPrompt.resolve(localPin);
            delete pinPromptMap[pinPrompt.id];
          }

          // Close PIN window
          if (sender && sender.tab) {
            if (browser.windows && sender.tab.windowId !== undefined) {
              await browser.windows.remove(sender.tab.windowId);
            } else if (sender.tab.id !== undefined) {
              await browser.tabs.remove(sender.tab.id);
            }
          }

          return { success: true };
        } catch (error) {
          return { success: false, error: 'Incorrect PIN' };
        }
      }

      case 'disablePin': {
        if (!localPin) {
          return { success: false, error: 'Missing PIN' };
        }

        // Verify PIN and disable protection
        await Storage.disablePinProtection(localPin);
        clearCachedPin();

        // Resolve PIN prompt
        if (pinPrompt) {
          pinPrompt.resolve(localPin);
          delete pinPromptMap[pinPrompt.id];
        }

        // Close PIN window
        if (sender && sender.tab) {
          if (browser.windows && sender.tab.windowId !== undefined) {
            await browser.windows.remove(sender.tab.windowId);
          } else if (sender.tab.id !== undefined) {
            await browser.tabs.remove(sender.tab.id);
          }
        }

        return { success: true };
      }

      // Hand the decrypted key to the PIN window that just asked for it, so it can be put on the
      // clipboard and taken elsewhere. With PIN protection on this is the only way a key can leave
      // the extension at all, and a signer that cannot give a key back is a trap rather than a
      // safe: whoever turns PIN protection on would be choosing, without being told, never to move
      // that identity again.
      //
      // Three things keep this narrow, and none of them is optional:
      //
      //   - it answers extension pages only, like every other PIN message (EXTENSION_PAGES_ONLY),
      //     so a website asking for it is refused before this switch is reached;
      //   - it decrypts with the PIN typed into this window, never with the cached one, and does
      //     not refresh the cache. Riding the cache would make "export my private key" a
      //     two-click operation for anybody who reaches an unlocked browser;
      //   - the key goes back to that window and nowhere else. The options page never receives it.
      case 'copyNsec': {
        if (!localPin) {
          return { success: false, error: 'Missing PIN' };
        }

        const storedKey = await Storage.getEncryptedPrivateKey();
        if (!storedKey) {
          return { success: false, error: 'No encrypted key found' };
        }

        let hexKey: string | null = null;
        try {
          hexKey = await decryptPrivateKey(localPin, storedKey);
        } catch (error) {
          return { success: false, error: 'Incorrect PIN' };
        }
        if (!hexKey) {
          return { success: false, error: 'No key to copy' };
        }

        const bytes = convertHexToUint8Array(hexKey);
        try {
          return {
            success: true,
            nsec: nip19.nsecEncode(bytes),
            npub: nip19.npubEncode(derivePublicKeyFromPrivateKey(hexKey))
          };
        } finally {
          clearUint8Array(bytes);
          hexKey = clearStringReference(hexKey) as any;
          // The prompt is resolved but the window is deliberately left open: it still has to write
          // to the clipboard and say which key it wrote. It closes itself afterwards.
          if (pinPrompt) {
            pinPrompt.resolve(null);
            delete pinPromptMap[pinPrompt.id];
          }
        }
      }

      default:
        return { success: false, error: 'Unknown PIN message type' };
    }
  } catch (error) {
    if (pinPrompt) {
      pinPrompt.reject(error);
      delete pinPromptMap[pinPrompt.id];
    }
    return { success: false, error: error.message };
  } finally {
    // Clear PIN reference after use (strings are immutable, but we null the reference)
    localPin = clearStringReference(localPin) as any;
  }
}

/**
 * The NIP-44 conversation key with `peer`.
 *
 * A cache used to sit in front of this, and it never held anything: it was cleared whenever `sk`
 * differed from a variable nothing ever assigned, which was every call. It is gone rather than
 * repaired — `sk` is a fresh array for every request, so a "same key" check by reference could never
 * have matched, and a cache of conversation keys is a cache of secrets.
 */
function getSharedSecret(sk: Uint8Array, peer: string) {
  return nip44.v2.utils.getConversationKey(sk, peer);
}
