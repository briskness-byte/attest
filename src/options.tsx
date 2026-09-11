import React, { useState, useCallback, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { useDebouncedCallback } from 'use-debounce';
import browser from 'webextension-polyfill';
import { getPublicKey, generateSecretKey, nip19 } from 'nostr-tools';
import { format, formatDistance } from 'date-fns';

import { Alert, Modal } from './components';

import {
  ConfigurationKeys,
  PermissionConfig,
  PermissionDecision,
  ProfileConfig,
  ProfilesConfig,
  RelaysConfig
} from './types';
import * as Storage from './storage';
import {
  convertHexToUint8Array,
  convertUint8ArrayToHex,
  getPermissionsString,
  isHexadecimal,
  isValidRelayURL,
  isValidNostrLinkHandlerTemplate,
  truncatePublicKeys,
  isPrivateKeyEncrypted,
  derivePublicKeyFromPrivateKey,
  canDerivePublicKeyFromPrivateKey,
  findExistingProfileByPrivateKey,
  formatPrivateKeyForDisplay,
  validatePrivateKeyFormat,
  formatPermissionConditionLabel,
  formatPermissionDecisionLabel,
  migratePermissionKeys,
  entriesOf
} from './common';
// The SVG rather than the PNG: its wordmark is drawn in currentColor, so it follows the
// theme. The PNG has near-black lettering baked in, which on the dark background came out
// at 1.04:1 — a name you cannot read on your own settings page.
import Logotype from './assets/logo/logotype.svg';
import AddCircleIcon from './assets/icons/add-circle-outline.svg';
import ArrowUpCircleIcon from './assets/icons/arrow-up-circle-outline.svg';
import CopyIcon from './assets/icons/copy-outline.svg';
import DiceIcon from './assets/icons/dice-outline.svg';
import EyeIcon from './assets/icons/eye-outline.svg';
import EyeOffIcon from './assets/icons/eye-off-outline.svg';
import DownloadIcon from './assets/icons/download-outline.svg';
import PencilIcon from './assets/icons/pencil-outline.svg';
import RadioIcon from './assets/icons/radio-outline.svg';
import TrashIcon from './assets/icons/trash-outline.svg';
import WarningIcon from './assets/icons/warning-outline.svg';

import { applyTheme } from './theme';

applyTheme();

type RelayConfig = {
  url: string;
  policy: { read: boolean; write: boolean };
};

function Options() {
  let [selectedProfilePubKey, setSelectedProfilePubKey] = useState<string>('');
  let [profiles, setProfiles] = useState<ProfilesConfig>({});
  let [isLoadingProfile, setLoadingProfile] = useState(false);
  let [profileName, setProfileName] = useState<string>();
  let [profileExportJson, setProfileExportJson] = useState('');
  let [profileImportJson, setProfileImportJson] = useState('');
  let [isRenameModalShown, setRenameModalShown] = useState(false);
  let [isExportModalShown, setExportModalShown] = useState(false);
  let [isImportModalShown, setImportModalShown] = useState(false);

  let [privateKey, setPrivateKey] = useState<string>('');
  let [isKeyHidden, setKeyHidden] = useState(true);
  let [relays, setRelays] = useState<RelayConfig[]>([]);
  let [newRelayURL, setNewRelayURL] = useState('');
  let [isNewRelayURLValid, setNewRelayURLValid] = useState(true);
  // Derived from the stored profile on every render, not kept as a copy. The copy was loaded once,
  // so a revoked site stayed in this table — and anything written from it put the grant back.
  const permissions = convertPermissionsToUIObject(profiles[selectedProfilePubKey]?.permissions);
  let [message, setMessage] = useState('');
  let [messageType, setMessageType] = useState('info');

  let [version, setVersion] = useState('0.0.0');
  let [pinEnabled, setPinEnabled] = useState(false);
  let [pinKind, setPinKind] = useState<'pin' | 'passphrase'>('pin');
  let [pinCacheDuration, setPinCacheDuration] = useState<number>(10 * 1000); // Default: 10 seconds
  let [theme, setTheme] = useState<'system' | 'light' | 'dark'>('system');
  let [nostrLinkHandlerUrl, setNostrLinkHandlerUrl] = useState('');
  let [isNostrLinkHandlerUrlValid, setNostrLinkHandlerUrlValid] = useState(true);

  /**
   * Load options from Storage
   */
  useEffect(() => {
    Storage.readProfiles().then(profiles => {
      if (profiles) {
        setProfiles(profiles);

        // load selected profile
        let selectedPubKey = Object.keys(profiles)[0];
        if (selectedProfilePubKey != '') {
          // there is an selected public key
          selectedPubKey = selectedProfilePubKey;
          console.debug(`Already selected public key`);
        }

        console.debug('Selected pub key to be loaded', selectedPubKey);
        // this call will load the profile in the screen
        setSelectedProfilePubKey(selectedPubKey);
      }
    });
  }, []);

  /**
   * Keep the profiles in step with storage. The background grants sites while this page is open,
   * and a revoke is written by the storage layer, not here. Without this the page showed whatever
   * it loaded when it opened. A "(new profile)" still being set up exists only on this page, so it is
   * carried across.
   */
  useEffect(() => {
    const listener = (changes: Record<string, browser.Storage.StorageChange>, area: string) => {
      if (area !== 'local') return;
      if (changes[ConfigurationKeys.PROFILES]) {
        const fresh = (changes[ConfigurationKeys.PROFILES].newValue ?? {}) as ProfilesConfig;
        setProfiles(current => ('' in current ? { ...fresh, '': current[''] } : fresh));
      }
      // Protection is switched in the PIN window, which takes as long as the user takes. This page
      // used to look once, a second after opening it, and usually looked before anything happened.
      if (changes[ConfigurationKeys.PIN_ENABLED]) {
        const enabled = !!changes[ConfigurationKeys.PIN_ENABLED].newValue;
        setPinEnabled(enabled);
        // An encrypted key cannot be shown, so whatever the field held goes.
        if (enabled) setPrivateKey('');
      }
      if (changes[ConfigurationKeys.PIN_KIND]) {
        setPinKind(changes[ConfigurationKeys.PIN_KIND].newValue === 'passphrase' ? 'passphrase' : 'pin');
      }
    };
    browser.storage.onChanged.addListener(listener);
    return () => browser.storage.onChanged.removeListener(listener);
  }, []);

  /**
   * Initialization
   */
  useEffect(() => {
    fetch('./manifest.json')
      .then(response => response.json())
      .then(json => setVersion(json.version));

    // Check PIN protection status
    Storage.isPinEnabled().then(enabled => {
      setPinEnabled(enabled);
    });
    Storage.getPinKind().then(setPinKind);

    // Load PIN cache duration
    Storage.getTheme().then(setTheme);
    Storage.getPinCacheDuration().then(duration => {
      setPinCacheDuration(duration);
    });

    Storage.getNostrLinkHandlerUrlTemplate().then(template => {
      setNostrLinkHandlerUrl(template);
    });
  }, []);

  /**
   * When relays are updated
   */
  useEffect(() => {
    if (isLoadingProfile) return;

    saveRelaysInStorage()
      ?.then(() => console.log('Relays stored.'))
      .catch(err => console.error('Error storing relays', err));
  }, [relays]);

  const saveNostrLinkHandlerUrl = useDebouncedCallback(async (template: string) => {
    const trimmed = template.trim();
    if (trimmed && !isValidNostrLinkHandlerTemplate(trimmed)) {
      setNostrLinkHandlerUrlValid(false);
      return;
    }

    setNostrLinkHandlerUrlValid(true);
    await Storage.setNostrLinkHandlerUrlTemplate(trimmed);
    showMessage(
      trimmed ? 'Nostr link handler saved' : 'Nostr link handler disabled',
      'success'
    );
  }, 700);

  /**
   * When selected public key changes
   */
  useEffect(() => {
    loadAndSelectProfile(selectedProfilePubKey);
  }, [selectedProfilePubKey]);

  const showMessage: (
    msg: string,
    type?: 'info' | 'success' | 'warning',
    timeout?: number
  ) => void = useCallback((msg, type = 'info', timeout = 3000) => {
    setMessageType(type);
    setMessage(msg);
    if (timeout > 0) {
      setTimeout(setMessage, 3000);
    }
  }, []);

  //#region Profiles

  async function loadAndSelectProfile(pubKey: string) {
    const profile: ProfileConfig = profiles[pubKey];
    if (!profile) {
      console.warn(`The profile for pubkey '${pubKey}' does not exist.`);
      return;
    }
    setLoadingProfile(true);
    setProfileName(profile.name);
    setRelays(convertRelaysToUIArray(profile.relays));

    // Always check current PIN status when loading profile
    const currentPinEnabled = await Storage.isPinEnabled();
    setPinEnabled(currentPinEnabled);
    setPrivateKey(formatPrivateKeyForDisplay(profile.privateKey || '', currentPinEnabled));

    setLoadingProfile(false);
    console.log(`The profile for pubkey '${pubKey}' was loaded.`);
  }

  // The private key field accepts hex or nsec, so anything reading it has to normalise the same
  // way savePrivateKey does rather than assume one of the two.
  function privateKeyBytes(): Uint8Array | null {
    if (!privateKey || !isKeyValid()) return null;
    if (isHexadecimal(privateKey)) return convertHexToUint8Array(privateKey);
    try {
      const { type, data } = nip19.decode(privateKey);
      return type === 'nsec' ? (data as Uint8Array) : null;
    } catch (e) {
      return null;
    }
  }

  // The public key is the identity: it is what you paste into a client, what you hand to somebody
  // who wants to find you, and what you check when you are not sure which profile is selected.
  // Until now this page showed the private key in a field and never showed the public one at all,
  // which is the wrong way round. A saved profile knows its own; an unsaved one is derived from
  // whatever is in the key field, so the npub appears as soon as there is a key to derive it from.
  function selectedNpub(): string {
    let hex = selectedProfilePubKey;
    if (!hex) {
      const bytes = privateKeyBytes();
      if (bytes) hex = derivePublicKeyFromPrivateKey(convertUint8ArrayToHex(bytes));
    }
    try {
      return hex ? nip19.npubEncode(hex) : '';
    } catch (e) {
      return '';
    }
  }

  async function copyNpub() {
    try {
      await navigator.clipboard.writeText(selectedNpub());
    } catch (e) {
      console.error('Could not copy the public key.', e);
    }
  }

  // The confirmation is not there to slow anybody down — it is there because the risk is not the
  // click, it is where the key goes afterwards. A clipboard manager keeps a history, on disk, and a
  // private key that lands in it stays there long after the paste it was meant for.
  //
  // Deliberately not cleared on a timer: checking whether the clipboard still holds the key needs
  // the clipboardRead permission, and adding a permission to a signer in order to implement a
  // mitigation a clipboard manager has already outrun is a bad trade. Say what happens instead.
  async function copyNsec() {
    const bytes = privateKeyBytes();

    // With PIN protection on there is nothing in the field to copy — an encrypted key cannot be
    // displayed — so the decryption happens in the PIN window instead. This page deliberately
    // never receives the key: it only asks for that window to be opened.
    if (!bytes && pinEnabled) {
      const response = (await browser.runtime.sendMessage({
        type: 'openPinPrompt',
        mode: 'copy'
      })) as { success: boolean; error?: string };
      if (response && !response.success) {
        showMessage(response.error || 'Could not open the PIN prompt', 'warning');
      }
      return;
    }

    if (!bytes) return;
    const ok = window.confirm(
      'Copy the private key to the clipboard?\n\n' +
        'Anything that can read your clipboard can read it, and a clipboard manager will keep a ' +
        'copy in its history — on disk, often for a long time.\n\n' +
        'Paste it where you need it, then copy something else. To store it, use Export instead.'
    );
    if (!ok) return;
    try {
      await navigator.clipboard.writeText(nip19.nsecEncode(bytes));
    } catch (e) {
      console.error('Could not copy the private key.', e);
    }
  }

  function handleSelectedProfileChange(event) {
    const pubKey = event.target.value;
    setSelectedProfilePubKey(pubKey);
    // loadProfile(pubKey);
  }

  function handleNewProfileClick(event) {
    const newProfile: ProfileConfig = {
      privateKey: ''
    };
    setProfiles({ ...profiles, ...{ ['']: newProfile } });
    setSelectedProfilePubKey('');

    setRelays([]);
    setPrivateKey('');
  }

  function isNewProfilePending() {
    return Object.keys(profiles).includes('');
  }

  function getSelectedProfile(): ProfileConfig | null {
    if (selectedProfilePubKey) {
      return profiles[selectedProfilePubKey];
    } else {
      return null;
    }
  }

  function handleProfileRenameClick() {
    const profile = getSelectedProfile();
    if (profile) {
      setProfileName(profile.name);
      setRenameModalShown(true);
    }
  }
  function handleProfileNameChange(e) {
    setProfileName(e.target.value);
  }
  async function handleProfileRenameConfirm() {
    const profile = getSelectedProfile();
    const name = profileName?.trim() || undefined;
    // Only the name is written. This used to hand the storage layer this page's copy of the whole
    // profile, loaded when the page opened, and a site revoked since was back the moment you renamed.
    if (profile && name !== profile.name) {
      await Storage.renameProfile(selectedProfilePubKey, name);
    }
    setRenameModalShown(false);
  }
  function handleProfileRenameModalClose() {
    setRenameModalShown(false);
  }

  async function handleExportProfileClick() {
    // From storage, so the export carries what is stored now rather than what this page last saw.
    const profile = selectedProfilePubKey ? await Storage.getProfile(selectedProfilePubKey) : null;
    const profileJson = JSON.stringify(profile);
    setProfileExportJson(profileJson);
    setExportModalShown(true);
  }

  function handleExportProfileCopyClick() {
    navigator.clipboard.writeText(profileExportJson);
  }

  function handleExportModalClose() {
    setExportModalShown(false);
  }

  function handleImportProfileClick() {
    setImportModalShown(true);
  }

  function handleChangeProfileImportJson(e) {
    setProfileImportJson(e.target.value);
  }

  async function handleImportProfileImportClick() {
    let newProfile: ProfileConfig;
    // validations
    try {
      newProfile = JSON.parse(profileImportJson);
    } catch (error) {
      console.warn(`Error parsing the entered JSON`, error);
      showMessage(`There was an error parsing the JSON. ${error.message}`, 'warning');
      return;
    }
    if (!newProfile) {
      console.warn(`The imported profile is empty.`);
      showMessage(`The imported profile is invalid.`, 'warning');
      return;
    }
    // A profile exported before 1.25.0 keys its permissions on bare hosts. They are moved to
    // origins the same way stored ones were, or they would sit in the table matching nothing.
    newProfile.permissions = migratePermissionKeys(newProfile.permissions);

    // Determine public key before storing
    const pinEnabled = await Storage.isPinEnabled();
    const existingProfiles = await Storage.readProfiles();
    let newPubKey: string;

    if (!canDerivePublicKeyFromPrivateKey(newProfile.privateKey, pinEnabled)) {
      // PIN enabled and private key is encrypted - can't derive public key
      // Try to find existing profile with same encrypted key, or require public key
      const matchingProfile = Object.entries(existingProfiles).find(
        ([_, p]) => p.privateKey === newProfile.privateKey
      );

      if (matchingProfile) {
        newPubKey = matchingProfile[0];
      } else {
        showMessage(
          'Cannot import profile with encrypted private key without public key. Please decrypt first or provide public key.',
          'warning'
        );
        return;
      }
    } else {
      // Derive public key from plain-text private key
      newPubKey = derivePublicKeyFromPrivateKey(newProfile.privateKey);
    }

    const duplicatePubKey = findExistingProfileByPrivateKey(
      newProfile.privateKey,
      existingProfiles,
      pinEnabled,
      newPubKey
    );
    if (duplicatePubKey) {
      const existingProfile = existingProfiles[duplicatePubKey];
      const profileLabel = existingProfile?.name
        ? `"${existingProfile.name}"`
        : nip19.npubEncode(duplicatePubKey);
      if (
        !window.confirm(
          `A profile with this private key already exists (${profileLabel}). Import anyway? This will overwrite the existing profile.`
        )
      ) {
        return;
      }
    }

    // If PIN protection is enabled, encrypt the private key before saving
    if (pinEnabled && newProfile.privateKey && !isPrivateKeyEncrypted(newProfile.privateKey)) {
      try {
        const encryptResponse: { success: boolean; encryptedKey?: string; error?: string } =
          (await browser.runtime.sendMessage({
            type: 'encryptPrivateKey',
            privateKey: newProfile.privateKey
          })) as any;

        if (!encryptResponse || !encryptResponse.success) {
          showMessage(
            encryptResponse?.error ||
              'Failed to encrypt private key. PIN is required when PIN protection is enabled.',
            'warning'
          );
          return;
        }

        if (!encryptResponse.encryptedKey) {
          showMessage('Failed to encrypt private key: no encrypted key returned', 'warning');
          return;
        }

        newProfile.privateKey = encryptResponse.encryptedKey;
      } catch (error) {
        console.error('Error encrypting private key:', error);
        showMessage('Failed to encrypt private key. ' + error.message, 'warning');
        return;
      }
    }

    // store the new profile
    await Storage.addProfile(newProfile, newPubKey);

    setProfiles({ ...profiles, ...{ [newPubKey]: newProfile } });

    // now load in the component
    setPrivateKey(formatPrivateKeyForDisplay(newProfile.privateKey || '', pinEnabled));
    setSelectedProfilePubKey(newPubKey);

    setImportModalShown(false);
  }

  function handleImportModalClose() {
    setImportModalShown(false);
  }

  async function handleDeleteProfileClick(e) {
    e.preventDefault();
    // A "(new profile)" that was never saved has nothing in storage and no public key. Delete named
    // it for the confirmation by the npub of an empty key — a string that belongs to nobody — and
    // asked whether to delete that. There is nothing to delete; discarding it is all this means.
    if (!selectedProfilePubKey) {
      const { ['']: _unsaved, ...saved } = profiles;
      setProfiles(saved);
      setPrivateKey('');
      setRelays([]);
      setSelectedProfilePubKey(Object.keys(saved)[0] ?? '');
      return;
    }
    if (window.confirm(`Delete the profile "${nip19.npubEncode(selectedProfilePubKey)}"?`)) {
      const updatedProfiles = await Storage.deleteProfile(selectedProfilePubKey);
      setProfiles({ ...updatedProfiles });

      // if no profiles left, set the default values
      const remainingKeys = Object.keys(updatedProfiles);
      if (remainingKeys.length === 0) {
        setSelectedProfilePubKey('');
        setRelays([]);
        setPrivateKey('');
        return;
      }

      const activePublicKey = await Storage.getActivePublicKey();
      setSelectedProfilePubKey(
        activePublicKey && activePublicKey in updatedProfiles ? activePublicKey : remainingKeys[0]
      );
    }
  }

  //#endregion Profiles

  //#region Private key

  async function savePrivateKey() {
    if (!isKeyValid()) return;

    if (privateKey == '') {
      console.warn("Won't save an empty private key");
      return;
    }

    let privateKeyIntArray: Uint8Array | undefined = undefined;

    if (isHexadecimal(privateKey)) {
      privateKeyIntArray = convertHexToUint8Array(privateKey);
    } else {
      try {
        let { type, data } = nip19.decode(privateKey);
        if (type === 'nsec') privateKeyIntArray = data as Uint8Array;
      } catch (err) {
        console.error('Converting key to hexa (decode NIP19)', err);
      }
    }

    if (privateKeyIntArray) {
      const hexPrivateKey = convertUint8ArrayToHex(privateKeyIntArray);
      const newPubKey = derivePublicKeyFromPrivateKey(hexPrivateKey);

      // Saving a key that already has a profile replaces that profile: its name, its relays, every
      // site decision on it. Import has always asked first; this did it without a word.
      const existing = (await Storage.readProfiles())[newPubKey];
      if (
        existing &&
        !window.confirm(
          `A profile with this key already exists (${
            existing.name ? `"${existing.name}"` : nip19.npubEncode(newPubKey)
          }). Saving replaces it, including its relays and site permissions. Continue?`
        )
      ) {
        return;
      }

      setPrivateKey(nip19.nsecEncode(privateKeyIntArray));
      let storedKey = hexPrivateKey;

      // If PIN protection is enabled, encrypt the private key before saving
      const pinEnabled = await Storage.isPinEnabled();
      if (pinEnabled) {
        try {
          // Request background script to encrypt the key (it will prompt for PIN if needed)
          const encryptResponse: { success: boolean; encryptedKey?: string; error?: string } =
            (await browser.runtime.sendMessage({
              type: 'encryptPrivateKey',
              privateKey: hexPrivateKey
            })) as any;

          if (!encryptResponse || !encryptResponse.success) {
            showMessage(
              encryptResponse?.error ||
                'Failed to encrypt private key. PIN is required when PIN protection is enabled.',
              'warning'
            );
            return;
          }

          if (!encryptResponse.encryptedKey) {
            showMessage('Failed to encrypt private key: no encrypted key returned', 'warning');
            return;
          }

          // Use the encrypted key
          storedKey = encryptResponse.encryptedKey;
        } catch (error) {
          console.error('Error encrypting private key:', error);
          showMessage('Failed to encrypt private key. ' + error.message, 'warning');
          return;
        }
      }

      // Only the new profile is written. This used to save this page's copy of every profile, as
      // loaded when the page opened, which put back any site revoked since — on every profile.
      await Storage.addProfile({ privateKey: storedKey }, newPubKey);
      setProfiles(await Storage.readProfiles());
      setSelectedProfilePubKey(newPubKey); // this re-loads the profile in the screen
      showMessage('Saved private key!', 'success');
    } else {
      // Reached when the text passed the format check but would not decode. Saying "Saved" here
      // told people their key was stored when nothing had been written at all.
      console.warn('Could not read that private key; nothing was saved.');
      showMessage('That key could not be read, so nothing was saved.', 'warning');
    }
  }

  function isKeyValid() {
    return validatePrivateKeyFormat(privateKey);
  }

  async function handlePrivateKeyChange(e) {
    let key = e.target.value.toLowerCase().trim();
    setPrivateKey(key);
  }

  async function generateRandomPrivateKey() {
    setPrivateKey(nip19.nsecEncode(generateSecretKey()));
  }

  function handlePrivateKeyShowClick() {
    setKeyHidden(!isKeyHidden);
  }

  // theme state lives with the other settings
  async function handleThemeChange(e) {
    const t = e.target.value;
    setTheme(t);
    await Storage.setTheme(t);
  }

  async function handleProtectWithPinClick() {
    const mode = pinEnabled ? 'disable' : 'setup';
    try {
      // The storage listener picks up the result, whenever the window is done with.
      await browser.runtime.sendMessage({
        type: 'openPinPrompt',
        mode
      });
    } catch (error) {
      console.error('Error opening PIN prompt:', error);
    }
  }

  async function handlePinCacheDurationChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const duration = parseInt(e.target.value, 10);
    setPinCacheDuration(duration);
    await Storage.setPinCacheDuration(duration);
    showMessage('PIN cache duration updated', 'success');
  }
  //#endregion Private key

  //#region Permissions

  function convertPermissionsToUIObject(permissions?: PermissionConfig) {
    if (!permissions) return undefined;

    // One row per remembered decision; a site can hold one at each permission level.
    return Object.entries(permissions)
      .flatMap(([host, value]) =>
        entriesOf(value).map(({ level, condition, created_at, duration_seconds, decision }) => ({
          host,
          level,
          condition,
          created_at,
          duration_seconds,
          decision
        }))
      )
      .sort((a, b) => {
        // rejections first: a site that is being refused never prompts again, so this
        // page is the only place the decision can be undone
        const aDenied = a.decision === PermissionDecision.DENY ? 0 : 1;
        const bDenied = b.decision === PermissionDecision.DENY ? 0 : 1;
        return aDenied - bDenied || b.created_at - a.created_at;
      });
  }

  async function handleRevoke(e) {
    e.preventDefault();
    const { domain: host, decision } = e.target.dataset;
    const level = Number(e.target.dataset.level);
    const isDenied = decision === PermissionDecision.DENY;
    // One row, one decision: the others this site holds stay as they are.
    const question = isDenied
      ? `Let ${host} ask again to ${getPermissionsString(level)}?`
      : `Revoke this permission from ${host}?`;

    if (window.confirm(question)) {
      await Storage.removePermissions(selectedProfilePubKey, host, level);
      // The table follows storage on its own; reloading the profile here would also reset the relays.
      showMessage(isDenied ? `${host} can ask again` : `Removed permissions from ${host}`);
    }
  }

  //#endregion Permissions

  //#region Relays

  function convertRelaysToUIArray(relays?: RelaysConfig) {
    if (!relays) return [];

    let relaysList: RelayConfig[] = [];
    for (let url in relays) {
      relaysList.push({
        url,
        policy: relays[url]
      });
    }

    return relaysList;
  }

  const saveRelaysInStorage = useDebouncedCallback(async () => {
    // if there is a selected profile
    if (selectedProfilePubKey) {
      let relaysToSave = {};
      if (relays && relays.length) {
        relaysToSave = Object.fromEntries(
          relays
            .filter(({ url }) => url.trim() !== '')
            .map(({ url, policy }) => [url.trim(), policy])
        );
      }
      console.debug('Relays to save', relaysToSave);
      await Storage.updateRelays(selectedProfilePubKey, relaysToSave);

      showMessage('Saved relays!', 'success');
    }
  }, 700);

  function handleChangeRelayURL(i, ev) {
    setRelays([
      ...relays.slice(0, i),
      { url: ev.target.value, policy: relays[i].policy },
      ...relays.slice(i + 1)
    ]);
  }

  function handleToggleRelayPolicy(i, cat) {
    setRelays([
      ...relays.slice(0, i),
      {
        url: relays[i].url,
        policy: { ...relays[i].policy, [cat]: !relays[i].policy[cat] }
      },
      ...relays.slice(i + 1)
    ]);
  }

  function handleNewRelayURLChange(e) {
    setNewRelayURL(e.target.value);
    if (!isRelayURLValid(e.target.value)) {
      setNewRelayURLValid(false);
    }
  }

  function handleAddRelayClick() {
    if (!isRelayURLValid()) {
      return;
    }

    setNewRelayURLValid(true);
    setRelays([
      ...relays,
      {
        url: newRelayURL,
        policy: { read: true, write: true }
      }
    ]);
    setNewRelayURL('');
  }

  function handleRemoveRelayClick(event: React.MouseEvent<HTMLButtonElement>) {
    const relayUrl = event.currentTarget.id;
    const newRelays = relays.filter(relay => relay.url != relayUrl);
    setRelays(newRelays);
  }

  /**
   * Check if the URL is valid. If no URL is provided is taken from the state
   * @param url Url to check.
   * @returns
   */
  function isRelayURLValid(url?: string) {
    const urlToCheck = url ? url : newRelayURL;
    return isValidRelayURL(urlToCheck);
  }

  //#endregion Relays

  function handleNostrLinkHandlerUrlChange(e: React.ChangeEvent<HTMLInputElement>) {
    const value = e.target.value;
    setNostrLinkHandlerUrl(value);
    const valid = !value.trim() || isValidNostrLinkHandlerTemplate(value);
    setNostrLinkHandlerUrlValid(valid);
    if (valid) {
      saveNostrLinkHandlerUrl(value);
    }
  }

  async function handleClearStorageClick() {
    if (confirm('Are you sure you want to delete everything from this browser?')) {
      await Storage.empty();
      // reload the page
      window.location.reload();
    }
  }

  return (
    <>
      <header className="header">
        <h1>
          <Logotype className="logotype" role="img" aria-label="Attest" />
        </h1>
        <p>nostr signer extension</p>
      </header>
      <main>
        <h2>Options</h2>
        {message && <Alert message={message} type={messageType} />}

        <section>
          <h3>Profile</h3>
          <div className="form-field">
            <label htmlFor="selected-profile">Selected profile:</label>
            <div id="selected-profile">
              <select value={selectedProfilePubKey} onChange={handleSelectedProfileChange}>
                {Object.keys(profiles).map(profilePubKey => (
                  <option value={profilePubKey} key={profilePubKey}>
                    {profilePubKey == ''
                      ? '(new profile)'
                      : (profiles[profilePubKey].name ??
                        truncatePublicKeys(nip19.npubEncode(profilePubKey), 20, 20))}
                  </option>
                ))}
              </select>
              <button disabled={isNewProfilePending()} onClick={handleProfileRenameClick}>
                <PencilIcon />
                Rename
              </button>
            </div>
          </div>
          <div className="form-field">
            <label htmlFor="public-key">Public key:</label>
            <div className="input-group">
              <input id="public-key" type="text" readOnly value={selectedNpub()} placeholder="no key yet" />
              <button onClick={copyNpub} disabled={!selectedNpub()} title="Copy the public key to the clipboard">
                <CopyIcon /> Copy
              </button>
            </div>
          </div>
          <div className="profile-actions">
            <button disabled={isNewProfilePending()} onClick={handleNewProfileClick}>
              <AddCircleIcon />
              New
            </button>
            <button onClick={handleExportProfileClick}>
              <DownloadIcon />
              Export
            </button>
            <button onClick={handleImportProfileClick}>
              <ArrowUpCircleIcon />
              Import
            </button>
            <button onClick={handleDeleteProfileClick} className="button button-danger">
              <TrashIcon />
              Delete
            </button>
          </div>
        </section>

        <section>
          <h3>Keys</h3>
          {/* The field is read-only while a saved profile is selected, and that is right: replacing
              a stored key is not an edit, it is a different identity, and doing it in place is how
              somebody loses the only copy of one. But a greyed-out box that says nothing is a dead
              end — you click it, nothing happens, and there is no way to guess that the way in is a
              button in another section. */}
          <p className="text-help">
            {selectedProfilePubKey
              ? 'This profile\u2019s key cannot be changed here. To add another identity — pasting an nsec you already have, or generating a new one — click New under Profile.'
              : 'Paste an nsec or a hex private key, or press Generate for a new one. Check the public key above before saving.'}
          </p>
          <div className="form-field">
            <label htmlFor="private-key">Private key:</label>
            <div className="input-group">
              <input
                id="private-key"
                type={isKeyHidden ? 'password' : 'text'}
                value={privateKey}
                readOnly={selectedProfilePubKey != ''}
                title={
                  selectedProfilePubKey
                    ? 'Saved keys cannot be edited. Click New under Profile to add another.'
                    : 'Paste an nsec or a hex private key'
                }
                onChange={handlePrivateKeyChange}
              />
              <button onClick={handlePrivateKeyShowClick}>
                {isKeyHidden ? <EyeIcon /> : <EyeOffIcon />}
              </button>
              {/* Not `!isKeyValid()`: an empty field counts as valid — that is what lets somebody
                  clear the box and type a new key. With PIN protection on there is nothing in the
                  box at all, because an encrypted key cannot be displayed, so the button used to
                  sit there enabled and do nothing whatsoever when clicked. No dialog, no message,
                  no console line. Ask what there is to copy instead. */}
              <button
                onClick={copyNsec}
                disabled={!privateKeyBytes() && !pinEnabled}
                title={
                  privateKeyBytes()
                    ? 'Copy the private key to the clipboard'
                    : pinEnabled
                      ? 'Enter your PIN or passphrase to copy this key to the clipboard'
                      : 'There is no key here to copy'
                }
              >
                <CopyIcon />
              </button>
              <button disabled={selectedProfilePubKey != ''} onClick={generateRandomPrivateKey}>
                <DiceIcon /> Generate
              </button>
            </div>
          </div>
          <button
            disabled={!privateKey || !isKeyValid() || selectedProfilePubKey != ''}
            onClick={savePrivateKey}
            title={privateKey ? 'Save this key' : 'Paste or generate a key first'}
          >
            Save key
          </button>

          <h4 className="mb-0">PIN or passphrase</h4>
          <p className="text-help">
            When on, ALL your private keys are encrypted, and you are asked for your PIN or
            passphrase whenever the extension needs a key. It is then kept for the duration you
            select below — in memory only, and never past closing Firefox.
            <br />
            A passphrase protects your keys even from somebody who copies your Firefox profile. A
            PIN does not: every PIN of 4 to 6 digits can be tried in minutes. A PIN stops somebody
            using this browser, and no more.
          </p>
          <div className="form-field mt-2">
            <div className="input-group">
              <button onClick={handleProtectWithPinClick}>
                {pinEnabled ? 'Turn protection off' : 'Turn protection on'}
              </button>
              <select
                id="pin-cache-duration"
                value={pinCacheDuration}
                onChange={handlePinCacheDurationChange}
              >
                <option value={10 * 1000}>10 seconds</option>
                <option value={30 * 1000}>30 seconds</option>
                <option value={5 * 60 * 1000}>5 minutes</option>
                <option value={10 * 60 * 1000}>10 minutes</option>
                <option value={30 * 60 * 1000}>30 minutes</option>
                <option value={60 * 60 * 1000}>1 hour</option>
                <option value={4 * 60 * 60 * 1000}>4 hours</option>
                <option value={8 * 60 * 60 * 1000}>8 hours</option>
                {/* The honest ceiling. The PIN lives in a variable in the background page and
                    nowhere else, so it cannot survive the browser closing however long a number is
                    put here — offering days or months would promise something the code cannot do.
                    2^31-1 ms is also the largest delay setTimeout accepts. */}
                <option value={2147483647}>until Firefox closes</option>
              </select>
            </div>
          </div>
          {pinEnabled && (
            <>
              <p className="mt-1 pin-status-message">
                Your private keys are encrypted with a {pinKind === 'passphrase' ? 'passphrase' : 'PIN'}.
              </p>
              {pinKind === 'pin' && (
                <p className="text-help">
                  That keeps out somebody using this browser, not somebody who copies your Firefox
                  profile. To switch to a passphrase, turn protection off and on again.
                </p>
              )}
            </>
          )}
        </section>

        <section>
          <h3>Appearance</h3>
          <p className="text-help">
            Following the system is the default and is usually right. The override is here because
            it is sometimes not — a dark desktop with one light window in it, or the reverse.
          </p>
          <div className="form-field">
            <label htmlFor="theme">Theme:</label>
            <select id="theme" value={theme} onChange={handleThemeChange}>
              <option value="system">Follow the system</option>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
          </div>
        </section>

        <section>
          <h3>Permissions</h3>
          <p className="text-help">
            Decisions you asked this extension to remember. A rejected site is refused without
            showing a prompt, so this is the only place to let it ask again.
          </p>
          {permissions && permissions.length > 0 ? (
            <>
              <table>
                <thead>
                  <tr>
                    <th>Site</th>
                    <th>Decision</th>
                    <th>Permissions</th>
                    <th>Condition</th>
                    <th>Since</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {permissions.map(
                    ({ host, level, condition, created_at, duration_seconds, decision }) => (
                      <tr key={`${host} ${level}`}>
                        <td>{host}</td>
                        <td>{formatPermissionDecisionLabel(decision)}</td>
                        <td>{getPermissionsString(level)}</td>
                        <td>{formatPermissionConditionLabel(condition, duration_seconds)}</td>
                        <td
                          className="help-cursor"
                          title={formatDistance(new Date(created_at * 1000), new Date())}
                        >
                          {format(new Date(created_at * 1000), 'yyyy-MM-dd HH:mm:ss')}
                        </td>
                        <td>
                          <button
                            onClick={handleRevoke}
                            data-domain={host}
                            data-level={level}
                            data-decision={decision}
                          >
                            {decision === PermissionDecision.DENY ? 'unblock' : 'revoke'}
                          </button>
                        </td>
                      </tr>
                    )
                  )}
                </tbody>
              </table>
            </>
          ) : (
            <p>(No permissions defined)</p>
          )}
        </section>

        <section>
          <h3>Preferred relays</h3>
          <div className="relays-list">
            {relays.map(({ url, policy }, i) => (
              <div key={i} className="relays-list-item">
                <button
                  className="button-onlyicon button-remove"
                  onClick={handleRemoveRelayClick}
                  title="Remove"
                  id={url}
                >
                  <TrashIcon />
                </button>
                <RadioIcon />
                <input value={url} onChange={handleChangeRelayURL.bind(null, i)} />
                <label>
                  read
                  <input
                    type="checkbox"
                    checked={policy.read}
                    onChange={handleToggleRelayPolicy.bind(null, i, 'read')}
                  />
                </label>
                <label>
                  write
                  <input
                    type="checkbox"
                    checked={policy.write}
                    onChange={handleToggleRelayPolicy.bind(null, i, 'write')}
                  />
                </label>
              </div>
            ))}
          </div>
          <div className={`form-field ${!isNewRelayURLValid ? 'validation-error' : ''}`}>
            <label htmlFor="new-relay-url">New relay URL:</label>
            <input
              id="new-relay-url"
              placeholder="wss://..."
              value={newRelayURL}
              onChange={handleNewRelayURLChange}
            />
            <button disabled={!isRelayURLValid()} onClick={handleAddRelayClick}>
              Add relay
            </button>
          </div>
        </section>

        <section>
          <h3>Nostr links</h3>
          <p className="text-help">
            When set, clicking <code>nostr:</code> links opens the URL below. Use <code>%s</code>{' '}
            for the part after <code>nostr:</code> (for example, <code>https://iris.to/%s</code> or{' '}
            <code>http://localhost:3000/%s</code>). Leave blank to disable.
          </p>
          <div className={`form-field ${!isNostrLinkHandlerUrlValid ? 'validation-error' : ''}`}>
            <label htmlFor="nostr-link-handler-url">Handler URL template:</label>
            <input
              id="nostr-link-handler-url"
              placeholder="https://iris.to/%s"
              value={nostrLinkHandlerUrl}
              onChange={handleNostrLinkHandlerUrlChange}
            />
          </div>
        </section>

        <section className="danger">
          <button className="button button-danger" onClick={handleClearStorageClick}>
            <WarningIcon />
            Delete configuration
            <WarningIcon />
          </button>
        </section>
      </main>
      <footer>version {version}</footer>

      <Modal
        show={isRenameModalShown}
        className="rename-modal"
        onClose={handleProfileRenameModalClose}
      >
        <div className="form-field">
          <label htmlFor="profile-name">Profile name:</label>
          <input
            id="profile-name"
            type="text"
            value={profileName ?? ''}
            onChange={handleProfileNameChange}
          />
        </div>
        <button onClick={handleProfileRenameConfirm}>Save</button>
      </Modal>

      <Modal show={isExportModalShown} className="export-modal" onClose={handleExportModalClose}>
        <p>
          This is the JSON that represents your profile (WARNING: it contains your private key):
        </p>
        <code>{profileExportJson}</code>
        <button onClick={handleExportProfileCopyClick}>
          <CopyIcon /> Copy
        </button>
      </Modal>

      <Modal show={isImportModalShown} className="import-modal" onClose={handleImportModalClose}>
        <p>Paste the profile JSON in the following box:</p>
        <textarea value={profileImportJson} onChange={handleChangeProfileImportJson}></textarea>
        <button onClick={handleImportProfileImportClick}>Import</button>
      </Modal>
    </>
  );
}

const root = createRoot(document.getElementById('main'));
root.render(<Options />);
