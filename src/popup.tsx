import browser from 'webextension-polyfill';
import { createRoot } from 'react-dom/client';
import { getPublicKey, generateSecretKey, nip19 } from 'nostr-tools';
import React, { useState, useEffect } from 'react';

import { ProfilesConfig } from './types';
import * as Storage from './storage';
import { convertHexToUint8Array, convertUint8ArrayToHex, truncatePublicKeys } from './common';

import logotype from './assets/logo/logotype.png';
import CopyIcon from './assets/icons/copy-outline.svg';
import CogIcon from './assets/icons/cog-outline.svg';
import AddCircleIcon from './assets/icons/add-circle-outline.svg';
import DownloadIcon from './assets/icons/download-outline.svg';
import CheckmarkCircleIcon from './assets/icons/checkmark-circle-outline.svg';

function Popup() {
  let [publicKeyHexa, setPublicKeyHexa] = useState<string>();
  let [publiKeyNIP19, setPublicKeyNIP19] = useState<string>();
  let [selectedKeyType, setSelectedKeyType] = useState('npub');
  let [profiles, setProfiles] = useState<ProfilesConfig>({});
  let [signerEnabled, setSignerEnabled] = useState<boolean>(true);
  let [isBackupPending, setBackupPending] = useState(false);
  let [profileName, setProfileName] = useState('');
  let [isCreatingKey, setCreatingKey] = useState(false);

  useEffect(() => {
    Storage.isSignerEnabled().then(setSignerEnabled);
    Promise.all([Storage.isKeyBackupPending(), Storage.isPinEnabled()]).then(
      ([pending, pinEnabled]) => setBackupPending(pending && !pinEnabled)
    );
  }, []);

  useEffect(() => {
    async function loadActiveProfile() {
      // Always use stored active public key (it's always saved now)
      const activePublicKey = await Storage.getActivePublicKey();
      if (activePublicKey) {
        setPublicKeyHexa(activePublicKey);
      } else {
        setPublicKeyHexa(undefined);
        setPublicKeyNIP19(undefined);
      }
    }

    loadActiveProfile();

    Storage.readProfiles().then(profiles => {
      if (profiles) {
        setProfiles(profiles);
      }
    });
  }, []);

  /**
   * When active public key changes
   */
  useEffect(() => {
    if (publicKeyHexa) {
      setPublicKeyNIP19(nip19.npubEncode(publicKeyHexa));

      Storage.readActiveRelays().then(relays => {
        if (relays) {
          let relaysList: string[] = [];
          for (let url in relays) {
            if (relays[url].write) {
              relaysList.push(url);
              if (relaysList.length >= 3) break;
            }
          }
        }
      });

      console.log(`The profile for pubkey '${publicKeyHexa}' was loaded.`);
    }
  }, [publicKeyHexa]);

  function handleKeyTypeSelect(event) {
    setSelectedKeyType(event.target.value);
  }

  async function handleSignerEnabledChange(event) {
    const enabled = event.target.checked;
    setSignerEnabled(enabled);
    await Storage.setSignerEnabled(enabled);
  }

  /** One click from an empty extension to a usable identity. */
  async function handleCreateKey() {
    if (isCreatingKey) return;
    setCreatingKey(true);
    try {
      const privateKey = convertUint8ArrayToHex(generateSecretKey());
      await Storage.createFirstProfile(privateKey);

      setPublicKeyHexa(await Storage.getActivePublicKey());
      setProfiles(await Storage.readProfiles());
      setBackupPending(true);
    } catch (err) {
      console.error('Could not create the key.', err);
    } finally {
      setCreatingKey(false);
    }
  }

  /** The plain-text key, available only while PIN protection is off. */
  async function readSecretKeyNsec(): Promise<string> {
    const privateKey = await Storage.readActivePrivateKey();
    if (!privateKey) throw new Error('No private key stored');
    return nip19.nsecEncode(convertHexToUint8Array(privateKey));
  }

  async function handleCopySecretKey() {
    try {
      await navigator.clipboard.writeText(await readSecretKeyNsec());
    } catch (err) {
      console.error('Could not copy the secret key.', err);
    }
  }

  async function handleDownloadSecretKey() {
    try {
      const nsec = await readSecretKeyNsec();
      const url = URL.createObjectURL(new Blob([nsec], { type: 'text/plain' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = 'nostr-secret-key.txt';
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Could not download the secret key.', err);
    }
  }

  async function handleBackupDone() {
    await Storage.setKeyBackupPending(false);
    setBackupPending(false);
  }

  // A popup closes the moment you click outside it, and everything typed into it goes with it.
  // Nobody expects that of a text field, and there is no warning — you look back later and the
  // profile is called npub1… again.
  //
  // Debounced rather than saved on every keystroke: a name is worth one write when you stop
  // typing, not one per letter, and half-typed labels have no business in storage. The name is a
  // local label for switching keys — the background never reads it, and nothing signs or publishes
  // it — so a value that lags the field by half a second costs nothing.
  //
  // The Save button needs no change to become the confirmation: it already disables itself when
  // what is in the field matches what is stored, so it greys out the moment this lands.
  useEffect(() => {
    const name = profileName.trim();
    if (!name || !publicKeyHexa) return;
    if (profiles[publicKeyHexa]?.name === name) return;
    const t = setTimeout(() => { handleProfileNameSave(); }, 500);
    return () => clearTimeout(t);
  }, [profileName, publicKeyHexa]);

  async function handleProfileNameSave() {
    const name = profileName.trim();
    if (!name || !publicKeyHexa) return;

    const profile = profiles[publicKeyHexa];
    if (!profile) return;

    profile.name = name;
    await Storage.updateProfile(profile, publicKeyHexa);
    setProfiles({ ...profiles, [publicKeyHexa]: profile });
  }

  function goToOptionsPage() {
    browser.tabs
      .create({
        url: browser.runtime.getURL('options.html'),
        active: true
      })
      .then(() => {
        window.close();
      });
  }

  async function handleProfileChange(event) {
    const pubKey = event.target.value;
    setPublicKeyHexa(pubKey);
    const profile = profiles[pubKey];
    if (!profile) {
      console.warn(`The profile for pubkey '${pubKey}' does not exist.`);
      return;
    }

    // Always update active public key first
    await Storage.setActivePublicKey(pubKey);

    // Then update private key based on PIN status
    const pinEnabled = await Storage.isPinEnabled();
    if (pinEnabled) {
      // When PIN protection is enabled, update encrypted private key
      if (profile.privateKey) {
        await Storage.setEncryptedPrivateKey(profile.privateKey);
      }
    } else {
      // When PIN protection is disabled, update active private key
      await Storage.updateActivePrivateKey(profile.privateKey);
    }
  }

  function clipboardCopyPubKey() {
    navigator.clipboard.writeText(
      (selectedKeyType === 'hex' ? publicKeyHexa : publiKeyNIP19) ?? ''
    );
  }

  return (
    <>
      <h1>
        <img src={logotype} alt="Attest" />
      </h1>
      <div className="signer-switch">
        <label className="switch">
          <input type="checkbox" checked={signerEnabled} onChange={handleSignerEnabledChange} />
          <span className="switch-slider" />
        </label>
        <span className="signer-switch-label">
          {signerEnabled ? 'Enabled' : 'Disabled'}
          <small>
            {signerEnabled
              ? 'Websites can request signatures.'
              : 'All website requests are refused.'}
          </small>
        </span>
      </div>
      {!publicKeyHexa ? (
        <div className="onboarding">
          <p>Create a key to start signing, or bring one you already have.</p>
          <button className="button" onClick={handleCreateKey} disabled={isCreatingKey}>
            <AddCircleIcon /> Create a new key
          </button>
          <p className="text-help">
            Already have one?{' '}
            <a href="#" onClick={goToOptionsPage}>
              Import it in the options page
            </a>
            .
          </p>
        </div>
      ) : (
        <>
          {isBackupPending && (
            <div className="backup-notice">
              <p>
                <strong>Back up your secret key.</strong> It exists only in this browser. If you
                lose it, this identity cannot be recovered by anyone.
              </p>
              <div className="input-group">
                <button onClick={handleCopySecretKey}>
                  <CopyIcon /> Copy
                </button>
                <button onClick={handleDownloadSecretKey}>
                  <DownloadIcon /> Download
                </button>
              </div>
              <div className="input-group">
                <input
                  type="text"
                  placeholder="Name this profile (optional)"
                  value={profileName}
                  onChange={e => setProfileName(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleProfileNameSave()}
                />
                <button
                  onClick={handleProfileNameSave}
                  disabled={
                    !profileName.trim() || profiles[publicKeyHexa]?.name === profileName.trim()
                  }
                >
                  Save
                </button>
              </div>
              <button className="button button-success" onClick={handleBackupDone}>
                <CheckmarkCircleIcon /> I saved my key
              </button>
            </div>
          )}
          <p>Your public key:</p>
          <div className="public-key">
            <div className="pubkey-show">
              <code>
                {truncatePublicKeys(
                  (selectedKeyType === 'hex' ? publicKeyHexa : publiKeyNIP19) ?? ''
                )}
              </code>
              <button
                className="button-onlyicon"
                onClick={clipboardCopyPubKey}
                title="Copy the public key to the clipboard"
              >
                <CopyIcon />
              </button>
            </div>
            <div className="select profile-switch">
              <select value={publicKeyHexa} onChange={handleProfileChange}>
                {Object.keys(profiles).map(profilePubKey => (
                  <option value={profilePubKey} key={profilePubKey}>
                    {profiles[profilePubKey].name ?? nip19.npubEncode(profilePubKey)}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <p>
            <a className="button" href="#" onClick={goToOptionsPage}>
              <CogIcon className="svg-fill" /> Options
            </a>
          </p>
        </>
      )}
    </>
  );
}

const root = createRoot(document.getElementById('main'));
root.render(<Popup />);
