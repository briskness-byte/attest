import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import browser from 'webextension-polyfill';
import { encryptPrivateKey } from './pinEncryption';
import * as Storage from './storage';
import { PinMessageResponse, PinMode } from './types';

import { applyTheme } from './theme';

applyTheme();

function PinPrompt() {
  const [mode, setMode] = useState<PinMode>('unlock');
  const [pin, setPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [error, setError] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [promptId, setPromptId] = useState('');
  const [copied, setCopied] = useState('');

  useEffect(() => {
    // Parse URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const urlMode = urlParams.get('mode') as PinMode;
    const id = urlParams.get('id');

    if (urlMode && ['setup', 'unlock', 'disable', 'copy'].includes(urlMode)) {
      setMode(urlMode);
    }
    if (id) {
      setPromptId(id);
    }

    // Cleanup: clear PIN state on component unmount
    return () => {
      setPin('');
      setConfirmPin('');
    };
  }, []);

  function handlePinChange(e: React.ChangeEvent<HTMLInputElement>) {
    const value = e.target.value.replace(/\D/g, ''); // Only allow digits
    if (value.length <= 6) {
      setPin(value);
      setError(''); // Clear error on input
    }
  }

  function handleConfirmPinChange(e: React.ChangeEvent<HTMLInputElement>) {
    const value = e.target.value.replace(/\D/g, ''); // Only allow digits
    if (value.length <= 6) {
      setConfirmPin(value);
      setError(''); // Clear error on input
    }
  }

  function validatePin(pinValue: string): boolean {
    if (pinValue.length < 4 || pinValue.length > 6) {
      setError('PIN must be between 4 and 6 digits');
      return false;
    }
    return true;
  }

  async function handleConfirm() {
    setError('');

    if (!validatePin(pin)) {
      return;
    }

    if (mode === 'setup') {
      // Setup mode: require PIN confirmation
      if (confirmPin !== pin) {
        setError('PINs do not match');
        return;
      }
      if (!validatePin(confirmPin)) {
        return;
      }

      setIsProcessing(true);
      try {
        // Get current private key
        const currentPrivateKey = await Storage.readActivePrivateKey();
        if (!currentPrivateKey) {
          setError('No private key found');
          setIsProcessing(false);
          return;
        }

        // Encrypt the private key
        const encryptedKey = await encryptPrivateKey(pin, currentPrivateKey);

        // Send to background script
        const response = (await browser.runtime.sendMessage({
          type: 'setupPin',
          pin,
          encryptedKey,
          id: promptId
        })) as PinMessageResponse;

        if (response && response.success) {
          // Clear PIN state immediately after successful setup
          setPin('');
          setConfirmPin('');
          window.close();
        } else {
          setError(response?.error || 'Failed to enable PIN protection');
          setIsProcessing(false);
          // Clear PIN state on error
          setPin('');
          setConfirmPin('');
        }
      } catch (error) {
        setError(error.message || 'Failed to enable PIN protection');
        setIsProcessing(false);
        // Clear PIN state on error
        setPin('');
        setConfirmPin('');
      }
    } else if (mode === 'unlock') {
      // Unlock mode: verify PIN and cache it
      setIsProcessing(true);
      try {
        const response = (await browser.runtime.sendMessage({
          type: 'verifyPin',
          pin,
          id: promptId
        })) as PinMessageResponse;

        if (response && response.success) {
          // Clear PIN state immediately after successful unlock
          setPin('');
          window.close();
        } else {
          setError(response?.error || 'Incorrect PIN');
          setIsProcessing(false);
          setPin(''); // Clear PIN on error
        }
      } catch (error) {
        setError(error.message || 'Failed to verify PIN');
        setIsProcessing(false);
        setPin(''); // Clear PIN on error
      }
    } else if (mode === 'copy') {
      // The key is decrypted in the background and handed to this window, which puts it on the
      // clipboard and closes. It never reaches the options page, and the PIN typed here is used
      // for this one decryption — the cached PIN is deliberately not accepted, because copying a
      // private key out should cost a deliberate act every time.
      setIsProcessing(true);
      try {
        const response = (await browser.runtime.sendMessage({
          type: 'copyNsec',
          pin,
          id: promptId
        })) as PinMessageResponse;

        if (response && response.success && response.nsec) {
          // The write has to happen while the click that opened this path is still the last thing
          // the user did, so it stays a user gesture.
          await navigator.clipboard.writeText(response.nsec);
          setPin('');
          setCopied(response.npub || '');
          // Long enough to read which key it was, short enough not to leave a window lying around.
          setTimeout(() => window.close(), 4000);
        } else {
          setError(response?.error || 'Incorrect PIN');
          setIsProcessing(false);
          setPin('');
        }
      } catch (error: any) {
        setError(error?.message || 'Could not copy the private key');
        setIsProcessing(false);
        setPin('');
      }
    } else if (mode === 'disable') {
      // Disable mode: verify PIN and disable protection
      setIsProcessing(true);
      try {
        const response = (await browser.runtime.sendMessage({
          type: 'disablePin',
          pin,
          id: promptId
        })) as PinMessageResponse | undefined;

        if (response && response.success) {
          // Clear PIN state immediately after successful disable
          setPin('');
          window.close();
        } else {
          setError((response && response.error) || 'Incorrect PIN');
          setIsProcessing(false);
          setPin(''); // Clear PIN on error
        }
      } catch (error: any) {
        setError(error?.message || 'Failed to disable PIN protection');
        setIsProcessing(false);
        setPin(''); // Clear PIN on error
      }
    }
  }

  function handleKeyPress(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') {
      handleConfirm();
    }
  }

  const getTitle = () => {
    switch (mode) {
      case 'setup':
        return 'Set up PIN Protection';
      case 'unlock':
        return 'Enter PIN';
      case 'disable':
        return 'Disable PIN Protection';
      case 'copy':
        return 'Copy your private key';
      default:
        return 'Enter PIN';
    }
  };

  const getDescription = () => {
    switch (mode) {
      case 'setup':
        return 'Enter a PIN to protect your private keys. You will need to enter this PIN each time you use the extension.';
      case 'unlock':
        return 'Enter your PIN to unlock your private keys.';
      case 'disable':
        return 'Enter your PIN to disable PIN protection. Your keys will be stored unencrypted.';
      case 'copy':
        return 'Enter your PIN to put your private key on the clipboard. Anything that can read the clipboard can read it, and a clipboard manager will keep a copy in its history — on disk, often for a long time. Paste it where you need it, then copy something else.';
      default:
        return '';
    }
  };

  return (
    <>
      <header>
        <h1>{getTitle()}</h1>
        <p>{getDescription()}</p>
      </header>
      <main>
        {copied && (
          <div className="alert success" role="status">
            Copied the private key for {copied.slice(0, 12)}…{copied.slice(-4)} to the clipboard.
            This window closes by itself.
          </div>
        )}
        {error && (
          <div className="alert warning" role="alert">
            {error}
          </div>
        )}

        <div className="form-field" hidden={!!copied}>
          <label htmlFor="pin-input">PIN (4-6 digits):</label>
          <input
            id="pin-input"
            type="password"
            value={pin}
            maxLength={6}
            onChange={handlePinChange}
            onKeyPress={handleKeyPress}
            disabled={isProcessing}
            autoFocus
          />
        </div>

        {mode === 'setup' && (
          <div className="form-field">
            <label htmlFor="confirm-pin-input">Confirm PIN:</label>
            <input
              id="confirm-pin-input"
              type="password"
              value={confirmPin}
              maxLength={6}
              onChange={handleConfirmPinChange}
              onKeyPress={handleKeyPress}
              disabled={isProcessing}
            />
          </div>
        )}

        <div className="action-buttons" hidden={!!copied}>
          <button
            onClick={handleConfirm}
            disabled={isProcessing || pin.length < 4 || (mode === 'setup' && confirmPin !== pin)}
            className="button button-success"
          >
            {mode === 'setup'
              ? 'Enable PIN Protection'
              : mode === 'disable'
                ? 'Disable Protection'
                : mode === 'copy'
                  ? 'Copy to clipboard'
                  : 'Unlock'}
          </button>
        </div>
      </main>
    </>
  );
}

const root = createRoot(document.getElementById('main'));
root.render(<PinPrompt />);
