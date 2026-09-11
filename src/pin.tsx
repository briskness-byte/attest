import React, { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import browser from 'webextension-polyfill';
import { encryptPrivateKey } from './pinEncryption';
import * as Storage from './storage';
import { MIN_PASSPHRASE_LENGTH, secretProblem } from './common';
import { PinMessageResponse, PinMode, SecretKind } from './types';

import { applyTheme } from './theme';

applyTheme();

function PinPrompt() {
  const [mode, setMode] = useState<PinMode>('unlock');
  // What protects the keys: chosen here during setup, read from storage for everything else. Null
  // until known, so a passphrase is never typed into a field that throws away all but digits.
  const [kind, setKind] = useState<SecretKind | null>(null);
  const [pin, setPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [error, setError] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [promptId, setPromptId] = useState('');
  const [copied, setCopied] = useState('');
  const input = useRef<HTMLInputElement>(null);

  const noun = kind === 'passphrase' ? 'passphrase' : 'PIN';

  useEffect(() => {
    // Parse URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const urlMode = urlParams.get('mode') as PinMode;
    const id = urlParams.get('id');

    const knownMode: PinMode =
      urlMode && ['setup', 'unlock', 'disable', 'copy'].includes(urlMode) ? urlMode : 'unlock';
    setMode(knownMode);
    if (id) {
      setPromptId(id);
    }

    // A new setup starts on the passphrase, the choice that protects the keys from somebody who
    // copies the profile. Every other mode uses whatever the keys were protected with.
    if (knownMode === 'setup') setKind('passphrase');
    else Storage.getPinKind().then(setKind);

    // Cleanup: clear PIN state on component unmount
    return () => {
      setPin('');
      setConfirmPin('');
    };
  }, []);

  // autoFocus does nothing on a field that is still disabled, so focus it once it can be used.
  useEffect(() => {
    if (kind) input.current?.focus();
  }, [kind]);

  function chooseKind(next: SecretKind) {
    setKind(next);
    setPin('');
    setConfirmPin('');
    setError('');
  }

  /** A PIN field keeps digits, at most six of them. A passphrase field keeps what was typed. */
  function clean(value: string) {
    return kind === 'pin' ? value.replace(/\D/g, '').slice(0, 6) : value;
  }

  function handlePinChange(e: React.ChangeEvent<HTMLInputElement>) {
    setPin(clean(e.target.value));
    setError(''); // Clear error on input
  }

  function handleConfirmPinChange(e: React.ChangeEvent<HTMLInputElement>) {
    setConfirmPin(clean(e.target.value));
    setError(''); // Clear error on input
  }

  function validatePin(value: string): boolean {
    const problem = kind ? secretProblem(kind, value) : 'Still loading';
    if (problem) {
      setError(problem);
      return false;
    }
    return true;
  }

  /** The background says "Incorrect PIN" whatever the kind; this window can use the right word. */
  function explain(message: string | undefined, fallback: string) {
    if (message === 'Incorrect PIN') return `Incorrect ${noun}`;
    return message || fallback;
  }

  async function handleConfirm() {
    setError('');

    if (!validatePin(pin)) {
      return;
    }

    if (mode === 'setup') {
      // Setup mode: require confirmation
      if (confirmPin !== pin) {
        setError(`The ${noun}s do not match`);
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
          id: promptId,
          kind
        })) as PinMessageResponse;

        if (response && response.success) {
          // Clear PIN state immediately after successful setup
          setPin('');
          setConfirmPin('');
          window.close();
        } else {
          setError(explain(response?.error, 'Could not turn protection on'));
          setIsProcessing(false);
          // Clear PIN state on error
          setPin('');
          setConfirmPin('');
        }
      } catch (error) {
        setError(error.message || 'Could not turn protection on');
        setIsProcessing(false);
        // Clear PIN state on error
        setPin('');
        setConfirmPin('');
      }
    } else if (mode === 'unlock') {
      // Unlock mode: verify and cache
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
          setError(explain(response?.error, `Incorrect ${noun}`));
          setIsProcessing(false);
          setPin(''); // Clear PIN on error
        }
      } catch (error) {
        setError(error.message || `Could not check the ${noun}`);
        setIsProcessing(false);
        setPin(''); // Clear PIN on error
      }
    } else if (mode === 'copy') {
      // The key is decrypted in the background and handed to this window, which puts it on the
      // clipboard and closes. It never reaches the options page, and the secret typed here is used
      // for this one decryption — the cached one is deliberately not accepted, because copying a
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
          setError(explain(response?.error, `Incorrect ${noun}`));
          setIsProcessing(false);
          setPin('');
        }
      } catch (error: any) {
        setError(error?.message || 'Could not copy the private key');
        setIsProcessing(false);
        setPin('');
      }
    } else if (mode === 'disable') {
      // Disable mode: verify and turn protection off
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
          setError(explain(response?.error, `Incorrect ${noun}`));
          setIsProcessing(false);
          setPin(''); // Clear PIN on error
        }
      } catch (error: any) {
        setError(error?.message || 'Could not turn protection off');
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
        return 'Protect your keys';
      case 'disable':
        return 'Turn protection off';
      case 'copy':
        return 'Copy your private key';
      default:
        return `Enter your ${noun}`;
    }
  };

  const getDescription = () => {
    switch (mode) {
      case 'setup':
        return 'Your private keys will be encrypted. You will be asked for this whenever the extension needs a key.';
      case 'unlock':
        return `Enter your ${noun} to unlock your private keys.`;
      case 'disable':
        return `Enter your ${noun} to turn protection off. Your keys will be stored unencrypted.`;
      case 'copy':
        return `Enter your ${noun} to put your private key on the clipboard. Anything that can read the clipboard can read it, and a clipboard manager will keep a copy in its history — on disk, often for a long time. Paste it where you need it, then copy something else.`;
      default:
        return '';
    }
  };

  const fieldProps = {
    type: 'password',
    className: kind === 'passphrase' ? 'passphrase' : undefined,
    inputMode: kind === 'pin' ? ('numeric' as const) : undefined,
    maxLength: kind === 'pin' ? 6 : undefined,
    autoComplete: 'off',
    onKeyPress: handleKeyPress,
    disabled: isProcessing || !kind
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

        {mode === 'setup' && (
          <>
            <fieldset className="secret-kind" aria-label="Protect with" disabled={isProcessing}>
              <label>
                <input
                  type="radio"
                  name="secret-kind"
                  value="passphrase"
                  checked={kind === 'passphrase'}
                  onChange={() => chooseKind('passphrase')}
                />
                a passphrase
              </label>
              <label>
                <input
                  type="radio"
                  name="secret-kind"
                  value="pin"
                  checked={kind === 'pin'}
                  onChange={() => chooseKind('pin')}
                />
                a PIN
              </label>
            </fieldset>
            {/* The difference between the two is the whole reason there is a choice, so it is
                said here, at the moment of choosing, rather than left for the options page. */}
            <p className="text-help secret-kind-help">
              {kind === 'pin'
                ? 'A PIN of 4 to 6 digits stops somebody using this browser. It does not stop somebody who copies your Firefox profile: every such PIN can be tried in minutes. For that, choose a passphrase.'
                : `At least ${MIN_PASSPHRASE_LENGTH} characters. Four or five random words are easy to type and very hard to guess — even for somebody with a copy of your Firefox profile.`}
            </p>
          </>
        )}

        <div className="form-field" hidden={!!copied}>
          <label htmlFor="pin-input">{kind === 'passphrase' ? 'Passphrase:' : 'PIN (4-6 digits):'}</label>
          <input id="pin-input" ref={input} value={pin} onChange={handlePinChange} {...fieldProps} />
        </div>

        {mode === 'setup' && (
          <div className="form-field">
            <label htmlFor="confirm-pin-input">Confirm {noun}:</label>
            <input
              id="confirm-pin-input"
              value={confirmPin}
              onChange={handleConfirmPinChange}
              {...fieldProps}
            />
          </div>
        )}

        <div className="action-buttons" hidden={!!copied}>
          <button
            onClick={handleConfirm}
            disabled={
              isProcessing ||
              !kind ||
              !!secretProblem(kind, pin) ||
              (mode === 'setup' && confirmPin !== pin)
            }
            className="button button-success"
          >
            {mode === 'setup'
              ? `Protect with this ${noun}`
              : mode === 'disable'
                ? 'Turn protection off'
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
