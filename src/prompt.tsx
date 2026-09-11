import React, { useEffect, useState } from 'react';
import browser from 'webextension-polyfill';
import { createRoot } from 'react-dom/client';
import { getPublicKey, nip19 } from 'nostr-tools';

import {
  convertHexToUint8Array,
  getAllowedCapabilities,
  MAX_PERMISSION_LEVEL,
  truncatePublicKeys,
  derivePublicKeyFromPrivateKey,
  customAuthorizationDurationSeconds,
  isRememberableKey,
  type AuthorizationTimeUnit
} from './common';
import {
  AuthorizationCondition,
  KindNames,
  PermissionDecision,
  ProfileConfig,
  PromptResponse
} from './types';
import * as Storage from './storage';

import ShieldCheckmarkIcon from './assets/icons/shield-checkmark-outline.svg';
import TimerIcon from './assets/icons/timer-outline.svg';
import CaretBackIcon from './assets/icons/caret-back-outline.svg';
import CaretForwradIcon from './assets/icons/caret-forward-outline.svg';
import CheckmarkCircleIcon from './assets/icons/checkmark-circle-outline.svg';
import CloseCircleIcon from './assets/icons/close-circle-outline.svg';
import { useOpenPrompts } from './PromptManager';

import { applyTheme } from './theme';

applyTheme();

function Prompt() {
  const openPrompts = useOpenPrompts();

  const [activeProfile, setActiveProfile] = useState<ProfileConfig>();
  const [activePubKeyNIP19, setActivePubKeyNIP19] = useState<string>('');

  // const [openPrompts, setOpenPromps] = useState<OpenPromptItem[]>();
  const [requestedPromptIndex, setActivePrompt] = useState<number>(0);
  // Clamped on every render rather than corrected afterwards. The queue shrinks as prompts are
  // answered, and answering the last one left the index past its end: the render read `.host` of
  // undefined, the window went blank, and the prompts still waiting could only be rejected, by
  // closing it. An effect would run too late — the render that throws comes first.
  const activePromptIndex = Math.min(
    requestedPromptIndex,
    Math.max((openPrompts?.length ?? 0) - 1, 0)
  );

  const [kindName, setKindName] = useState<string | null>(null);
  const [kind, setKind] = useState<number | null>(null);

  const [showCloseConfirmation, setShowCloseConfirmation] = useState(false);

  const [customDurationAmount, setCustomDurationAmount] = useState<string>('1');
  const [customDurationUnit, setCustomDurationUnit] = useState<AuthorizationTimeUnit>('minutes');
  const [customDurationError, setCustomDurationError] = useState<string>('');
  /** Which button opened the custom duration section, or null while it is closed. */
  const [customDurationDecision, setCustomDurationDecision] = useState<PermissionDecision | null>(
    null
  );

  useEffect(() => {
    Storage.getActiveProfile().then(profile => {
      setActiveProfile(profile);
      const pubKey = derivePublicKeyFromPrivateKey(profile.privateKey);
      setActivePubKeyNIP19(nip19.npubEncode(pubKey));
    });
  }, []);

  /** Pepare params of event */
  useEffect(() => {
    try {
      if (openPrompts?.[activePromptIndex]?.params) {
        const params = openPrompts[activePromptIndex].params;
        if (params.event) {
          setKind(params.event.kind);
          setKindName(getKindDescription(params.event.kind));
        } else {
          console.warn('params.event is not defined');
        }
      } else {
        console.error('Param is null');
      }
    } catch (err) {
      console.error('Error parsing params.', err);
    }
  }, [activePromptIndex, openPrompts]);

  useEffect(() => {
    setCustomDurationError('');
    setCustomDurationDecision(null);
  }, [activePromptIndex]);

  useEffect(() => {
    // if there are more than one prompt, then set the onbeforeunload
    if (openPrompts && openPrompts.length > 1) {
      const handleBeforeUnload = (event: BeforeUnloadEvent) => {
        if (!showCloseConfirmation) {
          event.preventDefault();
          event.returnValue = ''; // Required for Chrome
          setShowCloseConfirmation(true);
        }
      };
      window.addEventListener('beforeunload', handleBeforeUnload);

      // clean it up, if the dirty state changes
      return () => {
        window.removeEventListener('beforeunload', handleBeforeUnload);
      };
    }

    // since this is not dirty, don't do anything
    return () => {};
  }, [openPrompts]);

  function handleCloseConfirm() {
    // Actually close the window
    window.close();
  }

  function handleCloseCancel() {
    setShowCloseConfirmation(false);
  }

  function getKindDescription(kind: number): string | null {
    // 1. Try to find the specific kind key
    const kindEntry = KindNames[kind];
    if (kindEntry) {
      return kindEntry;
    }

    // 2. Fallback to find the range that the kind belongs to
    const rangeEntry = Object.entries(KindNames).find(([key]) => {
      const [start, end] = key.split('-').map(Number);
      return kind >= start && kind <= (end ?? start);
    });
    return rangeEntry ? rangeEntry[1] : null;
  }

  function submitDecision(
    decision: PermissionDecision,
    condition: AuthorizationCondition,
    durationSeconds?: number,
    level: number = openPrompts?.[activePromptIndex]?.level
  ) {
    if (!openPrompts?.length) {
      return;
    }
    const promptResponse: PromptResponse = {
      prompt: true,
      id: openPrompts[activePromptIndex].id,
      host: openPrompts[activePromptIndex].host,
      level,
      condition,
      decision
    };
    if (durationSeconds != null) {
      promptResponse.durationSeconds = durationSeconds;
    }
    browser.runtime.sendMessage(promptResponse);
  }

  function decisionHandler(decision: PermissionDecision, condition: AuthorizationCondition) {
    return function (ev: React.MouseEvent) {
      ev.preventDefault();
      setCustomDurationError('');
      setCustomDurationDecision(null);
      submitDecision(decision, condition);
    };
  }

  function handleAuthorizeEverything(ev: React.MouseEvent) {
    ev.preventDefault();
    setCustomDurationError('');
    setCustomDurationDecision(null);
    submitDecision(
      PermissionDecision.ALLOW,
      AuthorizationCondition.FOREVER,
      undefined,
      MAX_PERMISSION_LEVEL
    );
  }

  function showCustomDurationHandler(decision: PermissionDecision) {
    return function (ev: React.MouseEvent) {
      ev.preventDefault();
      setCustomDurationError('');
      setCustomDurationDecision(decision);
    };
  }

  function handleCustomDurationApply(ev: React.MouseEvent) {
    ev.preventDefault();
    if (!openPrompts?.length || customDurationDecision == null) {
      return;
    }
    const parsedAmount = parseInt(String(customDurationAmount).trim(), 10);
    const durationSeconds = customAuthorizationDurationSeconds(parsedAmount, customDurationUnit);
    if (durationSeconds == null) {
      setCustomDurationError(
        'Enter a whole number from 1 upward. The total duration cannot exceed 366 days.'
      );
      return;
    }
    setCustomDurationError('');
    submitDecision(
      customDurationDecision,
      AuthorizationCondition.EXPIRABLE_CUSTOM,
      durationSeconds
    );
  }

  /** The custom duration form, shown under whichever button row opened it. */
  function renderCustomDurationSection(decision: PermissionDecision) {
    if (customDurationDecision !== decision) return null;

    const isDeny = decision === PermissionDecision.DENY;
    return (
      <>
        <div className="prompt-custom-duration">
          <label className="prompt-custom-duration-label" htmlFor="custom-duration-amount">
            {isDeny ? 'Reject for' : 'Authorize for'}
          </label>
          <input
            id="custom-duration-amount"
            type="number"
            min={1}
            inputMode="numeric"
            className="prompt-custom-duration-input"
            value={customDurationAmount}
            onChange={e => {
              setCustomDurationAmount(e.target.value);
              setCustomDurationError('');
            }}
          />
          <select
            className="prompt-custom-duration-unit"
            value={customDurationUnit}
            onChange={e => {
              setCustomDurationUnit(e.target.value as AuthorizationTimeUnit);
              setCustomDurationError('');
            }}
          >
            <option value="minutes">minutes</option>
            <option value="hours">hours</option>
            <option value="days">days</option>
          </select>
          <button
            type="button"
            className={`button${isDeny ? ' button-danger' : ''}`}
            onClick={handleCustomDurationApply}
          >
            <TimerIcon />
            Apply
          </button>
        </div>
        {customDurationError ? (
          <p className="prompt-custom-duration-error" role="alert">
            {customDurationError}
          </p>
        ) : null}
      </>
    );
  }

  function movePrompt(direction: number) {
    if (openPrompts && openPrompts.length > 0) {
      let newIndex = activePromptIndex + direction;
      if (newIndex < 0) {
        newIndex = 0;
      }
      if (newIndex >= openPrompts.length) {
        newIndex = openPrompts.length - 1;
      }
      setActivePrompt(newIndex);
    }
  }

  if (!openPrompts || !openPrompts.length) {
    return <div className="p-2">There is no action to authorize</div>;
  }

  // Local files and sandboxed pages share the origin "null": a remembered answer for one would be
  // an answer for all of them. So they get this-time-only buttons; the background enforces it too.
  const rememberable = isRememberableKey(openPrompts[activePromptIndex].host);

  return (
    <>
      {/* Close confirmation modal */}
      {showCloseConfirmation && (
        <div className="close-confirm-dialog-wrapper">
          <div className="close-confirm-dialog">
            <p>If you close this window, all prompts will be taken as rejected.</p>
            <div className="action-buttons">
              <button onClick={handleCloseCancel}>Cancel</button>
              <button className="button-danger" onClick={handleCloseConfirm}>
                Reject all
              </button>
            </div>
          </div>
        </div>
      )}

      <div>
        {openPrompts.length > 1 && (
          <div className="prompt-navigator">
            <button
              className="button-onlyicon"
              disabled={activePromptIndex === 0}
              onClick={movePrompt.bind(null, -1)}
              title="Previous"
            >
              <CaretBackIcon />
            </button>
            <span>
              {activePromptIndex + 1} / {openPrompts.length}
            </span>
            <button
              className="button-onlyicon"
              disabled={activePromptIndex === openPrompts.length - 1}
              onClick={movePrompt.bind(null, 1)}
              title="Next"
            >
              <CaretForwradIcon />
            </button>
          </div>
        )}
        <h1 className="prompt-host">{openPrompts[activePromptIndex].host}</h1>
        <p>
          Signing with profile:{' '}
          <strong>
            {activeProfile && (
              <span>
                {activeProfile.name} ({truncatePublicKeys(activePubKeyNIP19, 10, 10)})
              </span>
            )}
          </strong>
        </p>
        <p>
          Event: <span className="badge">{kindName ?? `(not recognized. Kind: ${kind})`}</span>
        </p>
        <p>is requesting your permission to:</p>
        <ul className="prompt-requests">
          {getAllowedCapabilities(openPrompts[activePromptIndex].level).map(cap => (
            <li key={cap}>{cap}</li>
          ))}
        </ul>
        {!rememberable && (
          <p className="text-help">
            This page has no address of its own — a local file, or a page served sandboxed — so
            your answer applies to this request only and is not remembered.
          </p>
        )}
      </div>
      <div className="prompt-action-buttons">
        <button
          className="button"
          onClick={decisionHandler(PermissionDecision.ALLOW, AuthorizationCondition.FOREVER)}
          hidden={!rememberable}
        >
          <ShieldCheckmarkIcon /> Authorize forever
        </button>
        {rememberable && openPrompts[activePromptIndex].level < MAX_PERMISSION_LEVEL && (
          <button
            className="button"
            onClick={handleAuthorizeEverything}
            title="Grant every capability to this site, so it does not ask again as it needs more"
          >
            <ShieldCheckmarkIcon /> Authorize everything from this site
          </button>
        )}
        <div className="button-group" hidden={!rememberable}>
          <button
            className="button"
            onClick={decisionHandler(PermissionDecision.ALLOW, AuthorizationCondition.EXPIRABLE_5M)}
          >
            <TimerIcon />
            Authorize for 5 m
          </button>
          <button
            className="button"
            onClick={decisionHandler(PermissionDecision.ALLOW, AuthorizationCondition.EXPIRABLE_1H)}
          >
            1 h
          </button>
          <button
            className="button"
            onClick={decisionHandler(PermissionDecision.ALLOW, AuthorizationCondition.EXPIRABLE_8H)}
          >
            8 h
          </button>
          <button
            type="button"
            className="button"
            onClick={showCustomDurationHandler(PermissionDecision.ALLOW)}
          >
            Custom
          </button>
        </div>
        {renderCustomDurationSection(PermissionDecision.ALLOW)}
        <button
          className="button button-success"
          onClick={decisionHandler(PermissionDecision.ALLOW, AuthorizationCondition.SINGLE)}
        >
          <CheckmarkCircleIcon />
          Authorize just this
        </button>

        <hr className="prompt-action-separator" />

        <button
          className="button button-danger"
          onClick={decisionHandler(PermissionDecision.DENY, AuthorizationCondition.FOREVER)}
          hidden={!rememberable}
        >
          <CloseCircleIcon /> Reject forever
        </button>
        <div className="button-group" hidden={!rememberable}>
          <button
            className="button button-danger"
            onClick={decisionHandler(PermissionDecision.DENY, AuthorizationCondition.EXPIRABLE_5M)}
          >
            <TimerIcon />
            Reject for 5 m
          </button>
          <button
            className="button button-danger"
            onClick={decisionHandler(PermissionDecision.DENY, AuthorizationCondition.EXPIRABLE_1H)}
          >
            1 h
          </button>
          <button
            className="button button-danger"
            onClick={decisionHandler(PermissionDecision.DENY, AuthorizationCondition.EXPIRABLE_8H)}
          >
            8 h
          </button>
          <button
            type="button"
            className="button button-danger"
            onClick={showCustomDurationHandler(PermissionDecision.DENY)}
          >
            Custom
          </button>
        </div>
        {renderCustomDurationSection(PermissionDecision.DENY)}
        <button
          className="button button-danger"
          onClick={decisionHandler(PermissionDecision.DENY, AuthorizationCondition.REJECT)}
        >
          <CloseCircleIcon /> Reject just this
        </button>
      </div>
      {openPrompts[activePromptIndex].params && (
        <>
          <p>Acting on:</p>
          <pre className="prompt-request-raw">
            <code>{JSON.stringify(openPrompts[activePromptIndex].params, null, 2)}</code>
          </pre>
        </>
      )}
    </>
  );
}

const root = createRoot(document.getElementById('main'));
root.render(<Prompt />);
