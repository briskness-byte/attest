/**
 * Applying the chosen theme to a page.
 *
 * The stylesheet reads its colours from custom properties on :root, so switching is a matter of
 * stamping an attribute rather than loading anything — which is the only way this can happen
 * without a flash of the wrong colours on a popup that is open for two seconds.
 */
import browser from 'webextension-polyfill';

import * as Storage from './storage';
import { ConfigurationKeys } from './types';

function stamp(theme: string) {
  const root = document.documentElement;
  if (theme === 'light' || theme === 'dark') root.setAttribute('data-theme', theme);
  // Removing it hands the decision back to prefers-color-scheme, rather than freezing whatever
  // the system happened to be when this ran.
  else root.removeAttribute('data-theme');
}

/** Call once per page. Also follows the setting when it is changed from another page. */
export async function applyTheme(): Promise<void> {
  stamp(await Storage.getTheme());
  browser.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local' || !changes[ConfigurationKeys.THEME]) return;
    stamp((changes[ConfigurationKeys.THEME].newValue as string) ?? 'system');
  });
}
