import { handlerDestination } from './common';
import * as Storage from './storage';

/**
 * Redirects to the configured handler for nostr: protocol links.
 *
 * Takes the 'uri' param, substitutes it into the handler template, and redirects. Closes the window
 * if there is no template, no uri, or nowhere safe to go.
 *
 * @async
 */
async function handleNostrProtocolLink(): Promise<void> {
  const template = await Storage.getNostrLinkHandlerUrlTemplate();
  const destinationUrl = handlerDestination(template, location.search);

  if (!destinationUrl) {
    window.close();
    return;
  }

  location.replace(destinationUrl);
}

handleNostrProtocolLink();
