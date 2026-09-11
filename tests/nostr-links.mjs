#!/usr/bin/env node
// Where a nostr: link is sent.
//
//   node tests/nostr-links.mjs
//
// Two small faults, from the audit of 11 September 2026:
//
//   - The handler template accepted any scheme. It is typed in by the user, but a javascript: or
//     data: template would have run on whatever page a nostr: link was clicked on. Only http and
//     https now, checked when a template is saved and again when a link is followed, so a template
//     stored before the rule cannot slip past it.
//   - The ext+nostr: handler page decoded its parameter twice, so a % in a link threw and left a
//     blank tab.
import { rm } from 'node:fs/promises';

import { loadModule } from './load-background.mjs';
import { reporter } from './harness.mjs';

const { ok, state } = reporter();
const { exports: c, outdir } = await loadModule('src/common.ts');

console.log('\nWhich templates are accepted');
for (const [template, fine] of [
  ['', true],
  ['https://njump.me/%s', true],
  ['http://localhost:3000/%s', true],
  ['https://njump.me/', false], // no %s
  ['javascript:alert(%s)', false],
  ['data:text/html,%s', false],
  ['file:///tmp/%s', false],
  ['not an address %s', false]
]) {
  ok(`${JSON.stringify(template)} → ${fine ? 'accepted' : 'refused'}`,
     c.isValidNostrLinkHandlerTemplate(template) === fine);
}

console.log('\nWhere a link goes');
ok('to the template, with the part after nostr: filled in',
   c.buildNostrLinkUrl('https://njump.me/%s', 'nostr:npub1abc') === 'https://njump.me/npub1abc');
ok('never to javascript:, even from a template stored before the rule',
   c.buildNostrLinkUrl('javascript:alert(%s)', 'nostr:npub1abc') === null);
ok('  nor to data:', c.buildNostrLinkUrl('data:text/html,%s', 'nostr:npub1abc') === null);

console.log('\nThe ext+nostr: handler page');
// What Firefox hands the page: the whole link, percent-encoded once into ?uri=.
const search = '?uri=' + encodeURIComponent('ext+nostr:note1%zz');
let destination;
let threw = false;
try { destination = c.handlerDestination('https://njump.me/%s', search); } catch { threw = true; }
ok('a % in the link does not throw', !threw);
ok('  and reaches the destination encoded once', destination === 'https://njump.me/note1%25zz', destination);
ok('no template means nowhere to go', c.handlerDestination('', search) === null);
ok('no link means nowhere to go', c.handlerDestination('https://njump.me/%s', '') === null);

await rm(outdir, { recursive: true, force: true });

console.log(`\n${state.pass} passed, ${state.fail} failed`);
process.exit(state.fail ? 1 : 0);
