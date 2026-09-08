// Load background.ts into node with the browser API stubbed, so a suite can drive it directly.
//
// Shared by every stub-based suite. The single substitution is `webextension-polyfill`; nostr-tools,
// the storage layer, the permission model and the crypto are all the real thing, so a change that
// breaks them breaks the run.
import { build } from 'esbuild';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

/** Bundles and imports background.ts. Returns the temp directory, for the caller to clean up. */
export async function loadBackground() {
  const root = resolve(import.meta.dirname, '..');
  const outdir = await mkdtemp(join(tmpdir(), 'attest-test-'));
  const outfile = join(outdir, 'background.mjs');

  await build({
    bundle: true,
    entryPoints: [join(root, 'src/background.ts')],
    outfile,
    format: 'esm',
    platform: 'neutral',
    mainFields: ['module', 'main'],
    conditions: ['import', 'default'],
    alias: { 'webextension-polyfill': join(root, 'tests/browser-stub.mjs') },
    logLevel: 'warning'
  });

  await import(pathToFileURL(outfile).href); // registers the listeners on the stub
  return outdir;
}

/**
 * Bundles and imports any other module from src/, so a suite can use the extension's own routine
 * rather than reimplementing it — a fixture encrypted differently from the code under test proves
 * only that the two disagree.
 */
export async function loadModule(relativePath) {
  const root = resolve(import.meta.dirname, '..');
  const outdir = await mkdtemp(join(tmpdir(), 'attest-test-'));
  const outfile = join(outdir, 'module.mjs');

  await build({
    bundle: true,
    entryPoints: [join(root, relativePath)],
    outfile,
    format: 'esm',
    platform: 'neutral',
    mainFields: ['module', 'main'],
    conditions: ['import', 'default'],
    alias: { 'webextension-polyfill': join(root, 'tests/browser-stub.mjs') },
    logLevel: 'warning'
  });

  return { exports: await import(pathToFileURL(outfile).href), outdir };
}

/** A sender that looks like one of the extension's own pages, rather than a web page. */
export const OWN_PAGE = { url: 'moz-extension://attest-test/options.html' };
