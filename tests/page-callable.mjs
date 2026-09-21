#!/usr/bin/env node
// What a web page may ask for, held against the tables it has to agree with.
//
//   node tests/page-callable.mjs
//
// CALLABLE_FROM_PAGE is written out by hand, next to PERMISSIONS_REQUIRED, rather than derived from
// it: a derived list would make anything later added to the permission table callable from every
// page without anybody deciding so. The cost of writing it out is that the two can drift apart, and
// each direction fails differently:
//
//   - a NIP-07 method in the permission table but not in the list is refused to every site. Safe,
//     and quietly broken — the method simply stops working, with nothing to say why;
//   - a type in the list with no permission level is one a page can reach without the permission
//     model knowing what to ask for. That direction is the one that matters.
//
// The browser half — that the bridge really forwards these and really refuses the rest — is
// tests/security-boundary.mjs. This is the part that has to hold before there is a browser.
import { rm } from 'node:fs/promises';

import { loadModule } from './load-background.mjs';
import { reporter } from './harness.mjs';

const { ok, state } = reporter();

const { exports: common, outdir: commonDir } = await loadModule('src/common.ts');
const { exports: background, outdir: backgroundDir } = await loadModule('src/background.ts');

const callable = [...common.CALLABLE_FROM_PAGE];
const permissioned = Object.keys(common.PERMISSIONS_REQUIRED);
const privileged = [...background.EXTENSION_PAGES_ONLY];

console.log('\nEvery NIP-07 method is reachable from a page');
for (const method of permissioned) {
  ok(`${method}`, common.CALLABLE_FROM_PAGE.has(method));
}

console.log('\nNothing a page can reach is outside the permission model');
for (const type of callable) {
  ok(`${type} has a permission level`,
    Object.prototype.hasOwnProperty.call(common.PERMISSIONS_REQUIRED, type));
}

console.log('\nThe background\'s own-pages-only handlers stay out of reach');
ok('there are privileged handlers to check against', privileged.length > 0, privileged);
for (const type of privileged) {
  ok(`${type} is not callable from a page`, !common.CALLABLE_FROM_PAGE.has(type));
}

// Guards the guard: a Set built from an object literal would hand a page these for free.
console.log('\nNothing inherited slips through');
for (const type of ['toString', 'constructor', '__proto__', 'hasOwnProperty', 'valueOf']) {
  ok(`${type} is not callable`, !common.CALLABLE_FROM_PAGE.has(type));
}

await rm(commonDir, { recursive: true, force: true });
await rm(backgroundDir, { recursive: true, force: true });

console.log(`\n${state.pass} passed, ${state.fail} failed`);
process.exit(state.fail ? 1 : 0);
