// A fake `browser` for tests: enough of the extension API for background.ts to run in node.
//
// esbuild aliases `webextension-polyfill` to this file, so the bundle under test imports the stub
// instead of the real thing. The runner imports this file too, and gets a *different* module
// instance — the bundle has its own copy. Everything therefore lives on one object hung off
// globalThis, so both copies drive the same windows and the same storage.

const hub = (globalThis.__attestStub ??= {
  windows: new Map(), // id -> { id, url }
  nextWindowId: 1,
  created: [], // every window ever opened, in order
  storage: new Map(),
  onMessage: [],
  onWindowRemoved: [],
  onTabRemoved: [],
  onStorageChanged: [],
  failToOpen: false // make windows.create reject, the "nothing can be shown" case
});

export const control = hub;

/** Reset between scenarios. Listeners survive: background.ts registers them once, at import. */
export function reset() {
  hub.windows.clear();
  hub.created.length = 0;
  hub.nextWindowId = 1;
  hub.storage.clear();
  hub.failToOpen = false;
}

/**
 * The window disappears without windows.onRemoved firing.
 *
 * This is the gap the bug lived in — the map still holds the id, the window is already gone — and
 * it is exactly what a test cannot express by calling windows.remove(), which fires the event and
 * cleans everything up.
 */
export function killWindowSilently(id) {
  hub.windows.delete(id);
}

/** The ordinary close, event and all. */
export async function closeWindow(id) {
  hub.windows.delete(id);
  for (const fn of hub.onWindowRemoved) await fn(id);
}

/** Hand a message to background.ts the way the content script or the prompt page would. */
export function send(message, sender = null) {
  if (!hub.onMessage.length) throw new Error('background.ts registered no message listener');
  return hub.onMessage[0](message, sender);
}

const keysOf = query => {
  if (query == null) return null; // everything
  if (typeof query === 'string') return [query];
  if (Array.isArray(query)) return query;
  return Object.keys(query);
};

const browser = {
  runtime: {
    id: 'attest@test',
    getURL: path => `moz-extension://attest-test/${path}`,
    onMessage: { addListener: fn => hub.onMessage.push(fn) },
    onMessageExternal: { addListener: () => {} },
    onStartup: { addListener: () => {} },
    onInstalled: { addListener: () => {} },
    sendMessage: async () => undefined
  },

  storage: {
    local: {
      async get(query) {
        const out = {};
        const wanted = keysOf(query);
        if (wanted === null) {
          for (const [k, v] of hub.storage) out[k] = v;
        } else {
          for (const k of wanted) if (hub.storage.has(k)) out[k] = hub.storage.get(k);
          // an object query supplies defaults for missing keys
          if (query && !Array.isArray(query) && typeof query === 'object') {
            for (const [k, fallback] of Object.entries(query)) if (!(k in out)) out[k] = fallback;
          }
        }
        return out;
      },
      async set(items) {
        const changes = {};
        for (const [k, v] of Object.entries(items)) {
          changes[k] = { oldValue: hub.storage.get(k), newValue: v };
          hub.storage.set(k, v);
        }
        for (const fn of hub.onStorageChanged) await fn(changes, 'local');
      },
      async remove(query) {
        for (const k of keysOf(query) ?? []) hub.storage.delete(k);
      }
    },
    onChanged: { addListener: fn => hub.onStorageChanged.push(fn) }
  },

  windows: {
    async create({ url }) {
      if (hub.failToOpen) throw new Error('cannot open a window');
      const id = hub.nextWindowId++;
      const win = { id, url };
      hub.windows.set(id, win);
      hub.created.push(win);
      return win;
    },
    // Firefox rejects for an unknown id; that rejection is the whole subject of the test.
    async get(id) {
      const win = hub.windows.get(id);
      if (!win) throw new Error(`No window with id: ${id}.`);
      return win;
    },
    async remove(id) {
      await closeWindow(id);
    },
    onRemoved: { addListener: fn => hub.onWindowRemoved.push(fn) }
  },

  // Android Firefox path. Present so nothing crashes if it is reached; the desktop path is what
  // these tests drive, because `browser.windows` is truthy here.
  tabs: {
    async create({ url }) {
      return browser.windows.create({ url });
    },
    async get(id) {
      return browser.windows.get(id);
    },
    async remove(id) {
      return browser.windows.remove(id);
    },
    onRemoved: { addListener: fn => hub.onTabRemoved.push(fn) }
  }
};

export default browser;
