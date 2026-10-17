// A Nostr relay small enough to read in one sitting, for the remote-signer suites.
//
// The WebSocket side is written out on node's own http and crypto rather than taken from a package:
// the repo has no WebSocket server among its dependencies, and adding one for a test is the kind of
// dependency AGENTS.md asks not to add. It speaks just enough of RFC 6455 for nostr-tools: unmasked
// text frames out, masked text frames in, close and ping. No fragmentation, no extensions.
//
// Of NIP-01 it does EVENT, REQ and CLOSE, filters on ids, kinds, authors, #p, since and limit, and
// keeps no ephemeral event (20000–29999), as a real relay would not — so an answer published before
// anybody subscribed is gone, which is the case the client has to get right.
import http from 'node:http';
import { createHash } from 'node:crypto';
import { verifyEvent } from 'nostr-tools';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function frame(text) {
  const payload = Buffer.from(text);
  const n = payload.length;
  const head =
    n < 126 ? Buffer.from([0x81, n])
    : n < 65536 ? Buffer.from([0x81, 126, n >> 8, n & 255])
    : Buffer.concat([Buffer.from([0x81, 127]), (() => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; })()]);
  return Buffer.concat([head, payload]);
}

function matches(filter, event) {
  if (filter.ids && !filter.ids.includes(event.id)) return false;
  if (filter.kinds && !filter.kinds.includes(event.kind)) return false;
  if (filter.authors && !filter.authors.includes(event.pubkey)) return false;
  if (filter.since && event.created_at < filter.since) return false;
  for (const [key, values] of Object.entries(filter)) {
    if (key[0] !== '#') continue;
    const tagged = event.tags.filter(t => t[0] === key.slice(1)).map(t => t[1]);
    if (!values.some(v => tagged.includes(v))) return false;
  }
  return true;
}

/**
 * Starts a relay on a free port. `published` is every EVENT accepted, in order, for a test to look
 * at; `reject(event)` may return a reason to refuse one, the way a relay with a policy would.
 */
export async function startRelay({ reject } = {}) {
  const sockets = new Set();
  const stored = [];
  const published = [];

  const server = http.createServer((_, res) => { res.writeHead(426); res.end(); });

  server.on('upgrade', (req, socket) => {
    const accept = createHash('sha1').update(req.headers['sec-websocket-key'] + GUID).digest('base64');
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
    );

    const client = { socket, subs: new Map() };
    sockets.add(client);
    const send = message => { if (!socket.destroyed) socket.write(frame(JSON.stringify(message))); };
    client.send = send;

    let buffer = Buffer.alloc(0);
    socket.on('data', chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      for (;;) {
        if (buffer.length < 2) return;
        const opcode = buffer[0] & 0x0f;
        let len = buffer[1] & 0x7f;
        let offset = 2;
        if (len === 126) { if (buffer.length < 4) return; len = buffer.readUInt16BE(2); offset = 4; }
        else if (len === 127) { if (buffer.length < 10) return; len = Number(buffer.readBigUInt64BE(2)); offset = 10; }
        const masked = buffer[1] & 0x80;
        const mask = masked ? buffer.subarray(offset, offset + 4) : null;
        if (masked) offset += 4;
        if (buffer.length < offset + len) return;
        const payload = Buffer.from(buffer.subarray(offset, offset + len));
        if (mask) for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
        buffer = buffer.subarray(offset + len);

        if (opcode === 0x8) { socket.end(Buffer.from([0x88, 0])); return; }
        if (opcode === 0x9) { socket.write(Buffer.concat([Buffer.from([0x8a, payload.length]), payload])); continue; }
        if (opcode !== 0x1) continue;
        handle(client, payload.toString());
      }
    });
    socket.on('close', () => sockets.delete(client));
    socket.on('error', () => sockets.delete(client));
  });

  function handle(client, text) {
    let message;
    try { message = JSON.parse(text); } catch { return; }
    const [type, ...rest] = message;

    if (type === 'EVENT') {
      const event = rest[0];
      if (!verifyEvent(event)) { client.send(['OK', event?.id, false, 'invalid: bad signature']); return; }
      const reason = reject?.(event);
      if (reason) { client.send(['OK', event.id, false, reason]); return; }
      published.push(event);
      if (!(event.kind >= 20000 && event.kind < 30000)) stored.push(event);
      client.send(['OK', event.id, true, '']);
      for (const other of sockets) {
        for (const [subId, filters] of other.subs) {
          if (filters.some(f => matches(f, event))) other.send(['EVENT', subId, event]);
        }
      }
    } else if (type === 'REQ') {
      const [subId, ...filters] = rest;
      client.subs.set(subId, filters);
      for (const filter of filters) {
        if (filter.limit === 0) continue;
        const hits = stored.filter(e => matches(filter, e));
        for (const event of filter.limit ? hits.slice(-filter.limit) : hits) client.send(['EVENT', subId, event]);
      }
      client.send(['EOSE', subId]);
    } else if (type === 'CLOSE') {
      client.subs.delete(rest[0]);
    }
  }

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const url = `ws://127.0.0.1:${server.address().port}`;

  return {
    url,
    published,
    /** How many subscriptions are open right now, over every connection. */
    openSubscriptions: () => [...sockets].reduce((n, c) => n + c.subs.size, 0),
    /** Hand an event to every matching subscription as if it had been published, unchecked. */
    inject(event) {
      for (const c of sockets) for (const [subId, filters] of c.subs) {
        if (filters.some(f => matches(f, event))) c.send(['EVENT', subId, event]);
      }
    },
    close: () => new Promise(resolve => {
      for (const c of sockets) c.socket.destroy();
      server.close(() => resolve());
    })
  };
}
