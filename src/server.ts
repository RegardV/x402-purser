/**
 * The unix socket an agent talks to.
 *
 * Newline-delimited JSON, one object per request, because the payloads are small and it can be
 * poked at with nc. Filesystem permissions are the access control: the socket is created 0600 so
 * only the owning user can connect.
 *
 * There is no pending state in this protocol. v1 is envelope only, with no human escalation, so
 * every request gets a terminal answer on the same connection.
 */

import { createServer, type Server } from 'node:net';
import { chmodSync, rmSync } from 'node:fs';
import { pay, type PayResult } from './pay.js';
import type { PurserClientDeps } from './client.js';

export const PURSER_PROTOCOL_VERSION = 1;

export interface PurserServerDeps extends PurserClientDeps {
  readonly fetchImpl?: typeof fetch;
}

export interface PurserServer {
  readonly path: string;
  close(): Promise<void>;
}

interface WireRequest {
  v?: number;
  agentRef?: string;
  resourceUrl?: string;
  ceilingAtomic?: string;
  currency?: string;
  nonce?: string;
  timestamp?: string;
  signature?: string;
  intentId?: number | null;
}

function refused(reason: string): PayResult {
  return { status: 'refused', reason };
}

async function handle(line: string, deps: PurserServerDeps): Promise<PayResult> {
  let request: WireRequest;
  try {
    request = JSON.parse(line) as WireRequest;
  } catch {
    return refused('request was not valid JSON');
  }
  if (request.v !== PURSER_PROTOCOL_VERSION) {
    return refused(`unsupported protocol version ${String(request.v)}`);
  }
  const { agentRef, resourceUrl, ceilingAtomic, currency, nonce, timestamp, signature } = request;
  if (
    typeof agentRef !== 'string' ||
    typeof resourceUrl !== 'string' ||
    typeof ceilingAtomic !== 'string' ||
    typeof currency !== 'string' ||
    typeof nonce !== 'string' ||
    typeof timestamp !== 'string' ||
    typeof signature !== 'string'
  ) {
    return refused('request is missing a required field');
  }
  try {
    return await pay(
      deps,
      {
        claim: { agentRef, resourceUrl, ceilingAtomic, currency, nonce, timestamp },
        signature,
        intentId: request.intentId ?? null,
      },
      deps.fetchImpl ?? fetch,
    );
  } catch (cause) {
    return refused(cause instanceof Error ? cause.message : String(cause));
  }
}

export function startServer(socketPath: string, deps: PurserServerDeps): Promise<PurserServer> {
  rmSync(socketPath, { force: true });
  const server: Server = createServer((socket) => {
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      let index = buffer.indexOf('\n');
      while (index !== -1) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        void handle(line, deps).then((result) =>
          socket.write(`${JSON.stringify({ v: PURSER_PROTOCOL_VERSION, ...result })}\n`),
        );
        index = buffer.indexOf('\n');
      }
    });
    // A dropped agent is ordinary, not an error worth crashing over.
    socket.on('error', () => socket.destroy());
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      chmodSync(socketPath, 0o600);
      resolve({
        path: socketPath,
        close: () =>
          new Promise<void>((done) => {
            server.close(() => {
              rmSync(socketPath, { force: true });
              done();
            });
          }),
      });
    });
  });
}
