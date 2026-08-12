/**
 * The process that holds the key.
 *
 * It has exactly two operations and neither takes a digest. Everything it signs is structured typed
 * data it has validated itself, so there is no path from this socket to a signature over caller
 * chosen bytes. Deployed with PrivateNetwork=yes it has no route to the internet at all.
 */

import { createServer, type Server } from 'node:net';
import { chmodSync, rmSync } from 'node:fs';
import { decodeJson, encodeJson, SIGNER_PROTOCOL_VERSION } from './protocol.js';
import { SignerRefusedError, validateSigningRequest, type SignerPolicy } from './validate.js';
import type { TypedDataMessage, Wallet } from '../wallet.js';

export interface SignerServer {
  readonly path: string;
  close(): Promise<void>;
}

interface WireRequest {
  v?: number;
  op?: string;
  payload?: TypedDataMessage;
}

async function handle(
  line: string,
  wallet: Wallet,
  policy: SignerPolicy,
  now: () => Date,
): Promise<Record<string, unknown>> {
  let request: WireRequest;
  try {
    request = decodeJson(line) as WireRequest;
  } catch (cause) {
    return { error: `malformed_request: ${cause instanceof Error ? cause.message : String(cause)}` };
  }
  if (request.v !== SIGNER_PROTOCOL_VERSION) {
    return { error: `unsupported protocol version ${String(request.v)}` };
  }
  if (request.op === 'address') return { address: wallet.address };
  if (request.op !== 'sign') return { error: `unsupported_op: ${String(request.op)}` };
  if (request.payload === undefined) return { error: 'malformed_request: no payload' };

  try {
    validateSigningRequest(request.payload, policy, wallet.address, now());
    return { signature: await wallet.signTypedData(request.payload) };
  } catch (cause) {
    if (cause instanceof SignerRefusedError) return { error: cause.message };
    return { error: `signing_failed: ${cause instanceof Error ? cause.message : String(cause)}` };
  }
}

export function startSigner(
  socketPath: string,
  wallet: Wallet,
  policy: SignerPolicy,
  now: () => Date = () => new Date(),
): Promise<SignerServer> {
  rmSync(socketPath, { force: true });
  const server: Server = createServer((socket) => {
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      let index = buffer.indexOf('\n');
      while (index !== -1) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        void handle(line, wallet, policy, now).then((result) =>
          socket.write(`${encodeJson({ v: SIGNER_PROTOCOL_VERSION, ...result })}\n`),
        );
        index = buffer.indexOf('\n');
      }
    });
    socket.on('error', () => socket.destroy());
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      // 0660 rather than 0600: the daemon runs as a different user in the same group.
      chmodSync(socketPath, 0o660);
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
