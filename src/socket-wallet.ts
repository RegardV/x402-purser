/**
 * A Wallet backed by the signer process rather than by a key in this process.
 *
 * Drop in replacement for unlockWallet inside the daemon. lock() is local only: it stops this
 * process asking for signatures, and does not lock the signer, because a compromised daemon should
 * not be able to disable the signer for everyone. Revoking for real means stopping the signer.
 */

import { createConnection } from 'node:net';
import { decodeJson, encodeJson, SIGNER_PROTOCOL_VERSION } from './signer/protocol.js';
import { WalletLockedError, type TypedDataMessage, type Wallet } from './wallet.js';

function ask(socketPath: string, request: unknown): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath, () => socket.write(`${encodeJson(request)}\n`));
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString();
      const index = buffer.indexOf('\n');
      if (index === -1) return;
      socket.end();
      try {
        resolve(decodeJson(buffer.slice(0, index)) as Record<string, unknown>);
      } catch (cause) {
        reject(cause instanceof Error ? cause : new Error(String(cause)));
      }
    });
    socket.on('error', reject);
  });
}

export async function connectSignerWallet(socketPath: string): Promise<Wallet> {
  const hello = await ask(socketPath, { v: SIGNER_PROTOCOL_VERSION, op: 'address' });
  const address = hello['address'];
  if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/u.test(address)) {
    throw new Error(`signer at ${socketPath} did not report a usable address`);
  }

  let unlocked = true;
  return {
    address: address as `0x${string}`,
    async signTypedData(message: TypedDataMessage): Promise<`0x${string}`> {
      if (!unlocked) throw new WalletLockedError();
      const reply = await ask(socketPath, { v: SIGNER_PROTOCOL_VERSION, op: 'sign', payload: message });
      const signature = reply['signature'];
      if (typeof signature !== 'string') {
        throw new Error(String(reply['error'] ?? 'signer returned no signature'));
      }
      return signature as `0x${string}`;
    },
    lock(): void {
      unlocked = false;
    },
    isUnlocked(): boolean {
      return unlocked;
    },
  };
}
