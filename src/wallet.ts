/**
 * Wallet custody.
 *
 * Holds the signing account in memory and refuses to sign once locked. The shape matches
 * ClientEvmSigner from @x402/evm, so it can be handed straight to the scheme registration
 * without an adapter.
 *
 * Limit, stated plainly: the key sits in this process's memory while unlocked. Root on the
 * machine can read it. That is not fixable in userspace, and on-chain enforcement is not
 * available on this rail because USDC's transferWithAuthorization does a raw ecrecover, so a
 * contract cannot be the payer. Holding the key here and never handing it to an agent is the
 * strongest available position, not a compromise we settled for.
 */

import { privateKeyToAccount } from 'viem/accounts';

export interface TypedDataMessage {
  domain: Record<string, unknown>;
  types: Record<string, unknown>;
  primaryType: string;
  message: Record<string, unknown>;
}

export interface Wallet {
  readonly address: `0x${string}`;
  signTypedData(message: TypedDataMessage): Promise<`0x${string}`>;
  lock(): void;
  isUnlocked(): boolean;
}

export class WalletLockedError extends Error {
  constructor() {
    super('wallet is locked; nothing can be signed until it is unlocked again');
    this.name = 'WalletLockedError';
  }
}

export function unlockWallet(privateKeyHex: string): Wallet {
  if (!/^0x[0-9a-fA-F]{64}$/u.test(privateKeyHex)) {
    throw new Error('private key must be 0x followed by 64 hex characters');
  }
  let account: ReturnType<typeof privateKeyToAccount> | null = privateKeyToAccount(
    privateKeyHex as `0x${string}`,
  );
  const address = account.address;

  return {
    address,
    async signTypedData(message: TypedDataMessage): Promise<`0x${string}`> {
      if (account === null) throw new WalletLockedError();
      return account.signTypedData(message as Parameters<typeof account.signTypedData>[0]);
    },
    lock(): void {
      account = null;
    },
    isUnlocked(): boolean {
      return account !== null;
    },
  };
}
