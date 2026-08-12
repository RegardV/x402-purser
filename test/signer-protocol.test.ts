import { describe, expect, it } from 'vitest';
import { privateKeyToAccount } from 'viem/accounts';
import { decodeJson, encodeJson } from '../src/signer/protocol.js';
import type { TypedDataMessage } from '../src/wallet.js';

const KEY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';

const PAYLOAD: TypedDataMessage = {
  domain: { name: 'USD Coin', version: '2', chainId: 8453,
            verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' },
  types: { TransferWithAuthorization: [
    { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' } ] },
  primaryType: 'TransferWithAuthorization',
  message: { from: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    to: '0x000000000000000000000000000000000000dEaD',
    value: 1000n, validAfter: 0n, validBefore: 1786529574n,
    nonce: '0xf84e6d30534bfb2ec7380c923f5baea20e7bd3017a6c8e461c4354117112d9ad' },
};

describe('signer protocol codec', () => {
  it('round trips bigint as bigint, not string', () => {
    const back = decodeJson(encodeJson(PAYLOAD)) as TypedDataMessage;
    expect(typeof back.message['value']).toBe('bigint');
    expect(back.message['value']).toBe(1000n);
    expect(back.message['validAfter']).toBe(0n);
    expect(back).toEqual(PAYLOAD);
  });

  it('leaves chainId a plain number', () => {
    const back = decodeJson(encodeJson(PAYLOAD)) as TypedDataMessage;
    expect(typeof back.domain['chainId']).toBe('number');
  });

  // The gate that matters. A codec that alters the payload produces a different signature,
  // and a different signature is an unspendable payment that looks fine in every other test.
  it('a round tripped payload signs to the identical bytes', async () => {
    const account = privateKeyToAccount(KEY);
    const direct = await account.signTypedData(PAYLOAD as never);
    const viaWire = await account.signTypedData(decodeJson(encodeJson(PAYLOAD)) as never);
    expect(viaWire).toBe(direct);
  });

  it('rejects a bigint that is not an integer string', () => {
    expect(() => decodeJson('{"$bigint":"not-a-number"}')).toThrow();
  });
});
