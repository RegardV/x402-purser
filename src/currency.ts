/**
 * Maps a settlement asset to the currency an envelope is written in.
 *
 * Envelope caps are denominated in a currency, but a 402 quotes a contract address. Something has
 * to join them, and it must fail closed: an asset we do not recognise is refused rather than
 * guessed at, because guessing wrong means enforcing a USDC cap against a token worth something
 * else entirely.
 */

const KNOWN_ASSETS = new Map<string, string>([
  // Circle USDC
  ['eip155:8453/0x833589fcd6edb6e08f4c7c32d4f71b54bda02913', 'USDC'], // Base
  ['eip155:1/0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', 'USDC'], // Ethereum
  ['eip155:84532/0x036cbd53842c5426634e7929541ec2318f3dcf7e', 'USDC'], // Base Sepolia
]);

export class UnknownAssetError extends Error {
  constructor(asset: string) {
    super(`asset ${asset} is not a known settlement currency, refusing rather than guessing`);
    this.name = 'UnknownAssetError';
  }
}

/** Returns the currency symbol for an asset, or throws so the gate refuses. */
export function currencyForAsset(asset: string, network?: string): string {
  const bare = asset.toLowerCase();
  const key = network === undefined ? bare : `${network.toLowerCase()}/${bare}`;
  const found = KNOWN_ASSETS.get(key) ?? [...KNOWN_ASSETS].find(([k]) => k.endsWith(`/${bare}`))?.[1];
  if (found === undefined) throw new UnknownAssetError(asset);
  return found;
}
