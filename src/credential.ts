/**
 * Per-instrument credentials.
 *
 * Each agent gets an Ed25519 keypair at issuance. The vault stores ONLY the public key; the private key is returned
 * once and carried by the agent. Keeping every private key in one vault would mean co-resident code that reads the
 * vault holds them all, a credential has to be issued to its holder, not kept in a shared drawer.
 *
 * The daemon verifies a signature rather than accepting a name. Signing rather than a bearer secret is deliberate: a
 * bearer token would let the daemon impersonate the agent, a public key never can.
 *
 * Limit: this defends against co-resident code. It does not defend against root, which can read the agent's own key
 * material or patch this binary.
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';

export interface InstrumentKeypair {
  readonly publicKeyPem: string;
  readonly privateKeyPem: string;
}

/**
 * What the agent asks for. `ceilingAtomic` is the agent's own limit for this request, not a price. The daemon
 * discovers the price from the seller, so the agent cannot understate it or name its own recipient.
 */
export interface PaymentClaim {
  readonly agentRef: string;
  readonly resourceUrl: string;
  readonly ceilingAtomic: string;
  readonly currency: string;
  readonly nonce: string;
  readonly timestamp: string;
}

export function mintInstrumentKeypair(): InstrumentKeypair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  };
}

/** Field order is fixed here, not by object key order, so a caller cannot change the signed bytes. */
export function canonicalClaim(claim: PaymentClaim): string {
  return [claim.agentRef, claim.resourceUrl, claim.ceilingAtomic, claim.currency, claim.nonce, claim.timestamp].join(
    '\n',
  );
}

export function signClaim(claim: PaymentClaim, privateKeyPem: string): string {
  return sign(null, Buffer.from(canonicalClaim(claim), 'utf8'), createPrivateKey(privateKeyPem)).toString('base64');
}

export function verifyClaim(claim: PaymentClaim, signatureBase64: string, publicKeyPem: string): boolean {
  try {
    return verify(
      null,
      Buffer.from(canonicalClaim(claim), 'utf8'),
      createPublicKey(publicKeyPem),
      Buffer.from(signatureBase64, 'base64'),
    );
  } catch {
    return false;
  }
}
