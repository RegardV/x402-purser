# Privilege separated signer

> **Superseded in part, 2026-08-16.** The security claims in this document were falsified by audit.
> It states that a compromised Purser "cannot drain the wallet"; in fact the signer had no
> cumulative limit, so unlimited in-policy signatures could be obtained. Kept unedited as the
> historical record of what was built and why. The authoritative analysis is
> [the threat model](../specs/2026-08-16-threat-model.md).


**Status:** approved
**Date:** 2026-08-12

## Problem

The wallet key lives in the Purser daemon's memory. That daemon also opens outbound HTTPS
connections to sellers and parses their responses, which makes it the component most likely to be
compromised and the worst possible place to keep a key.

Cloud KMS looked like the fix and is not sufficient. KMS signs any 32 byte digest presented to it.
IAM can say who may call `Sign`; it cannot say what may be signed. A compromised daemon computes
the digest of a transaction that drains the wallet, asks KMS to sign it, and KMS complies. KMS
prevents key theft, not key use.

## Approach

Split the daemon at the boundary the `Wallet` interface already draws. The signer becomes a
separate process, running as a separate user, with no network access, that refuses to sign anything
that is not a payment.

```
purser         network, parses seller 402s, runs the gate
   |           unix socket, structured EIP-712 payload
purser-signer  no network, holds the key, validates, signs
```

The signer never accepts a raw digest. It accepts structured typed data and computes the digest
itself, so there is no code path that produces a signature over an attacker chosen hash. A fully
compromised Purser can at worst cause payments that were already inside policy. It cannot drain the
wallet, approve a spender, or move native currency.

This is a stronger guarantee than KMS provides, and the same seam accepts a KMS or YubiHSM adapter
later. Local validation and hardware custody are complementary rather than alternatives.

## Components

**`src/signer/validate.ts`** Pure validation. Takes typed data and a `SignerPolicy`, returns void or
throws `SignerRefusedError` with a stable code. No IO, so it is exhaustively testable.

**`src/signer/server.ts`** The signer process. Reads the key from stdin at startup, listens on a
unix socket, validates every request, signs with `unlockWallet`, returns the signature.

**`src/socket-wallet.ts`** `socketWallet(path)` implements `Wallet` by forwarding `signTypedData`
over the socket. Drop in replacement for `unlockWallet` inside the daemon.

**`src/signer/cli.ts`** The `purser-signer` binary.

## Signer policy

The signer enforces, independently of anything the daemon claims:

| Check | Refusal code |
| --- | --- |
| `primaryType` is `TransferWithAuthorization` | `not_a_payment` |
| `domain.verifyingContract` is on the token allowlist | `unknown_token` |
| `domain.chainId` is on the chain allowlist | `unknown_chain` |
| `message.from` equals the signer's own address | `wrong_payer` |
| `message.value` is at or below the signer's hard ceiling | `exceeds_signer_ceiling` |
| `validBefore` is in the future and within the max horizon | `bad_validity_window` |
| `types` contains exactly the EIP-3009 shape | `unexpected_types` |

The ceiling is deliberately duplicated policy. The daemon's envelope is the primary control; the
signer's ceiling is a backstop that holds when the daemon is the thing that failed. It is set once
at startup and is not reachable over the socket.

## Wire protocol

Newline delimited JSON, matching the existing daemon socket for consistency.

Request `{ "v": 1, "domain": {...}, "types": {...}, "primaryType": "...", "message": {...} }`
Response `{ "v": 1, "signature": "0x..." }` or `{ "v": 1, "error": "code: detail" }`

Socket mode `0660`, owned by the signer user with a group the daemon user belongs to. The daemon
cannot read the signer's memory because they are different users.

## Hardening

Shipped as a systemd unit template:

```
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
```

`PrivateNetwork=yes` is the load bearing one. The process holding the key has no network namespace,
so even arbitrary code execution inside it cannot exfiltrate the key. It can only reach the socket.

## What this does not fix

- The signer still holds the key in memory. It is a much smaller and better contained process, not
  a hardware boundary. YubiHSM 2 supports secp256k1 and slots into the same seam when wanted.
- A compromised daemon can still cause in policy payments. That is inherent: the daemon's job is to
  authorise payments, so compromising it buys the ability to authorise payments.
- TPM 2.0 and YubiKey PIV are not options. Both are NIST curve devices and neither signs secp256k1.

## Testing

The gate that matters is adversarial, against the validator: a transaction shaped payload, a raw
digest, a wrong `from`, an unknown token, an unknown chain, an over ceiling value, an expired
window, and a tampered `types` block are each refused with the right code. Plus an end to end test
proving the daemon pays correctly through the socket, so the split does not silently break payment.
