# Purser threat model

**Status:** authoritative
**Date:** 2026-08-16
**Supersedes the security claims in:** `2026-08-12-privilege-separated-signer-design.md`

Every control in Purser must trace to an adversary named here. Controls that do not are
decoration, and adversaries that appear later mean this document was wrong and needs amending
rather than another component being bolted on.

## Why this exists

Purser was built by discovering adversaries one at a time. The agent could not be trusted, so a
daemon was added. The daemon parses hostile seller responses, so a signer was added. The signer had
no aggregate limit, so a counter was proposed. Each step was locally correct and the sequence has
no end, because **no software component we can add is trustworthy by construction.**

The question that ends the regress is not "which component do we trust" but "what bounds the loss
when the component we trust is the one that fails".

## The invariant

> The total value that can leave the wallet in a window is bounded by something no compromised
> software can raise.

Nothing enforced in software satisfies this on its own, because software is what gets compromised.
Only the wallet's own balance does, since the token contract will not transfer what is not there.
Every other control below reduces blast radius or shortens time to detect. Those are worth a great
deal and they are not the invariant.

## Trust boundaries

| Boundary | Separated by | What crosses it |
| --- | --- | --- |
| Agent to daemon | unix socket, 0600, Ed25519 signed claims | a resource URL and a ceiling, never a price |
| Daemon to signer | unix socket, 0660, separate unix users | structured EIP-712 typed data, never a digest |
| Signer to key | process memory, no network namespace | nothing; the key does not leave |
| Hot wallet to cold reserve | a human, out of band | funding transfers only, never automated |

The last boundary is the only one not made of our code, which is why it is the only one that
bounds loss rather than reducing it.

## Adversaries

| Adversary | Capability | Loss is bounded by |
| --- | --- | --- |
| A1 Malicious or hijacked agent | Full control of its own process, can craft any request to the daemon socket, can be prompt injected by a seller | bounded by its envelope: per transaction cap, period cap, host and currency allowlists, and the pooled account allowance shared with every sibling agent |
| A2 Malicious seller | Chooses the price, the payload, and the response body the daemon parses; may collude with an agent | bounded by the agent's ceiling and envelope, since the quote is read from the seller's own 402 but checked against limits the seller cannot influence |
| A3 Compromised daemon | Arbitrary code execution as the daemon user, holds the ledger, can request any signature the signer will grant | bounded by the signer's own window total and per payment ceiling, and ultimately by the hot balance. It cannot obtain a signature over an arbitrary transaction, so native currency and approvals are out of reach |
| A4 Compromised signer | Arbitrary code execution as the signer user, holds the key in memory | bounded by the hot wallet balance and by the outstanding authorization horizon. Nothing in software constrains this adversary, which is why the hot balance must be sized as the acceptable loss |
| A5 Local unprivileged process in the purser group | Can connect to the signer socket directly, bypassing the daemon entirely | bounded by exactly the same signer window and ceiling as A3, because the signer trusts no caller |
| A6 Root on the host | Reads any process memory, replaces any binary | bounded by the hot balance only. No userspace control survives root, and we do not pretend otherwise |
| A7 Holder of a leaked authorization | Possesses a signed EIP-3009 payload that has not yet been broadcast | bounded by that payload's value and its validBefore, and by EIP-3009's own nonce, which makes it single use |

## What bounds the loss

Three mechanisms, in descending order of how much they can be relied upon.

**The hot balance, which is arithmetic.** Fund the signing wallet with only what is acceptable to
lose in one incident, from a cold reserve, out of band. Total loss under complete compromise of
every component is the hot balance. This is enforced by the token contract, not by Purser, and it
is the only control that survives A6.

**The signer's window total, which is our code but small.** The signer enforces a per payment
ceiling and a cumulative total across a rolling window, persisted so a restart does not reset it.
This bounds A3 and A5 to the window total rather than to the whole balance, and it bounds A4 only
until the attacker chooses to ignore it. The signer stays small and free of business logic
precisely so this remains reviewable.

**The authorization horizon, which bounds duration.** Every signature is a bearer instrument until
it expires. A short horizon converts a lasting liability into a brief one and limits A7. The signer
caps the horizon regardless of what the seller requests.

Detection is the fourth thing, and Purser currently has none. The signer's append only journal is
the intended source, giving both the window accounting and an audit trail that the daemon cannot
write to.

## Residual risk

Stated plainly, because the previous version of these documents did not.

- A compromised signer, or root, spends the hot balance. No software control we can write prevents
  this. The mitigation is a smaller hot balance.
- A compromised daemon spends up to the signer's window total, and chooses the recipient. Per agent
  envelopes do not constrain it, because it is the thing that enforces them.
- Authorizations already signed remain valid until they expire, including after the compromise is
  discovered and everything is shut down.
- The signer's window total resets if its persisted journal is deleted by someone able to write as
  the signer user, which is A4 or A6.

**Loss is bounded by the hot balance, by the window, and by how fast the operator notices. It is not
bounded by our code being correct.** A deployment that finds this unacceptable should hold a smaller
hot balance rather than expect more from the software.

## What we do not defend against

- Root on the host, or anyone who can read arbitrary process memory.
- A supply chain compromise of Node, viem, the x402 packages, or Purser itself.
- A user who funds the hot wallet with more than they can afford to lose, which converts every
  bounded risk above into an unbounded one.
- Sellers overcharging within an authorised ceiling. That is a commercial dispute, not an attack.
- Denial of service. An attacker who stops payments costs money but does not take it.
- On-chain enforcement of any of the above. USDC's transferWithAuthorization recovers the payer
  with a raw ecrecover, so a contract cannot be the payer and no on-chain policy can apply on this
  rail. This was verified rather than assumed, and it is why the controls are where they are.

## How this changes the design

The signer currently has a per payment ceiling and no cumulative accounting, which the audit of
2026-08-16 proved insufficient: twenty in-policy signatures drained twenty times the ceiling to an
arbitrary recipient. The corrections that follow from this document are:

1. The signer owns total outflow. It gains a persisted append only journal and a windowed total.
   The component that must be trusted stops being the one with no memory.
2. The daemon owns allocation, not safety. Envelopes, intents and the ledger remain exactly as
   built, and stop being described as though they bound a compromised daemon.
3. The horizon is capped in the low minutes rather than defaulting to a day.
4. The hot and cold split becomes documented operational procedure, not an assumption.
