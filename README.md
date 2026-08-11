# Purser

A purser is the officer who holds and disburses funds on behalf of others, under rules. That is
this project.

Purser gives an AI agent an **instrument**, not your wallet. Each agent gets its own signing key
and its own policy envelope: how much per payment, how much per rolling window, which hosts, which
currency, when it expires. Envelopes nest and can only narrow. Every agent draws on one shared
account allowance, so ten agents and one agent have the same worst case.

Payments are x402 over EIP-3009 on Base. Nothing is custodial. The wallet is yours.

## Why a separate process

If the policy lived in the same process as the agent, the agent could rewrite it. Purser holds the
key and the rules, and the agent never sees either. It asks Purser to pay for something; Purser
fetches the price from the seller itself, checks it against that agent's envelope, and only then
signs.

The agent supplying the price and the recipient would be the hole: a compromised agent could name
an approved host and substitute its own address. So those come from the seller's own 402 response,
never from the caller.

## What is here today

The enforcement core, tested. Envelopes and attenuation, a pooled account allowance, per-instrument
Ed25519 credentials, an intent and attempt record so a re-quote after a price change cannot inherit
the original approval, and a ledger with reserve-then-confirm and an in-doubt state that cannot
double-spend.

Not yet built: the signing path, the HTTP proxy, the socket server and key custody.

## Scope of the guarantee

Purser bounds payments **routed through it**. It does not bound authority an agent holds elsewhere.
If an agent also carries an unrelated API key, or pays a tool that then acts using separate
authority, no envelope here sees it, and no payment layer could.

## Licence

Apache-2.0, matching `@x402/core` and `@x402/evm` for the patent grant.
