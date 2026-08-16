# Security

Purser decides whether money moves. Treat defects here as security defects by default.

## Reporting a vulnerability

Report privately through [GitHub security advisories](https://github.com/RegardV/x402-purser/security/advisories/new). Please do not open a public issue for anything that could be used to make a daemon sign something it should not.

Useful reports include the version, what the daemon was configured to allow, and the sequence of requests that produced the outcome. A failing test against `test/adversarial.test.ts` is the ideal form.

Expect an acknowledgement within a few days. This is a single-author project with no service level agreement.

## Scope

**In scope.** Anything that causes Purser to sign a payment its policy should have refused, to spend past an envelope or the account allowance, to accept a claim it should not have authenticated, to leak the wallet key or an agent key, or to lose track of committed budget.

**Out of scope.** Compromise of the operator's user account, which is trusted by design. An agent misusing spend it was legitimately granted. Sellers overcharging within an authorised ceiling. Anything requiring the wallet key, which Purser does not defend against once it is out.

## Known limitations

These are documented, not defects. See the [threat model](docs/superpowers/specs/2026-08-16-threat-model.md)
for the full analysis.

- **The signer has no cumulative limit (found 2026-08-16, open).** It enforces a ceiling per
  payment and keeps no running total, so a caller holding the socket can obtain unlimited in-policy
  signatures to a recipient of its choosing and drain the token balance a ceiling at a time. A
  proof of concept produced twenty valid authorizations totalling twenty times the ceiling. The fix
  is a persisted windowed total in the signer. Until it lands, the hot wallet balance is the only
  effective bound.

- Enforcement exists only at the moment of signing. A signed authorization is valid until it expires regardless of later policy changes.
- Payments made on other rails are not governed by any envelope here.
- No external security audit has been performed.
