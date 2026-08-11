# Who told the agent it could spend? Make sure it was not the agent

A response to Soheima Canton's "Who told the agent it could spend?" (AAIF, 10 August 2026)

Canton's piece is the clearest short description of the stateless MCP and x402 gateway pattern I have read. The sequence is right, the header flow is right, and the observation that separating payment enforcement from tool execution lets you scale the two independently is the sort of thing that only becomes obvious once someone writes it down. If you are building paid tool calls, start there.

I want to pick up the title, because the body answers a different question than the one on the masthead. "Who told the agent it could spend?" is a question about authority. What follows it is a precise account of how a payment moves: agent asks, gateway prices, wallet approves, agent retries. That is the mechanism. The authority question gets one sentence:

> Put spend limits on the agent's wallet. A wallet turns a user's budget into rules that apply across paid tools. The agent can compare a price with those rules before it pays.

Everything hard lives in that last clause. If the agent compares the price to the rules, the agent is the one enforcing the rules. We have spent the last few weeks building the enforcement layer that sentence implies, and the interesting result is how much of the design is forced once you refuse to let the agent hold the ruler.

## The quote has to come from the seller

An agent that reports the price it is about to pay is an agent that can misreport it. Not because models are malicious, but because the agent is software running in a process the operator does not control, calling a service the operator did not write. Prompt injection is the loud version of this. The quiet version is a parsing bug.

So the price cannot be an input to the policy check. It has to be read out of the seller's own `PAYMENT-REQUIRED` response, by the component holding the key, at the moment of decision. The agent is allowed to say one thing about money: a ceiling. "I am willing to pay up to this much for this." That is a statement about intent, which the agent legitimately owns, rather than a statement about price, which it does not.

This inverts the usual shape. The agent does not fetch a price and ask permission. It asks for a resource, and something else does the fetching, the reading, and the deciding.

## The wallet is the wrong unit of identity

A wallet with a key and a spend limit can tell you that four hundred dollars left the account this week. It cannot tell you which of your six agents spent it, and it cannot stop one of them without stopping all of them.

This matters more than it sounds. If policy attaches to the wallet, then a single misbehaving agent, or a single agent whose credential leaked, means freezing the account. Every other agent stops working while you sort it out. The blast radius of one compromised component is the entire operation.

The alternative is agent identity beneath the accountholder: each agent gets its own keypair and its own policy envelope, with the account's allowance as a ceiling they all share. Revoking one is a row update. The others never notice. Settlement still resolves to one accountholder, which is what the finance side needs, while enforcement resolves to one agent, which is what the operations side needs. Those are different questions and a single wallet answers only the first.

## Approval belongs to an intent, not to a session

The article's flow ends with "the agent sends the request again." Between the wallet approving and the retry landing, the seller is free to quote something different. Nothing in the protocol prevents it.

If the approval is a token the agent carries, that re-quote inherits it. The fix is not subtle, it is just easy to skip: separate the intent from the attempt. An intent is "buy this thing, up to this much." An attempt is one signed try against one specific quote. A second attempt gets checked against both ceilings from scratch, and never inherits the decision that admitted the first. Retries are the normal case in payments, not the exception, so this is load-bearing rather than defensive.

## Settlement should be observed, not reported

In the gateway pattern as drawn, the agent drives the retry and therefore learns the outcome first. Whatever the ledger records is the agent's account of how its own payment went.

We ended up having the enforcement layer replay the request itself and read the response directly. That is a small structural change with a large consequence: the record of what happened is a first-hand observation rather than a report from the party with the most reason to be wrong about it. It also means the component that reserved the budget is the component that learns whether to confirm or release it, with no round trip through the thing being governed.

## The failure paths are where the money actually leaks

The happy path in these articles is always fine. The interesting states are the other ones, and they are the states that decide whether a spend limit is real.

Two we hit, both caught by tests rather than by review:

A payment can settle while the response is lost. Money moved and nobody knows. Releasing the budget is wrong, because the money is gone; confirming it is wrong, because you have no evidence. It needs a third state that keeps consuming the allowance until it is reconciled against the settlement record. Anything else quietly double-spends the same budget.

And a reservation taken before signing must be released when signing fails. We locked the wallet mid-flight in a test and watched the budget stay held for a payment that could never happen. Every signing failure would have permanently burned allowance until the period rolled over. The test that caught it was one we added beyond the plan, because the drafted assertion was weak enough to pass over it.

Spend limits are not a comparison. They are an accounting system, and accounting systems are judged on their failure modes.

## Two payments, one envelope

The `pay_invoice` example deserves a note, and the article is scrupulous about it: the x402 charge is the provider's fee for invoking the tool, and it is separate from the amount owed on `inv-4417`. The tool then "uses the agent's existing payment authority" to settle the invoice itself.

Both are payments the agent caused. Only the smaller one passed the wallet's rules. The larger one moved on a different rail, under an authority granted somewhere else, and the x402 policy envelope never saw it.

This is a boundary rather than a defect. Payment policy at the HTTP layer governs payments routed through the HTTP layer, and that is a coherent thing to be. But the title's question applies to both payments, and a reader skimming the pattern could reasonably come away thinking the envelope covered the invoice. Worth naming, because "the agent has a spend limit" and "the agent's spending is limited" are not the same claim.

## Where this leaves us

We have built the enforcement layer described above and released it as Purser: a local daemon holding the key, agents talking to it over a unix socket with signed requests, per-agent envelopes bounded by a pooled account allowance, reserve-then-confirm accounting, and the quote read from the seller rather than accepted from the agent. It has an adversarial test suite whose premise is that the agent fully controls its own process and still cannot exceed its envelope.

What it does not yet have is a real on-chain payment. Everything to date is verified against stubs and the reference implementation, which is enough to prove the policy logic and not enough to prove the money moves. That is the next piece of work, and I would rather say so than let a test count imply more than it earns.

The gateway pattern Canton describes is the right shape. The question its title asks is the right question. The answer cannot be the agent.
