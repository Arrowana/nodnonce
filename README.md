# nodnonce

Send a unique Solana transaction message hash with multiple signatures leveraging ed25519 signature malleability. Unicity is based on the message hash so a single transaction with land

Inspired by https://slowli.github.io/ed25519-quirks/malleability/

Concept:

For a given message we alter r in a way that could be safe, to produce multiple signature for the same message.

Disclaimer: /!\ This is a proof of concept, the corruption brought to ed25519-dalek is unknown, use at your own risk, really, please don't use it

Why not a durable nonce?

This has a similar effect to the usage of a durable nonce, however, the message cannot change, but there is no nonce management to do at all

Possible usage:

- Benchmark different sending pipelines (RPCs...)
- Spam with different signatures while identical message hash to defeat noob grade rate limiting

# Demo

`cargo run -r`
