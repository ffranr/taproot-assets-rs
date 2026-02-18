# taproot-assets-core

Core no-std logic for Taproot Assets. This crate is backend-agnostic and expects
crypto operations to be supplied by a `TaprootOps` implementation.

## Verification

This crate exposes the core proof verification flow used by both the SDK and
the ZK verifier.

Key entry points include `verify_proofs`, `verify_genesis_reveal`, and the
claim-level helpers (anchor, taproot, stxo, and asset claims) that the ZK
guests mirror. Claim outputs now surface output indices, proof version, and
meta hash data needed for join verification.

## Test Vectors

The `proof_vectors` test reads upstream vectors from
`external/taproot-assets-upstream/proof/testdata` and skips when they are not
available.
