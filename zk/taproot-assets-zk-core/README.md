# taproot-assets-zk-core

Core traits, types, and logic for Taproot Assets zero-knowledge proofs.

This crate defines the shared interfaces and data structures used by both ZK
provers and verifiers in the Taproot Assets ecosystem. It is backend-agnostic
and designed for integration with proof systems such as
[RISC Zero](https://www.risczero.com/).

## Claims

Claim types are split into:
- Anchor claim: validates anchor transaction inclusion and returns taproot output keys.
- Taproot claim: proves asset commitment inclusion or exclusion for a taproot output.
- STXO claim: proves state transition against a taproot output and proof version.
- Asset claim: proves asset integrity (genesis, meta, group key) and emits asset metadata.
- Join claim: composes the receipts, checks coverage/consistency, and emits the final join output.

Full proof-file replacement by a single ZK proof is still in progress.

## Usage

Add to your `Cargo.toml`:

```toml
taproot-assets-zk-core = { version = "0.0.1" }
```

## License

MIT OR Apache-2.0

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.
