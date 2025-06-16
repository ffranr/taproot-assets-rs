# Taproot Assets Rust Workspace

This workspace provides Rust crates for working with the
[Taproot Assets protocol](https://github.com/lightninglabs/taproot-assets),
including shared types, a gRPC client, and zero-knowledge proof components.

It does **not** implement the protocol itself.

## Workspace Structure

```text
taproot-assets-rs/
├── taproot-assets             # High-level SDK crate
├── taproot-assets-types       # Shared types and serialization logic
├── taproot-assets-rpc         # gRPC client bindings for the Taproot Assets daemon
└── zk/
    ├── taproot-assets-zk-core     # Traits and types for ZK integration
    ├── taproot-assets-zk-verifier # ZK verifier (e.g., for RISC Zero)
    └── guests/
        └── mint-prover            # Guest-side ZK proof logic for minting
```

## Status

🚧 **Work in progress** — this workspace is under active development.\
APIs and internal structure may change without notice.

## License

MIT OR Apache-2.0

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.
