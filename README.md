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
        ├── anchor-claim-prover        # ZK guest for anchor tx/merkle verification
        ├── taproot-commitment-prover  # ZK guest for taproot commitment proofs
        ├── stxo-claim-prover          # ZK guest for STXO proof verification
        ├── asset-claim-prover         # ZK guest for asset integrity (genesis/meta/group key)
        └── join-prover                # ZK guest for receipt composition (WIP)
```

## Status

🚧 **Work in progress** — this workspace is under active development.\
APIs and internal structure may change without notice.

## ZK Progress

- Proof verification is partitioned into anchor, taproot, stxo, asset, and join claims.
- Join verification enforces output coverage and output-index consistency across claims.
- Core vectors live in `external/taproot-assets-upstream/proof/testdata` and are exercised by
  `cargo test -p taproot-assets-core --test proof_vectors` (skips if vectors are missing).
- ZK parity tests compare join output against core verification with
  `RUN_ZK_PARITY=1 cargo test -p taproot-assets-zk-verifier --test zk_parity` and require
  guest ELFs under `target/riscv32im-risc0-zkvm-elf/docker`.

## Roadmap

Full proof-file replacement by a single ZK proof is in progress. See
`docs/zk-proof-verification-plan.md` for current gaps.

## License

MIT OR Apache-2.0

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE) for details.
