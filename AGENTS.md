# AGENTS.md

This file provides guidance for AI agents working with this codebase.

## Key Makefile Commands

- `make all` / `make build-all` - Build everything including ZK guest binaries
- `make build` - Build workspace excluding ZK guests
- `make build-zk` - Build ZK guest code (prover circuits) using risc0. 
  Agents should ask before running this command since it is very expensive.
- `make build-rpc` - Vendor protos and regenerate Rust RPC stubs
- `make build-tests` - Compile tests without running them
- `make fmt` - Format code with cargo fmt and dprint
- `make publish-dry-run` - Test publishing crates without actually publishing

## Build Order

The ZK guest binaries must be built before the host-side crates that depend on
them. The `build-all` target handles this automatically.

## ZK Guest Packages

Built with `cargo +nightly-2024-12-15 risczero build`:

- anchor-claim-prover
- taproot-commitment-prover
- stxo-claim-prover
- asset-claim-prover
- join-prover
