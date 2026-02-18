# ZK Proof Verification Partition Plan (RISC0)

## Current State
- Anchor claim implemented end-to-end (core verification + zk guest):
  `taproot-assets-core/src/verify/tx.rs`,
  `zk/taproot-assets-zk-core/src/verify/tx.rs`,
  `zk/guests/anchor-claim-prover/src/main.rs`.
- Taproot commitment claim implemented (core verification + zk guest):
  `taproot-assets-core/src/verify/proof.rs`,
  `taproot-assets-core/src/verify/taproot_proof.rs`,
  `zk/guests/taproot-commitment-prover/src/main.rs`.
- STXO claim implemented (core verification + zk guest):
  `taproot-assets-core/src/verify/proof.rs`,
  `zk/guests/stxo-claim-prover/src/main.rs`.
- Asset integrity claim implemented (genesis/meta + group key verification):
  `taproot-assets-core/src/verify/proof.rs`,
  `taproot-assets-core/src/verify/group_key_reveal.rs`,
  `zk/guests/asset-claim-prover/src/main.rs`.
- Join/aggregation exists and verifies anchor/asset plus per-output taproot/STXO
  receipts and optional split-root receipts:
  `zk/guests/join-prover/src/main.rs`,
  `zk/taproot-assets-zk-core/src/verify/join.rs`,
  `zk/taproot-assets-zk-verifier/src/bin/run_join.rs`.
  - Verifies receipt integrity for anchor/asset/taproot/stxo/split-root claims.
  - Checks taproot output key consistency across anchor/taproot/stxo/split-root.
  - Enforces taproot claim coverage for all anchor P2TR outputs.
  - Enforces STXO claim coverage whenever STXO proofs are required.
  - Commits combined output (anchor txid, block hash/height, taproot output key,
    taproot commitment root+sum, asset id, group key, meta hash, proof version).
- Proof-chain claim implemented (checksum chain + prev_out linkage + last
  outpoint output):
  `zk/taproot-assets-zk-core/src/verify/proof_chain.rs`,
  `zk/guests/proof-chain-claim-prover/src/main.rs`.

## Motivation
- Keep guest RAM usage small by splitting verification into narrow circuits.
- Enable parallel proof generation on the host.
- Allow optional receipt aggregation/recursion without redoing heavy work.

## Partitioned Claims (per proof file entry)
1) Anchor Claim (tx/merkle/header/outpoint)
   - Inputs: anchor tx, merkle proof, block header+height, prev outpoint,
     internal key + tapscript root (if needed).
   - Outputs (digest): anchor txid, output index, derived taproot output key.

2) Taproot Commitment Claim (inclusion/exclusion + split root)
   - Inputs: taproot proofs, asset, expected taproot output key (from anchor
     claim).
   - Outputs (digest): tap commitment root (hash+sum) and proof version.

3) STXO Claim(s) (per output or per asset batch)
   - Inputs: taproot proof (with STXO proofs), full asset (prev_witnesses),
     proof version, expected taproot output key, inclusion flag.
   - Behavior: for v1 transfer roots, require all expected STXO proofs; for v0
     proofs, validate only if STXO proofs are present; skip tapscript-only
     outputs.
   - Outputs (digest): set of verified script keys (or hash of sorted keys).

4) Asset Integrity Claim (genesis/meta/group key)
   - Inputs: asset, genesis reveal, meta reveal, group key reveal.
   - Outputs (digest): asset id, group key (if any), meta hash (if any).

5) Proof-Chain Claim (file continuity)
   - Inputs: prev outpoints + proof file checksum chain.
   - Outputs (digest): last proof checksum and last outpoint.

## Aggregation Strategy
- Host runs claims in parallel and combines receipts.
- Join guest verifies receipt integrity and checks digest consistency
  (anchor/taproot/stxo taproot output key alignment), then commits a combined
  output digest.
- Use continuations for large proofs if a single claim exceeds guest limits.
- Keep journals tiny (commit digests/flags only) so join/recursion guests stay
  low-memory.

## Implementation Notes (Rust Modules)
- Anchor Claim: `taproot-assets-core/src/verify/tx.rs`.
- Taproot Claim: `taproot-assets-core/src/verify/proof.rs` +
  `taproot-assets-core/src/verify/taproot_proof.rs`.
- STXO Claim: `taproot-assets-core/src/verify/proof.rs`,
  `zk/guests/stxo-claim-prover`.
- Asset Claim: `taproot-assets-core/src/verify/group_key_reveal.rs` +
  asset validation in `proof.rs`.
- Proof-Chain Claim:
  `zk/taproot-assets-zk-core/src/verify/proof_chain.rs`,
  `zk/guests/proof-chain-claim-prover/src/main.rs`.
- ZkProofFile Format:
  `zk/taproot-assets-zk-core/src/verify/zk_proof_file.rs`,
  `zk/taproot-assets-zk-verifier/src/zk_proof_file.rs`.

## ZkProofFile Format (V1)
- Blob encoding: `magic(4 bytes: "TZKF") || bincode(v2, serde payload)`.
- Payload type: `ZkProofFile`.
  - `format_version`
  - `proof_file_version`
  - `proof_count`
  - `proof_chain_tip` (last checksum in the source proof-file chain)
  - `proof_chain_claim` (proof-chain claim output digest)
  - `proof_chain_receipt` (opaque serialized proof-chain receipt bytes)
  - `entries` (one `ZkProofFileEntry` per proof index)
- Entry type: `ZkProofFileEntry`.
  - `proof_index`
  - `proof_checksum` (source `HashedProof.hash`)
  - `join_output` (committed join digest payload)
  - `join_receipt` (opaque serialized join receipt bytes)
- Deterministic commitments:
  - Entry commitment: SHA256 over domain tag + index/checksum + committed
    `join_output` digest + SHA256(`join_receipt`).
  - Artifact digest: SHA256 over domain tag + header fields + ordered entry
    commitments.
- Canonical validity checks:
  - `format_version` must match V1.
  - `proof_count` must equal `entries.len()`.
  - `entries` must be strictly increasing by `proof_index`.
  - each `proof_index` must be `< proof_count`.

## Gaps / Remaining Work (for Full Proof-File Replacement)
Status update: exclusion and split-root claims are wired into the ZK join flow,
join commits `meta_hash`, join enforces per-output claim coverage for taproot/STXO,
and the proof-chain claim is implemented as a dedicated ZK guest.

1) Additional inputs are parsed but not verified. `Proof.additional_inputs`
   (nested `File`s) are not checked by `taproot-assets-core` or ZK guests, so
   recursive verification is missing.
2) `Proof.challenge_witness` ownership proofs are not verified anywhere in core
   or ZK, so challenge/ownership validation is missing.
3) `Proof.alt_leaves` are decoded but not validated against taproot commitments,
   which means arbitrary alternative leaves are not covered by current proofs.
4) Anchor claim does not validate block header PoW/chain context. The ZK claim
   checks merkle inclusion and output key only; full header validation would
   require a separate header/chain claim or light-client integration.
5) Join consistency checks still primarily bind claims through output-key
   alignment and coverage. It does not cryptographically bind the asset-claim
   digest to the inclusion tap-commitment leaf contents beyond shared key data.
6) Continuations/segmentation are not implemented. Large proofs may exceed
   RISC0 guest limits; the plan mentions continuations but none exist today.
7) Tooling is demo-level. `zk/taproot-assets-zk-verifier` provides runners, but
   there is no production CLI/workflow to generate a single ZK artifact that
   replaces an entire proof file, nor integration into the main
   `taproot-assets` pipeline.
8) Test/fixture coverage for ZK guests and join consistency is still limited.
   Existing parity coverage is narrow and not an exhaustive equivalence suite
   against full `verify_proofs` across all variants.
