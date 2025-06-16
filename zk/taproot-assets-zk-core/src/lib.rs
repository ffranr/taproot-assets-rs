#![no_std]
#![no_main]

extern crate alloc;

pub mod mint {
    use serde::{Deserialize, Serialize};
    use taproot_assets_types::proof::TxMerkleNode;

    // use bitcoin::{hashes::Hash};
    use risc0_zkvm::sha::Sha256;
    use risc0_zkvm::{sha::Impl as Sha256Impl, Digest};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct TxMerkleProof {
        /// The list of sibling hashes along the Merkle path from the transaction
        /// up to the root.
        pub nodes: alloc::vec::Vec<[u8; 32]>,

        /// Direction bits: `false` means the node is on the left, `true` means on the right.
        /// The bits correspond to entries in `nodes`.
        pub bits: alloc::vec::Vec<bool>,
    }

    #[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
    pub struct GuestInput {
        pub txid: [u8; 32],
        pub proof: TxMerkleProof,
        pub merkle_root: [u8; 32],
    }

    fn hash_branches(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        // concat(a, b)
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(a);
        buf[32..].copy_from_slice(b);

        // double-SHA-256 using zk-VM gadget
        let first = Sha256Impl::hash_bytes(&buf);
        let second = Sha256Impl::hash_bytes(&first.as_bytes());

        second.as_bytes().try_into().unwrap()
    }

    pub fn verify_tx_merkle_proof(input: &GuestInput) -> bool {
        // Parse transaction from input.
        let mut current = input.txid;

        // Verify Merkle path.
        let proof = &input.proof;
        // assert_eq!(
        //     proof.nodes.len(),
        //     proof.bits.len(),
        //     "nodes/bits length mismatch"
        // );

        for (node, bit) in proof.nodes.iter().zip(proof.bits.iter()) {
            let (left, right) = if *bit {
                (current, *node)
            } else {
                (*node, current)
            };
            current = hash_branches(&left, &right);
        }

        current == input.merkle_root
    }
}
