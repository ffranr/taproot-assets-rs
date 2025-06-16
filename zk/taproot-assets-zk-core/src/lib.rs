#![no_std]
#![no_main]

extern crate alloc;

pub mod mint {
    use serde::{Deserialize, Serialize};

    use risc0_zkvm::sha::Impl as Sha256Impl;
    use risc0_zkvm::sha::Sha256;

    /// A Merkle proof for a transaction in a block.
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
    pub struct VerifyMerkleProofInput {
        /// The transaction ID which is expected to be committed in the Merkle tree.
        pub txid: [u8; 32],

        /// The Merkle proof containing the nodes and direction bits which are used in conjunction
        /// with the transaction ID to verify the Merkle root.
        pub proof: TxMerkleProof,

        /// The expected Merkle root which commits to the transaction ID.
        pub merkle_root: [u8; 32],
    }

    /// Hash two Merkle nodes together using double-SHA-256.
    fn hash_nodes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        // Concatenate the two nodes into a 64-byte buffer.
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(a);
        buf[32..].copy_from_slice(b);

        // Double-SHA-256 using zk-VM gadget.
        let h = Sha256Impl::hash_bytes(&Sha256Impl::hash_bytes(&buf).as_bytes());

        h.as_bytes().try_into().unwrap()
    }

    /// Verify a Merkle proof for a transaction ID against the expected Merkle root.
    pub fn verify_tx_merkle_proof(input: &VerifyMerkleProofInput) -> bool {
        let nodes = &input.proof.nodes;
        let direction_bits = &input.proof.bits;

        // Ensure that the number of nodes matches the number of direction bits.
        if nodes.len() != direction_bits.len() {
            return false;
        }

        // Attempt to derive the Merkle root from the transaction ID and the proof nodes and
        // directional bits.
        let mut current = input.txid;
        for (node, bit) in nodes.iter().zip(direction_bits.iter()) {
            // Swap the current node with the sibling node based on the direction bit.
            let (left, right) = if *bit {
                (current, *node)
            } else {
                (*node, current)
            };

            // Hash the current node with the sibling node based on the direction bit.
            current = hash_nodes(&left, &right);
        }

        current == input.merkle_root
    }
}
