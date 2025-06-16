use crate::error::Error;
use alloc::{string::ToString, vec::Vec};
use bitcoin::hashes::{sha256::Hash as Sha256Hash, Hash};
use bitcoin::io::Read;
use serde::{Deserialize, Serialize};

/// Represents a node in an MS-SMT (Merkle Sum Sparse Merkle Tree).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MssmtNode {
    /// The hash of the node.
    pub hash: Sha256Hash,
    /// The sum of the node.
    pub sum: u64,
}

/// Represents a merkle proof for a MS-SMT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MssmtProof {
    // Corresponds to mssmt.Proof
    /// Siblings that should be hashed with the leaf and its parents to arrive at the root.
    pub nodes: Vec<MssmtNode>,
}

impl MssmtProof {
    pub fn decode_tlv<R: Read>(mut r: R) -> Result<Self, Error> {
        // Decode the compressed MSSMT proof format:
        // - 2 bytes: number of nodes (uint16, big endian)
        // - For each node: 32 bytes hash + 8 bytes sum (uint64, big endian)
        // - Packed bits (32 bytes for 255 bits max representing empty tree bits)

        // Read number of nodes (uint16, big endian)
        let mut num_nodes_bytes = [0u8; 2];
        r.read_exact(&mut num_nodes_bytes).map_err(Error::Io)?;
        let num_nodes = u16::from_be_bytes(num_nodes_bytes) as usize;

        // Read the non-empty nodes
        let mut explicit_nodes = Vec::with_capacity(num_nodes);
        for _ in 0..num_nodes {
            // Read 32-byte hash
            let mut hash_bytes = [0u8; 32];
            r.read_exact(&mut hash_bytes).map_err(Error::Io)?;
            let hash = Sha256Hash::from_byte_array(hash_bytes);

            // Read 8-byte sum (uint64, big endian)
            let mut sum_bytes = [0u8; 8];
            r.read_exact(&mut sum_bytes).map_err(Error::Io)?;
            let sum = u64::from_be_bytes(sum_bytes);

            explicit_nodes.push(MssmtNode { hash, sum });
        }

        // Read the packed bits (32 bytes for exactly 256 bits)
        // MaxTreeLevels = 256, so MaxTreeLevels / 8 = 32 bytes
        let mut packed_bits = [0u8; 32];
        r.read_exact(&mut packed_bits).map_err(Error::Io)?;

        // Unpack bits - matches Go's UnpackBits function
        // Go uses little-endian bit order: LSB first within each byte
        // Creates len(bytes)*8 = 32*8 = 256 bits
        let mut bits = Vec::with_capacity(256);
        for i in 0..256 {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            let byte_val = packed_bits[byte_idx];
            let bit_set = (byte_val >> bit_idx) & 1 == 1;
            bits.push(bit_set);
        }

        // Reconstruct the full proof by combining explicit nodes with empty tree nodes
        let mut nodes = Vec::new();
        let mut explicit_node_idx = 0;

        // Count how many bits are set to false for validation
        let false_bits = bits.iter().filter(|&&b| !b).count();

        // According to Go logic:
        // - true bit means use empty tree node
        // - false bit means use explicit node
        // So false_bits should equal explicit_nodes.len()
        if false_bits != explicit_nodes.len() {
            return Err(Error::InvalidTlvValue(
                0,
                "Bit/node count mismatch: false bits != explicit nodes".to_string(),
            ));
        }

        for (_level, bit_set) in bits.iter().enumerate() {
            if *bit_set {
                // Bit is set: use empty tree node (matches Go logic)
                nodes.push(MssmtNode {
                    hash: Sha256Hash::all_zeros(),
                    sum: 0,
                });
            } else {
                // Bit is not set: use explicit node (matches Go logic)
                if explicit_node_idx >= explicit_nodes.len() {
                    return Err(Error::InvalidTlvValue(
                        0,
                        "Insufficient explicit nodes for compressed proof".to_string(),
                    ));
                }
                nodes.push(explicit_nodes[explicit_node_idx].clone());
                explicit_node_idx += 1;
            }
        }

        // Verify all explicit nodes were consumed
        if explicit_node_idx != explicit_nodes.len() {
            return Err(Error::InvalidTlvValue(
                0,
                "Too many explicit nodes for compressed proof".to_string(),
            ));
        }

        Ok(MssmtProof { nodes })
    }
}
