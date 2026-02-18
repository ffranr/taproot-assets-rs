//! High-level convenience API for Taproot Assets.
//!
//! Re-export low-level crates and.

#![cfg_attr(not(feature = "std"), no_std)]

/// Re-export of taproot-assets-core for backend implementations.
pub use taproot_assets_core as core;

#[cfg(feature = "rpc")]
pub use taproot_assets_rpc as rpc;

/// Host-side verification helpers backed by bitcoin/secp256k1.
pub mod verify;
