//! High-level convenience API for Taproot Assets.
//!
//! Re-export low-level crates and.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "rpc")]
pub use taproot_assets_rpc as rpc;
