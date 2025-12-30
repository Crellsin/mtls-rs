//! Raw TCP adapter for mTLS authentication.
//!
//! This crate provides raw TCP server and client with mTLS authentication and IP whitelisting.

#![warn(missing_docs)]

/// TCP server and client with mTLS.
pub mod tcp;

/// Re-export commonly used types.
pub mod prelude {
    pub use crate::tcp::*;
}
