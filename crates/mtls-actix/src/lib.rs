//! Actix-web middleware for mTLS authentication.
//!
//! This crate provides Actix-web middleware for integrating mTLS authentication
//! with IP whitelisting into Actix-web applications.

#![warn(missing_docs)]

/// Actix-web middleware for mTLS authentication.
pub mod middleware;

/// Re-export commonly used types.
pub mod prelude {
    pub use crate::middleware::*;
}
