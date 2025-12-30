//! Rocket fairing for mTLS authentication.
//!
//! This crate provides Rocket fairings for integrating mTLS authentication
//! with IP whitelisting into Rocket applications.

#![warn(missing_docs)]

/// Rocket fairing for mTLS authentication.
pub mod fairing;

/// Re-export commonly used types.
pub mod prelude {
    pub use crate::fairing::*;
}
