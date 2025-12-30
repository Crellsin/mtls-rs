//! gRPC adapter for mTLS authentication.
//!
//! This crate provides gRPC (tonic) interceptors and credentials for mTLS authentication with IP whitelisting.

#![warn(missing_docs)]

/// gRPC interceptors and credentials for mTLS.
pub mod grpc;

/// Re-export commonly used types.
pub mod prelude {
    pub use crate::grpc::*;
}
