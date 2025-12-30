//! Example implementations for mTLS authentication.
//!
//! This crate provides example servers and clients using the mTLS authentication library.

#![warn(missing_docs)]

/// Example Actix-web server with mTLS.
#[cfg(feature = "actix")]
pub mod actix_example;

/// Example Rocket server with mTLS.
#[cfg(feature = "rocket")]
pub mod rocket_example;

/// Example TCP server and client with mTLS.
#[cfg(feature = "tcp")]
pub mod tcp_example;

/// Example gRPC server and client with mTLS.
#[cfg(feature = "grpc")]
pub mod grpc_example;
