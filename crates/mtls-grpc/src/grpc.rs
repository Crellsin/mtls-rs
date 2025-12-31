//! gRPC (tonic) interceptors and credentials for mTLS authentication.
//! 
//! This module is a work in progress. The actual implementation will be added
//! once the underlying tonic version and its API are stabilized for mTLS.

use mtls_core::validator::ConnectionValidator;
use std::sync::Arc;

/// gRPC server credentials builder for mTLS.
pub struct ServerCredentials {
    /// Connection validator for the server.
    validator: Arc<ConnectionValidator>,
}

impl ServerCredentials {
    /// Creates a new ServerCredentials with the given connection validator.
    pub fn new(validator: ConnectionValidator) -> Self {
        Self {
            validator: Arc::new(validator),
        }
    }

    /// Returns a reference to the connection validator.
    pub fn validator(&self) -> &Arc<ConnectionValidator> {
        &self.validator
    }
}

/// gRPC client credentials builder for mTLS.
pub struct ClientCredentials {
    /// Connection validator for the client.
    validator: Arc<ConnectionValidator>,
}

impl ClientCredentials {
    /// Creates a new ClientCredentials with the given connection validator.
    pub fn new(validator: ConnectionValidator) -> Self {
        Self {
            validator: Arc::new(validator),
        }
    }

    /// Returns a reference to the connection validator.
    pub fn validator(&self) -> &Arc<ConnectionValidator> {
        &self.validator
    }
}

/// Interceptor for gRPC that validates mTLS and IP whitelisting.
#[derive(Clone)]
#[allow(dead_code)]
pub struct MtlsInterceptor {
    /// Connection validator for mTLS.
    validator: Arc<ConnectionValidator>,
}

impl MtlsInterceptor {
    /// Creates a new MtlsInterceptor with the given connection validator.
    pub fn new(validator: ConnectionValidator) -> Self {
        Self {
            validator: Arc::new(validator),
        }
    }
}
