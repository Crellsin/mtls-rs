//! Rocket fairing for mTLS authentication.

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Status;
use rocket::{Request, Response, Data};
use mtls_core::validator::ConnectionValidator;
use std::sync::Arc;

/// Rocket fairing for mTLS authentication.
#[derive(Clone)]
pub struct MtlsFairing {
    /// Connection validator for mTLS.
    validator: Arc<ConnectionValidator>,
}

impl MtlsFairing {
    /// Creates a new MtlsFairing with the given connection validator.
    pub fn new(validator: ConnectionValidator) -> Self {
        Self {
            validator: Arc::new(validator),
        }
    }
}

#[rocket::async_trait]
impl Fairing for MtlsFairing {
    fn info(&self) -> Info {
        Info {
            name: "mTLS Authentication Fairing",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _data: &mut Data<'_>) {
        // TODO: Extract client certificate from request and validate
        // For now, just set a local cache with the validator for use in routes
        request.local_cache(|| self.validator.clone());
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, _response: &mut Response<'r>) {
        // Nothing to do for now
    }
}
