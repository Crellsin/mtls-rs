//! Rocket fairing for mTLS authentication.

use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Status;
use rocket::{Request, Response, Data};
use mtls_core::validator::ConnectionValidator;
use std::net::IpAddr;
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
        // Extract client IP from the request
        let client_ip = extract_client_ip(request);

        // Validate IP if IP validator is configured
        if let Some(ip_validator) = self.validator.ip_validator() {
            if let Err(e) = ip_validator.validate(client_ip) {
                // If validation fails, we can either reject the request here or set a flag.
                // For now, we'll set a local cache with the error and let the route handle it.
                request.local_cache(|| Some(Err::<Arc<ConnectionValidator>, String>(e.to_string())));
                return;
            }
        }

        // Extract client certificate from header (if present)
        let cert_header = request.headers().get_one("X-Client-Cert");
        if let Some(cert_header) = cert_header {
            // TODO: Validate the client certificate against the CA
            // For now, just log that we received a certificate
            log::debug!("Client certificate present: {:?}", cert_header);
        }

        // Set the validator in local cache for use in routes
        request.local_cache(|| Some(Ok::<Arc<ConnectionValidator>, String>(self.validator.clone())));
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        // If there was an IP validation error, we can set a 403 status
        if let Some(result) = request.local_cache(|| None::<Option<Result<Arc<ConnectionValidator>, String>>>) {
            if let Some(Err(_)) = result {
                response.set_status(Status::Forbidden);
            }
        }
    }
}

/// Extract client IP from the request.
fn extract_client_ip(req: &Request<'_>) -> IpAddr {
    // Try to get the IP from the connection
    if let Some(addr) = req.client_ip() {
        return addr;
    }

    // Try to get from the "X-Forwarded-For" header (if behind proxy)
    if let Some(forwarded_for) = req.headers().get_one("X-Forwarded-For") {
        if let Some(first_ip) = forwarded_for.split(',').next() {
            if let Ok(ip) = first_ip.trim().parse() {
                return ip;
            }
        }
    }

    // Fallback to remote address
    if let Some(addr) = req.remote() {
        return addr.ip();
    }

    // Default to loopback if we can't determine (should not happen in production)
    "127.0.0.1".parse().unwrap()
}
