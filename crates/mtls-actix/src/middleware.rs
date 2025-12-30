//! Actix Web middleware for mTLS authentication.

use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::StatusCode;
use actix_web::Error;
use actix_web::body::BoxBody;
use mtls_core::validator::ConnectionValidator;
use std::future::{ready, Ready};
use std::net::IpAddr;
use std::rc::Rc;

/// Actix Web middleware for mTLS authentication.
#[derive(Clone)]
pub struct MtlsMiddleware {
    /// Connection validator for mTLS.
    validator: Rc<ConnectionValidator>,
}

impl MtlsMiddleware {
    /// Creates a new MtlsMiddleware with the given connection validator.
    pub fn new(validator: ConnectionValidator) -> Self {
        Self {
            validator: Rc::new(validator),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for MtlsMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = MtlsMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(MtlsMiddlewareService {
            service: Rc::new(service),
            validator: self.validator.clone(),
        }))
    }
}

pub struct MtlsMiddlewareService<S> {
    service: Rc<S>,
    validator: Rc<ConnectionValidator>,
}

impl<S, B> Service<ServiceRequest> for MtlsMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let validator = self.validator.clone();

        Box::pin(async move {
            // Extract client IP from the request
            let client_ip = extract_client_ip(&req);

            // Validate IP if IP validator is configured
            if let Some(ip_validator) = validator.ip_validator() {
                if ip_validator.validate(client_ip).is_err() {
                    let response = actix_web::HttpResponse::build(StatusCode::FORBIDDEN)
                        .body("IP address not allowed");
                    return Err(Error::from(actix_web::error::ErrorForbidden("IP address not allowed")));
                }
            }

            // Extract client certificate from header (if present)
            let cert_header = req.headers().get("X-Client-Cert");
            if let Some(cert_header) = cert_header {
                // TODO: Validate the client certificate against the CA
                // For now, just log that we received a certificate
                log::debug!("Client certificate present: {:?}", cert_header);
            }

            // Continue with the request
            service.call(req).await
        })
    }
}

/// Extract client IP from the request.
fn extract_client_ip(req: &ServiceRequest) -> IpAddr {
    // First try to get the IP from the connection info (handles X-Forwarded-For)
    if let Some(addr) = req.connection_info().realip_remote_addr() {
        if let Ok(ip) = addr.parse() {
            return ip;
        }
    }

    // Fallback to peer address
    if let Some(addr) = req.connection_info().peer_addr() {
        if let Ok(ip) = addr.parse() {
            return ip;
        }
    }

    // Default to loopback if we can't determine (should not happen in production)
    "127.0.0.1".parse().unwrap()
}
