//! Actix-web extractors for mTLS authentication.

use actix_web::dev::Payload;
use actix_web::{FromRequest, HttpRequest, Error};
use actix_web::error::ErrorUnauthorized;
use mtls_core::validator::ConnectionValidator;
use std::future::{Future, ready};
use std::pin::Pin;
use std::rc::Rc;
use std::net::IpAddr;

/// Extracts and validates client certificate information from mTLS requests.
#[derive(Debug, Clone)]
pub struct ValidCertificate {
    /// Client IP address.
    pub client_ip: IpAddr,
    /// Certificate subject (if certificate is present and valid).
    pub certificate_subject: Option<String>,
    /// Certificate issuer (if certificate is present and valid).
    pub certificate_issuer: Option<String>,
}

impl ValidCertificate {
    /// Creates a new ValidCertificate from request data.
    pub fn new(
        client_ip: IpAddr,
        certificate_subject: Option<String>,
        certificate_issuer: Option<String>,
    ) -> Self {
        Self {
            client_ip,
            certificate_subject,
            certificate_issuer,
        }
    }

    /// Returns whether a valid certificate is present.
    pub fn has_certificate(&self) -> bool {
        self.certificate_subject.is_some() && self.certificate_issuer.is_some()
    }

    /// Returns the client IP address.
    pub fn client_ip(&self) -> &IpAddr {
        &self.client_ip
    }

    /// Returns the certificate subject, if available.
    pub fn certificate_subject(&self) -> Option<&str> {
        self.certificate_subject.as_deref()
    }

    /// Returns the certificate issuer, if available.
    pub fn certificate_issuer(&self) -> Option<&str> {
        self.certificate_issuer.as_deref()
    }
}

impl FromRequest for ValidCertificate {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // Try to get the validator from request extensions (set by MtlsMiddleware)
        let validator = if let Some(validator) = req.extensions().get::<Rc<ConnectionValidator>>() {
            validator.clone()
        } else {
            // If no validator is found, the middleware wasn't added or failed
            return Box::pin(ready(Err(
                ErrorUnauthorized("mTLS middleware not configured or failed to validate connection")
            )));
        };

        // Get client IP from request extensions (set by MtlsMiddleware)
        let client_ip = if let Some(ip) = req.extensions().get::<IpAddr>().cloned() {
            ip
        } else {
            // If no IP is found, try to extract from request
            extract_client_ip(req)
        };

        // Validate IP if IP validator is configured
        if let Some(ip_validator) = validator.ip_validator() {
            if let Err(e) = ip_validator.validate(client_ip) {
                return Box::pin(ready(Err(
                    ErrorUnauthorized(format!("IP address not allowed: {}", e))
                )));
            }
        }

        // Extract and validate client certificate from header
        let certificate_info = req.headers()
            .get("X-Client-Cert")
            .and_then(|header| header.to_str().ok())
            .and_then(|cert_pem| {
                // TODO: In a production implementation, validate the certificate against the CA
                // For now, we'll just parse and extract basic information
                parse_certificate_info(cert_pem).ok()
            });

        let (certificate_subject, certificate_issuer) = if let Some(info) = certificate_info {
            (Some(info.subject), Some(info.issuer))
        } else {
            (None, None)
        };

        // Check if certificate is required (you could make this configurable)
        // For now, we require a certificate for this extractor
        if certificate_subject.is_none() || certificate_issuer.is_none() {
            return Box::pin(ready(Err(
                ErrorUnauthorized("Valid client certificate is required")
            )));
        }

        Box::pin(ready(Ok(ValidCertificate::new(
            client_ip,
            certificate_subject,
            certificate_issuer,
        ))))
    }
}

/// Extract client IP from the request.
fn extract_client_ip(req: &HttpRequest) -> IpAddr {
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

/// Basic certificate information extracted from PEM.
#[derive(Debug)]
struct CertificateInfo {
    subject: String,
    issuer: String,
}

/// Parse basic certificate information from PEM string.
fn parse_certificate_info(pem_str: &str) -> Result<CertificateInfo, Box<dyn std::error::Error>> {
    use x509_parser::prelude::*;
    
    // Remove PEM headers/footers if present
    let pem_str = pem_str.replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace('\n', "")
        .replace('\r', "");
    
    // Decode base64
    let bytes = base64::decode(&pem_str)?;
    
    // Parse X.509 certificate
    let (_, cert) = X509Certificate::from_der(&bytes)?;
    
    Ok(CertificateInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
    })
}
