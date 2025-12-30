//! Certificate information extraction.

use x509_parser::prelude::*;

/// Information extracted from a certificate.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CertificateInfo {
    /// Subject distinguished name.
    pub subject: String,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Validity start date.
    pub valid_from: String,
    /// Validity end date.
    pub valid_to: String,
    /// Serial number.
    pub serial_number: String,
    /// Signature algorithm.
    pub signature_algorithm: String,
}

impl CertificateInfo {
    /// Creates CertificateInfo from an X509Certificate.
    pub fn from_x509(cert: &X509Certificate) -> Self {
        Self {
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            valid_from: cert.validity().not_before.to_string(),
            valid_to: cert.validity().not_after.to_string(),
            serial_number: cert.serial.to_string(),
            signature_algorithm: cert.signature_algorithm.algorithm.to_string(),
        }
    }

    /// Returns the subject distinguished name.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the issuer distinguished name.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the validity start date.
    pub fn valid_from(&self) -> &str {
        &self.valid_from
    }

    /// Returns the validity end date.
    pub fn valid_to(&self) -> &str {
        &self.valid_to
    }

    /// Returns the serial number.
    pub fn serial_number(&self) -> &str {
        &self.serial_number
    }

    /// Returns the signature algorithm.
    pub fn signature_algorithm(&self) -> &str {
        &self.signature_algorithm
    }
}
