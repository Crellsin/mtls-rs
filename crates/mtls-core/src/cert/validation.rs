//! Certificate validation utilities.

use crate::error::{Result, CertificateError};
use x509_parser::prelude::*;
use ::time::OffsetDateTime;

/// Certificate validation functions.
#[derive(Debug, Clone)]
pub struct CertificateValidation;

impl CertificateValidation {
    /// Validates a certificate chain against a time.
    pub fn validate_certificate_chain(
        cert_chain: &[Vec<u8>],
        ca_certs: &[Vec<u8>],
        time: Option<OffsetDateTime>,
    ) -> Result<()> {
        if cert_chain.is_empty() {
            return Err(CertificateError::Validation("Certificate chain is empty".to_string()).into());
        }

        // Parse the end-entity certificate
        let (_, cert) = X509Certificate::from_der(&cert_chain[0])
            .map_err(|e| CertificateError::Parse(format!("Failed to parse certificate: {}", e)))?;

        // Validate the certificate's validity period
        Self::validate_validity(&cert, time)?;

        // TODO: Implement chain validation against CA certificates
        // For now, we just check that we have CA certificates if chain validation is required
        if !ca_certs.is_empty() {
            // Placeholder for chain validation
            Ok(())
        } else {
            Err(CertificateError::Validation("No CA certificates provided for chain validation".to_string()).into())
        }
    }

    /// Validates the certificate's validity period.
    pub fn validate_validity(
        cert: &X509Certificate,
        time: Option<OffsetDateTime>,
    ) -> Result<()> {
        let validity = cert.validity();
        let now = time.unwrap_or_else(OffsetDateTime::now_utc);

        let not_before = validity.not_before.to_datetime();
        let not_after = validity.not_after.to_datetime();

        if not_before > now {
            return Err(CertificateError::NotYetValid.into());
        }

        if not_after < now {
            return Err(CertificateError::Expired.into());
        }

        Ok(())
    }

    /// Checks if a certificate has the required key usage extensions.
    pub fn validate_key_usage(
        cert: &X509Certificate,
        required_key_usage: KeyUsage,
    ) -> Result<()> {
        // TODO: Implement key usage validation
        // For now, we just return Ok(()) as a placeholder
        Ok(())
    }

    /// Checks if a certificate has the required extended key usage.
    pub fn validate_extended_key_usage(
        cert: &X509Certificate,
        required_extended_key_usage: &[&str],
    ) -> Result<()> {
        // TODO: Implement extended key usage validation
        Ok(())
    }
}

/// Key usage flags for certificate validation.
#[derive(Debug, Clone, Copy)]
pub enum KeyUsage {
    /// Digital signature.
    DigitalSignature,
    /// Non-repudiation.
    NonRepudiation,
    /// Key encipherment.
    KeyEncipherment,
    /// Data encipherment.
    DataEncipherment,
    /// Key agreement.
    KeyAgreement,
    /// Key certificate sign.
    KeyCertSign,
    /// CRL sign.
    CrlSign,
    /// Encipher only.
    EncipherOnly,
    /// Decipher only.
    DecipherOnly,
}
