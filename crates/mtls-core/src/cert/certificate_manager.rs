//! Certificate Manager for mTLS authentication.

use crate::error::{Result, CertificateError};
use std::fs;
use std::path::{Path, PathBuf};
use rustls::{RootCertStore};
use rustls_pemfile::{certs, private_key};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use x509_parser::prelude::*;

/// Manages certificates for mTLS authentication.
#[derive(Debug, Clone)]
pub struct CertificateManager {
    /// Path to the certificate file.
    cert_path: PathBuf,
    /// Path to the private key file.
    key_path: PathBuf,
    /// Path to the CA certificate file (optional).
    ca_cert_path: Option<PathBuf>,
    /// Loaded certificate chain.
    cert_chain: Vec<CertificateDer<'static>>,
    /// Raw private key bytes.
    private_key_raw: Vec<u8>,
    /// Root certificate store for validation.
    root_store: Option<RootCertStore>,
}

impl CertificateManager {
    /// Creates a new CertificateManager by loading certificates from files.
    pub fn new(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        ca_cert_path: Option<impl AsRef<Path>>,
    ) -> Result<Self> {
        let cert_path = cert_path.as_ref().to_path_buf();
        let key_path = key_path.as_ref().to_path_buf();
        
        // Validate paths exist
        if !cert_path.exists() {
            return Err(CertificateError::FileNotFound(cert_path.clone()).into());
        }
        if !key_path.exists() {
            return Err(CertificateError::FileNotFound(key_path.clone()).into());
        }
        
        // Load certificate chain
        let cert_data = fs::read(&cert_path)?;
        let cert_chain = Self::load_certificates(&cert_data)?;
        
        // Load private key raw bytes
        let private_key_raw = fs::read(&key_path)?;
        
        // Load CA certificates if provided
        let (ca_cert_path, root_store) = if let Some(ca_path) = ca_cert_path {
            let ca_path = ca_path.as_ref().to_path_buf();
            if !ca_path.exists() {
                return Err(CertificateError::FileNotFound(ca_path.clone()).into());
            }
            let ca_data = fs::read(&ca_path)?;
            let root_store = Self::load_root_store(&ca_data)?;
            (Some(ca_path), Some(root_store))
        } else {
            (None, None)
        };
        
        Ok(Self {
            cert_path,
            key_path,
            ca_cert_path,
            cert_chain,
            private_key_raw,
            root_store,
        })
    }
    
    /// Creates a CertificateManager for client use.
    pub fn for_client(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        ca_cert_path: Option<impl AsRef<Path>>,
    ) -> Result<Self> {
        Self::new(cert_path, key_path, ca_cert_path)
    }
    
    /// Creates a CertificateManager for server use.
    pub fn for_server(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
        ca_cert_path: impl AsRef<Path>,
    ) -> Result<Self> {
        Self::new(cert_path, key_path, Some(ca_cert_path))
    }
    
    /// Loads certificates from PEM data.
    fn load_certificates(data: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
        let mut reader = std::io::Cursor::new(data);
        let certs_result: std::io::Result<Vec<CertificateDer<'static>>> = certs(&mut reader).collect();
        let certs = certs_result
            .map_err(|e| CertificateError::Parse(format!("Failed to parse certificates: {}", e)))?;
        
        Ok(certs)
    }
    
    /// Parses the private key from the stored raw bytes.
    pub fn parse_private_key(&self) -> Result<PrivateKeyDer<'static>> {
        let mut reader = std::io::Cursor::new(&self.private_key_raw);
        // private_key returns Result<Option<PrivateKeyDer<'static>>>
        match private_key(&mut reader) {
            Ok(Some(key)) => Ok(key),
            Ok(None) => Err(CertificateError::UnsupportedKeyType(
                "No private key found in PEM data".to_string(),
            ).into()),
            Err(e) => Err(CertificateError::Parse(format!("Failed to parse private key: {}", e)).into()),
        }
    }
    
    /// Loads root certificate store from PEM data.
    fn load_root_store(data: &[u8]) -> Result<RootCertStore> {
        let mut reader = std::io::Cursor::new(data);
        let certs_result: std::io::Result<Vec<CertificateDer<'static>>> = certs(&mut reader).collect();
        let certs = certs_result
            .map_err(|e| CertificateError::Parse(format!("Failed to parse CA certificates: {}", e)))?;
        
        let mut root_store = RootCertStore::empty();
        for cert in certs {
            root_store
                .add(cert)
                .map_err(|e| CertificateError::ChainValidation(format!("Failed to add CA certificate: {}", e)))?;
        }
        
        Ok(root_store)
    }
    
    /// Returns a reference to the certificate chain.
    pub fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert_chain
    }
    
    /// Returns a reference to the raw private key bytes.
    pub fn private_key_raw(&self) -> &[u8] {
        &self.private_key_raw
    }
    
    /// Returns a reference to the root certificate store, if any.
    pub fn root_store(&self) -> Option<&RootCertStore> {
        self.root_store.as_ref()
    }
    
    /// Returns the path to the certificate file.
    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }
    
    /// Returns the path to the private key file.
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }
    
    /// Returns the path to the CA certificate file, if any.
    pub fn ca_cert_path(&self) -> Option<&Path> {
        self.ca_cert_path.as_deref()
    }
    
    /// Validates the certificate chain against the root store.
    pub fn validate_certificate_chain(&self) -> Result<()> {
        if let Some(root_store) = &self.root_store {
            // For now, we just check that we have a root store.
            // In a more complete implementation, we would validate the chain.
            if self.cert_chain.is_empty() {
                return Err(CertificateError::Validation("No certificates in chain".to_string()).into());
            }
            // TODO: Implement full chain validation
            Ok(())
        } else {
            Err(CertificateError::Validation("No root store available for validation".to_string()).into())
        }
    }
    
    /// Extracts basic information from the certificate.
    pub fn certificate_info(&self) -> Result<CertificateInfo> {
        if self.cert_chain.is_empty() {
            return Err(CertificateError::Validation("No certificates in chain".to_string()).into());
        }
        
        let cert_data = self.cert_chain[0].as_ref();
        let (_, cert) = X509Certificate::from_der(cert_data)
            .map_err(|e| CertificateError::Parse(format!("Failed to parse X.509 certificate: {}", e)))?;
        
        Ok(CertificateInfo::from_x509(&cert))
    }
}

/// Information extracted from a certificate.
#[derive(Debug, Clone)]
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
}
