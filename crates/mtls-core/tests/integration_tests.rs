//! Integration tests for mTLS core functionality.

use mtls_core::{ConnectionValidator, ServerConfig, ClientConfig, CertificateManager};
use std::path::Path;

#[test]
fn test_certificate_manager_creation() {
    // Use test certificates
    let cert_path = Path::new("../../tests/certs/server/server.crt");
    let key_path = Path::new("../../tests/certs/server/server.key");
    let ca_cert_path = Path::new("../../tests/certs/server/ca.crt");

    let manager = CertificateManager::for_server(cert_path, key_path, ca_cert_path);
    assert!(manager.is_ok());
}

#[test]
fn test_certificate_manager_client_creation() {
    let cert_path = Path::new("../../tests/certs/client/client.crt");
    let key_path = Path::new("../../tests/certs/client/client.key");
    let ca_cert_path = Path::new("../../tests/certs/client/ca.crt");

    let manager = CertificateManager::for_client(cert_path, key_path, Some(ca_cert_path));
    assert!(manager.is_ok());
}

#[test]
fn test_server_config_creation() {
    let config = ServerConfig::new(
        Path::new("../../tests/certs/server/server.crt"),
        Path::new("../../tests/certs/server/server.key"),
        Path::new("../../tests/certs/server/ca.crt"),
    );
    // ServerConfig::new does not return a Result, so we just check that it's created
    assert_eq!(config.cert_path, Path::new("../../tests/certs/server/server.crt"));
    assert_eq!(config.key_path, Path::new("../../tests/certs/server/server.key"));
    assert_eq!(config.ca_cert_path, Path::new("../../tests/certs/server/ca.crt"));
}

#[test]
fn test_client_config_creation() {
    let config = ClientConfig::new(
        Path::new("../../tests/certs/client/client.crt"),
        Path::new("../../tests/certs/client/client.key"),
    )
    .with_ca_cert_path(Path::new("../../tests/certs/client/ca.crt"));
    // ClientConfig::new and with_ca_cert_path do not return a Result, so we just check that it's created
    assert_eq!(config.cert_path, Path::new("../../tests/certs/client/client.crt"));
    assert_eq!(config.key_path, Path::new("../../tests/certs/client/client.key"));
    assert_eq!(config.ca_cert_path, Some(Path::new("../../tests/certs/client/ca.crt").to_path_buf()));
}

#[test]
fn test_connection_validator_creation() {
    let server_config = ServerConfig::new(
        Path::new("../../tests/certs/server/server.crt"),
        Path::new("../../tests/certs/server/server.key"),
        Path::new("../../tests/certs/server/ca.crt"),
    );

    let server_validator = ConnectionValidator::create_for_server(server_config);
    assert!(server_validator.is_ok());

    let client_config = ClientConfig::new(
        Path::new("../../tests/certs/client/client.crt"),
        Path::new("../../tests/certs/client/client.key"),
    )
    .with_ca_cert_path(Path::new("../../tests/certs/client/ca.crt"));

    let client_validator = ConnectionValidator::create_for_client(client_config);
    assert!(client_validator.is_ok());
}
