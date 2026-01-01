//! Example gRPC server and client with mTLS authentication.
//!
//! Note: The gRPC adapter is currently a work in progress. This example
//! demonstrates the intended usage pattern once the adapter is fully implemented.

use std::path::Path;
use mtls_core::{ConnectionValidator, ServerConfig, ClientConfig};
use mtls_grpc::{ServerCredentials, ClientCredentials};

/// Run the gRPC server example.
pub async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    println!("Note: gRPC adapter is a work in progress. This example shows the intended API.");
    
    // Load server configuration from test certificates
    let server_config = ServerConfig::new(
        Path::new("tests/certs/server/server.crt"),
        Path::new("tests/certs/server/server.key"),
        Path::new("tests/certs/server/ca.crt"),
    )?;

    // Create connection validator for server
    let validator = ConnectionValidator::create_for_server(server_config)?;

    // Create server credentials (once implemented, this would build TLS config)
    let _server_credentials = ServerCredentials::new(validator);

    // TODO: Once implemented, use the credentials to build a tonic server
    // let server = tonic::transport::Server::builder()
    //     .tls_config(server_credentials.build_tls_config()?)?
    //     .serve(...)
    //     .await?;

    println!("gRPC server would start here with mTLS once the adapter is implemented.");
    println!("For now, this is a placeholder example.");
    
    Ok(())
}

/// Run the gRPC client example.
pub async fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    println!("Note: gRPC adapter is a work in progress. This example shows the intended API.");
    
    // Load client configuration from test certificates
    let client_config = ClientConfig::new(
        Path::new("tests/certs/client/client.crt"),
        Path::new("tests/certs/client/client.key"),
    )?
    .with_ca_cert_path(Path::new("tests/certs/client/ca.crt"))?;

    // Create connection validator for client
    let validator = ConnectionValidator::create_for_client(client_config)?;

    // Create client credentials (once implemented, this would build TLS config)
    let _client_credentials = ClientCredentials::new(validator);

    // TODO: Once implemented, use the credentials to build a tonic channel
    // let channel = tonic::transport::Endpoint::from_static("https://127.0.0.1:50051")
    //     .tls_config(client_credentials.build_tls_config("localhost")?)?
    //     .connect()
    //     .await?;

    println!("gRPC client would connect here with mTLS once the adapter is implemented.");
    println!("For now, this is a placeholder example.");
    
    Ok(())
}

/// Main function for the gRPC example.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("gRPC Example for mTLS Authentication");
    println!("=====================================");
    
    // We can't actually run the server and client until the adapter is implemented
    // For now, just show the intended usage
    
    println!("\nServer setup:");
    run_server().await?;
    
    println!("\nClient setup:");
    run_client().await?;
    
    println!("\nNote: The gRPC adapter is marked as experimental in the initial release.");
    println!("Full implementation will be added in a future release.");
    
    Ok(())
}
