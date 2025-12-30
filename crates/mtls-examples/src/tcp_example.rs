//! Example TCP server and client with mTLS authentication.

use mtls_core::{ConnectionValidator, ServerConfig, ClientConfig};
use std::path::Path;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Run the TCP server example.
pub async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    // Load server configuration from test certificates
    let server_config = ServerConfig::new(
        Path::new("tests/certs/server/server.crt"),
        Path::new("tests/certs/server/server.key"),
        Path::new("tests/certs/server/ca.crt"),
    )?;

    // Create connection validator for server
    let server_validator = ConnectionValidator::create_for_server(server_config)?;

    // Bind to localhost:8443
    let addr = SocketAddr::from(([127, 0, 0, 1], 8443));
    let listener = TcpListener::bind(&addr).await?;
    println!("TCP server listening on {}", addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        println!("Accepted connection from {}", peer_addr);

        // Validate incoming connection and upgrade to TLS
        let (validation_result, tls_stream) = server_validator.validate_incoming(stream).await?;

        if !validation_result.is_valid {
            eprintln!("Connection validation failed: {:?}", validation_result.failure_reason);
            continue;
        }

        println!("Connection validated: {:?}", validation_result);

        // Handle the connection
        tokio::spawn(async move {
            if let Err(e) = handle_connection(tls_stream).await {
                eprintln!("Error handling connection: {}", e);
            }
        });
    }
}

async fn handle_connection(mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).await?;
    let request = String::from_utf8_lossy(&buffer[..n]);
    println!("Received: {}", request);

    let response = b"Hello from mTLS server!";
    stream.write_all(response).await?;
    stream.flush().await?;
    Ok(())
}

/// Run the TCP client example.
pub async fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    // Load client configuration from test certificates
    let client_config = ClientConfig::new(
        Path::new("tests/certs/client/client.crt"),
        Path::new("tests/certs/client/client.key"),
    )
    .with_ca_cert_path(Path::new("tests/certs/client/ca.crt"))?;

    // Create connection validator for client
    let client_validator = ConnectionValidator::create_for_client(client_config)?;

    // Connect to server at localhost:8443
    let addr = SocketAddr::from(([127, 0, 0, 1], 8443));
    println!("Connecting to {}", addr);

    // Validate outgoing connection and get TLS stream
    let validation_result = client_validator.validate_outgoing("127.0.0.1", 8443).await?;

    if !validation_result.is_valid {
        return Err(format!("Connection validation failed: {:?}", validation_result.failure_reason).into());
    }

    println!("Connection validated: {:?}", validation_result);

    // The validate_outgoing doesn't return the stream, so we need to create a new one.
    // Instead, let's use the socket factory from the validator to create a client socket.
    let socket_factory = client_validator.socket_factory();
    let tls_stream = socket_factory.create_client_socket(addr).await?;

    // Send a message
    let message = b"Hello from mTLS client!";
    let mut stream = tls_stream;
    stream.write_all(message).await?;
    stream.flush().await?;

    // Read response
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).await?;
    let response = String::from_utf8_lossy(&buffer[..n]);
    println!("Received: {}", response);

    Ok(())
}
