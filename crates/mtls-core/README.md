# mtls-core

Core mTLS authentication library with IP whitelisting for Rust applications.

## Overview

`mtls-core` provides a robust, async-first library for mutual TLS (mTLS) authentication with built-in IP whitelisting capabilities. It's designed to be framework-agnostic and can be used with various Rust web frameworks and network protocols.

## Features

- **Certificate Management**: Load and validate X.509 certificates for both clients and servers
- **IP Whitelisting**: Flexible CIDR-based IP validation for IPv4 and IPv6
- **Secure Socket Factory**: Create TLS-secured sockets with automatic certificate validation
- **Connection Validator**: High-level orchestrator for validating incoming and outgoing connections
- **Multiple Backends**: Built-in support for rustls (default) with extensible backend architecture
- **Async/Await**: Fully async using Tokio

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
mtls-core = "0.1.0"
```

### Server Example

```rust
use mtls_core::validator::ConnectionValidator;
use mtls_core::config::ServerConfig;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_config = ServerConfig::new(
        Path::new("certs/server.crt"),
        Path::new("certs/server.key"),
        Path::new("certs/ca.crt"),
    );

    let validator = ConnectionValidator::create_for_server(server_config)?;
    
    // Use validator to validate incoming connections
    // (See TCP adapter or framework-specific adapters for complete examples)
    Ok(())
}
```

### Client Example

```rust
use mtls_core::validator::ConnectionValidator;
use mtls_core::config::ClientConfig;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client_config = ClientConfig::new(
        Path::new("certs/client.crt"),
        Path::new("certs/client.key"),
    )
    .with_ca_cert_path(Path::new("certs/ca.crt"));

    let validator = ConnectionValidator::create_for_client(client_config)?;
    
    // Validate outgoing connection
    let result = validator.validate_outgoing("example.com", 443).await?;
    
    if result.is_valid {
        println!("Connection validated successfully!");
    } else {
        eprintln!("Connection validation failed: {:?}", result.failure_reason);
    }
    
    Ok(())
}
```

## Architecture

### Core Components

1. **CertificateManager**: Handles loading, parsing, and validation of X.509 certificates
2. **IPWhitelistValidator**: Validates IP addresses against configured CIDR ranges
3. **SecureSocketFactory**: Creates TLS-secured sockets with proper client/server authentication
4. **ConnectionValidator**: High-level API that orchestrates certificate and IP validation
5. **TlsConfig**: Configuration for TLS parameters and certificate management

### Adapter Crates

For framework-specific integration, see:

- `mtls-actix`: Actix Web middleware
- `mtls-rocket`: Rocket fairing
- `mtls-tcp`: Raw TCP adapter
- `mtls-grpc`: gRPC (tonic) adapter

## Configuration

### Server Configuration

```rust
use mtls_core::config::ServerConfig;
use ipnetwork::IpNetwork;

let config = ServerConfig::new(
    Path::new("server.crt"),
    Path::new("server.key"),
    Path::new("ca.crt"),
)
.with_client_ipv4_whitelist(vec![
    IpNetwork::new("192.168.1.0".parse()?, 24)?,
    IpNetwork::new("10.0.0.0".parse()?, 8)?,
])
.with_require_client_auth(true);
```

### Client Configuration

```rust
use mtls_core::config::ClientConfig;

let config = ClientConfig::new(
    Path::new("client.crt"),
    Path::new("client.key"),
)
.with_ca_cert_path(Path::new("ca.crt"))
.with_verify_server(true);
```

## Error Handling

The library uses a comprehensive error type `MtlsError` that covers all possible failure modes:

- Certificate parsing and validation errors
- IP whitelist validation failures
- TLS configuration and handshake errors
- I/O and network errors

## Testing

Run the test suite:

```bash
cargo test --workspace
```

The project includes comprehensive integration tests with pre-generated test certificates.

## License

licensed under:

- GNU GPL-3.0 license


## Contributing

Contributions are welcome! Please see the main project repository for contribution guidelines.
