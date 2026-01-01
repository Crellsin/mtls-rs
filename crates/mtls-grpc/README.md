# mtls-grpc

gRPC adapter for mTLS authentication with IP whitelisting (Work in Progress).

## Overview

`mtls-grpc` provides gRPC (tonic) interceptors and credentials for integrating mTLS (mutual TLS) authentication and IP whitelisting into your gRPC applications. This crate is currently a work in progress and serves as a placeholder for future gRPC mTLS integration.

## Current Status

⚠️ **Experimental**: This crate is currently a skeleton implementation. The actual gRPC mTLS integration will be added once the underlying tonic version and its API are stabilized for mTLS.

## Planned Features

- **gRPC Server Credentials**: Configure mTLS for gRPC servers
- **gRPC Client Credentials**: Configure mTLS for gRPC clients
- **IP Whitelist Interceptors**: Validate client IP addresses in gRPC calls
- **Certificate Validation**: Extract and validate client certificates in gRPC metadata

## Quick Start (Planned)

Add to your `Cargo.toml`:

```toml
[dependencies]
mtls-grpc = "0.1.0"
mtls-core = "0.1.0"
```

### Example Server (Planned)

```rust
use tonic::transport::Server;
use mtls_grpc::ServerCredentials;
use mtls_core::validator::ConnectionValidator;
use mtls_core::config::ServerConfig;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure mTLS server
    let server_config = ServerConfig::new(
        Path::new("certs/server.crt"),
        Path::new("certs/server.key"),
        Path::new("certs/ca.crt"),
    );

    // Create connection validator
    let validator = ConnectionValidator::create_for_server(server_config)?;

    // Create gRPC server credentials
    let credentials = ServerCredentials::new(validator);

    // Build gRPC server with mTLS
    Server::builder()
        .tls_config(credentials.into_tls_config()?)?
        .add_service(YourServiceServer::new(YourService))
        .serve("127.0.0.1:50051".parse()?)
        .await?;

    Ok(())
}
```

### Example Client (Planned)

```rust
use tonic::transport::Channel;
use mtls_grpc::ClientCredentials;
use mtls_core::validator::ConnectionValidator;
use mtls_core::config::ClientConfig;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure mTLS client
    let client_config = ClientConfig::new(
        Path::new("certs/client.crt"),
        Path::new("certs/client.key"),
    )
    .with_ca_cert_path(Path::new("certs/ca.crt"));

    // Create connection validator
    let validator = ConnectionValidator::create_for_client(client_config)?;

    // Create gRPC client credentials
    let credentials = ClientCredentials::new(validator);

    // Create channel with mTLS
    let channel = Channel::from_static("https://127.0.0.1:50051")
        .tls_config(credentials.into_tls_config()?)?
        .connect()
        .await?;

    // Use channel to create gRPC client
    // let client = YourServiceClient::new(channel);

    Ok(())
}
```

## Architecture (Planned)

### Server Components

1. **ServerCredentials**: Configures TLS for gRPC servers
2. **Connection Validator**: Validates client certificates and IP addresses
3. **gRPC Interceptors**: Validate requests before they reach service handlers

### Client Components

1. **ClientCredentials**: Configures TLS for gRPC clients
2. **Connection Validator**: Validates server certificates
3. **gRPC Interceptors**: Add client certificates to outgoing requests

## Current Implementation

The current implementation provides placeholder structs that will be expanded in future releases:

```rust
// Placeholder structs - to be implemented
pub struct ServerCredentials { /* ... */ }
pub struct ClientCredentials { /* ... */ }
pub struct MtlsInterceptor { /* ... */ }
```

## Roadmap

### v0.1.0 (Current)
- Skeleton implementation
- Basic struct definitions
- Compilation compatibility

### v0.2.0 (Planned)
- Basic tonic TLS integration
- Server and client credential configuration
- Simple certificate validation

### v0.3.0 (Planned)
- IP whitelist validation in interceptors
- Metadata-based certificate extraction
- Comprehensive error handling

### v1.0.0 (Planned)
- Production-ready API
- Performance optimizations
- Full documentation and examples

## Contributing

Contributions are welcome! Since this crate is in early development, we particularly welcome:

1. Tonic TLS integration expertise
2. gRPC interceptor patterns
3. Certificate extraction from gRPC metadata

Please see the main project repository for contribution guidelines.

## License

licensed under:

- GNU GPL-3.0 license
 

## Note

This crate depends on the `mtls-core` crate for certificate and IP validation. The actual gRPC/Tonic integration will be implemented as the underlying libraries stabilize their mTLS support.
