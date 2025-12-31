# mtls-actix

Actix Web middleware for mTLS authentication with IP whitelisting.

## Overview

`mtls-actix` provides Actix Web middleware for integrating mTLS (mutual TLS) authentication and IP whitelisting into your Actix applications. It validates client certificates and IP addresses before requests reach your handlers.

## Features

- **IP Whitelist Validation**: Rejects requests from unauthorized IP addresses before TLS handshake
- **Certificate Header Extraction**: Extracts client certificates from HTTP headers (X-Client-Cert)
- **Seamless Integration**: Drop-in middleware for Actix Web applications
- **Async Validation**: All validation happens asynchronously without blocking

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
mtls-actix = "0.1.0"
mtls-core = "0.1.0"
```

### Example Server

```rust
use actix_web::{web, App, HttpServer, Responder};
use mtls_actix::MtlsMiddleware;
use mtls_core::validator::ConnectionValidator;
use mtls_core::config::ServerConfig;
use std::path::Path;

async fn hello() -> impl Responder {
    "Hello from mTLS-protected server!"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Configure mTLS server
    let server_config = ServerConfig::new(
        Path::new("certs/server.crt"),
        Path::new("certs/server.key"),
        Path::new("certs/ca.crt"),
    );

    // Create connection validator
    let validator = ConnectionValidator::create_for_server(server_config)
        .expect("Failed to create connection validator");

    // Create mTLS middleware
    let mtls_middleware = MtlsMiddleware::new(validator);

    // Start HTTP server with mTLS middleware
    HttpServer::new(move || {
        App::new()
            .wrap(mtls_middleware.clone())
            .route("/", web::get().to(hello))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

### Example Client

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
    
    // Validate connection before making requests
    let result = validator.validate_outgoing("example.com", 443).await?;
    
    if result.is_valid {
        println!("Connection validated successfully!");
        
        // Now you can make HTTP requests with the validated connection
        // or use the validator to configure your HTTP client
    }
    
    Ok(())
}
```

## Configuration

### Server Configuration

The middleware requires a `ConnectionValidator` configured for server use:

```rust
use mtls_core::config::ServerConfig;
use ipnetwork::IpNetwork;

let server_config = ServerConfig::new(
    Path::new("server.crt"),
    Path::new("server.key"),
    Path::new("ca.crt"),
)
.with_client_ipv4_whitelist(vec![
    IpNetwork::new("192.168.1.0".parse()?, 24)?,
    IpNetwork::new("10.0.0.0".parse()?, 8)?,
])
.with_require_client_auth(true);

let validator = ConnectionValidator::create_for_server(server_config)?;
let middleware = MtlsMiddleware::new(validator);
```

### Client Configuration

For clients that need to validate outgoing connections:

```rust
use mtls_core::config::ClientConfig;

let client_config = ClientConfig::new(
    Path::new("client.crt"),
    Path::new("client.key"),
)
.with_ca_cert_path(Path::new("ca.crt"))
.with_verify_server(true);

let validator = ConnectionValidator::create_for_client(client_config)?;
```

## How It Works

### IP Validation
1. The middleware extracts the client's IP address from the request
2. If an IP whitelist is configured, it validates the IP against allowed networks
3. Unauthorized IPs receive an immediate 403 Forbidden response

### Certificate Validation
1. The middleware looks for client certificates in the `X-Client-Cert` header
2. Certificates are validated against the trusted CA chain
3. Requests without valid certificates are rejected (when client auth is required)

### Request Flow
```
Request → Extract IP → Validate IP → Extract Certificate → Validate Certificate → Handler
    ↓           ↓             ↓               ↓                  ↓
    ↓        [Invalid]     [Reject]        [Missing]         [Invalid]
    ↓                                        ↓                  ↓
    ↓                                     [Optional]         [Reject]
```

## Advanced Usage

### Custom Certificate Headers

By default, the middleware looks for certificates in the `X-Client-Cert` header. You can extract certificates from different headers by extending the middleware:

```rust
// Custom middleware that extracts from different headers
pub struct CustomMtlsMiddleware {
    validator: Rc<ConnectionValidator>,
    cert_header: String,
}

impl CustomMtlsMiddleware {
    pub fn new(validator: ConnectionValidator, cert_header: &str) -> Self {
        Self {
            validator: Rc::new(validator),
            cert_header: cert_header.to_string(),
        }
    }
}
```

### Combining with Other Middleware

The mTLS middleware can be combined with other Actix middleware:

```rust
App::new()
    .wrap(Logger::default())
    .wrap(mtls_middleware)
    .wrap(Compress::default())
    .route("/", web::get().to(handler))
```

## Error Handling

The middleware returns appropriate HTTP status codes:

- **403 Forbidden**: IP address not in whitelist
- **400 Bad Request**: Invalid or missing client certificate (when required)
- **500 Internal Server Error**: Configuration or validation errors

## Security Considerations

### IP Spoofing
- The middleware trusts the IP address provided by Actix's connection info
- When behind proxies, ensure `X-Forwarded-For` headers are properly validated
- Consider using a trusted proxy layer for accurate IP extraction

### Certificate Security
- Always use strong private keys (RSA 2048-bit minimum, prefer ECDSA)
- Regularly rotate certificates and update whitelists
- Monitor for certificate expiration

### Deployment
- Deploy the middleware in production behind a reverse proxy (nginx, Apache)
- Use hardware security modules (HSM) for private key storage in production
- Enable detailed logging for security audits

## Testing

Test your mTLS-protected endpoints:

```rust
#[cfg(test)]
mod tests {
    use actix_web::{test, web, App};
    use super::*;

    #[actix_web::test]
    async fn test_mtls_protected_endpoint() {
        // Create test validator with test certificates
        // ...
        
        let app = test::init_service(
            App::new()
                .wrap(MtlsMiddleware::new(validator))
                .route("/", web::get().to(hello))
        ).await;
        
        // Test with valid certificate header
        let req = test::TestRequest::get()
            .insert_header(("X-Client-Cert", "valid-cert-base64"))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }
}
```

## Limitations

### Current Limitations
- Certificate validation from headers only (not from TLS handshake at HTTP layer)
- Header-based certificates require proxy termination of TLS
- No built-in certificate revocation checking (CRL/OCSP)

### Future Improvements
- Direct TLS termination in Actix (when Actix supports mTLS natively)
- Certificate revocation support
- More flexible certificate extraction strategies

## License

Dual-licensed under either:

- MIT License
- Apache License, Version 2.0

at your option.

## Contributing

Contributions are welcome! Please see the main project repository for contribution guidelines.
