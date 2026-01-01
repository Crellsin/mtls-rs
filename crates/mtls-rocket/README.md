# mtls-rocket

Rocket fairing for mTLS authentication with IP whitelisting.

## Overview

`mtls-rocket` provides a Rocket fairing for integrating mTLS (mutual TLS) authentication and IP whitelisting into your Rocket applications. It validates client certificates and IP addresses before requests reach your route handlers.

## Features

- **IP Whitelist Validation**: Rejects requests from unauthorized IP addresses
- **Certificate Header Extraction**: Extracts client certificates from HTTP headers (X-Client-Cert)
- **Seamless Integration**: Rocket fairing that automatically validates incoming requests
- **Request Guards**: Optional request guards for requiring valid certificates in specific routes

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
mtls-rocket = "0.1.0"
mtls-core = "0.1.0"
```

### Example Server

```rust
#[macro_use] extern crate rocket;

use rocket::{get, launch, routes};
use mtls_rocket::MtlsFairing;
use mtls_core::validator::ConnectionValidator;
use mtls_core::config::ServerConfig;
use std::path::Path;

#[get("/")]
fn hello() -> &'static str {
    "Hello from mTLS-protected Rocket server!"
}

#[launch]
fn rocket() -> _ {
    // Configure mTLS server
    let server_config = ServerConfig::new(
        Path::new("certs/server.crt"),
        Path::new("certs/server.key"),
        Path::new("certs/ca.crt"),
    );

    // Create connection validator
    let validator = ConnectionValidator::create_for_server(server_config)
        .expect("Failed to create connection validator");

    // Create mTLS fairing
    let mtls_fairing = MtlsFairing::new(validator);

    rocket::build()
        .attach(mtls_fairing)
        .mount("/", routes![hello])
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
    let result = validator.validate_outgoing("example.com", 8000).await?;
    
    if result.is_valid {
        println!("Connection validated successfully!");
        
        // Now you can make HTTP requests with the validated connection
    }
    
    Ok(())
}
```

## Configuration

### Server Configuration

The fairing requires a `ConnectionValidator` configured for server use:

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
let fairing = MtlsFairing::new(validator);
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
1. The fairing extracts the client's IP address from the request
2. If an IP whitelist is configured, it validates the IP against allowed networks
3. Unauthorized IPs receive an immediate 403 Forbidden response

### Certificate Validation
1. The fairing looks for client certificates in the `X-Client-Cert` header
2. Certificates are validated against the trusted CA chain
3. Requests without valid certificates are rejected (when client auth is required)

### Request Flow
```
Request → Fairing on_request → Extract IP → Validate IP → Extract Certificate → Validate Certificate
    ↓           ↓                 ↓             ↓               ↓                  ↓
    ↓        [Invalid]         [Reject]      [Missing]       [Invalid]
    ↓                                         ↓                  ↓
    ↓                                      [Optional]         [Reject]
    ↓
 Route Handler (if validation passes)
```

## Advanced Usage

### Request Guards

You can create request guards to require valid certificates in specific routes:

```rust
use rocket::request::{FromRequest, Outcome};
use rocket::Request;

pub struct ValidatedClient {
    pub ip: std::net::IpAddr,
    pub certificate_info: Option<mtls_core::cert::CertificateInfo>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ValidatedClient {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Extract validation result from request local cache
        // This requires extending the fairing to store validation results
        Outcome::Forward(())
    }
}

#[get("/secure")]
fn secure_endpoint(client: ValidatedClient) -> String {
    format!("Hello from secure endpoint! Your IP: {}", client.ip)
}
```

### Configuration via Rocket.toml

You can configure the fairing via Rocket's configuration system:

```toml
# Rocket.toml
[default]
mtls_cert_path = "certs/server.crt"
mtls_key_path = "certs/server.key"
mtls_ca_cert_path = "certs/ca.crt"
mtls_require_client_auth = true

[default.mtls_ip_whitelist]
ipv4 = ["192.168.1.0/24", "10.0.0.0/8"]
```

Then in your Rocket application:

```rust
use rocket::figment::Figment;

let figment = Figment::from(rocket::Config::default())
    .merge(("mtls_cert_path", "certs/server.crt"))
    .merge(("mtls_key_path", "certs/server.key"))
    .merge(("mtls_ca_cert_path", "certs/ca.crt"));

let rocket = rocket::custom(figment)
    .attach(mtls_fairing)
    .mount("/", routes![hello]);
```

## Error Handling

The fairing returns appropriate HTTP status codes:

- **403 Forbidden**: IP address not in whitelist or invalid certificate
- **400 Bad Request**: Invalid or missing client certificate (when required)
- **500 Internal Server Error**: Configuration or validation errors

## Security Considerations

### IP Spoofing
- The fairing trusts the IP address provided by Rocket's connection info
- When behind proxies, ensure `X-Forwarded-For` headers are properly validated
- Consider using a trusted proxy layer for accurate IP extraction

### Certificate Security
- Always use strong private keys (RSA 2048-bit minimum, prefer ECDSA)
- Regularly rotate certificates and update whitelists
- Monitor for certificate expiration

### Deployment
- Deploy the fairing in production behind a reverse proxy (nginx, Apache)
- Use hardware security modules (HSM) for private key storage in production
- Enable detailed logging for security audits

## Testing

Test your mTLS-protected endpoints:

```rust
#[cfg(test)]
mod tests {
    use rocket::local::blocking::Client;
    use rocket::http::Status;
    use super::rocket;

    #[test]
    fn test_mtls_protected_endpoint() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        
        // Test without certificate header (should fail if client auth required)
        let response = client.get("/").dispatch();
        
        // Adjust expectations based on configuration
        if client_auth_required {
            assert_eq!(response.status(), Status::Forbidden);
        } else {
            assert_eq!(response.status(), Status::Ok);
        }
    }
}
```

## Limitations

### Current Limitations
- Certificate validation from headers only (not from TLS handshake at HTTP layer)
- Header-based certificates require proxy termination of TLS
- No built-in certificate revocation checking (CRL/OCSP)

### Future Improvements
- Direct TLS termination in Rocket (when Rocket supports mTLS natively)
- Certificate revocation support
- More flexible certificate extraction strategies
- Built-in request guards for certificate validation

## License

licensed under:

- GNU GPL-3.0 license
at your option.

## Contributing

Contributions are welcome! Please see the main project repository for contribution guidelines.
