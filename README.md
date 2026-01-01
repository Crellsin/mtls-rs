# mTLS Authentication System for Rust

A Rust-native implementation of mutual TLS (mTLS) authentication with IP whitelisting for both IPv4 and IPv6. This project provides reusable Rust crates that work on both client and server sides, supporting Actix, Rocket, raw TCP, and gRPC.

## Features

### Core Features

- **Mutual TLS Authentication**: Both client and server authenticate each other using X.509 certificates
- **IP Whitelisting**: Validate client IP addresses against configured whitelists (IPv4/IPv6 CIDR support)
- **Certificate Validation**: Full certificate chain validation, key usage, and extended key usage validation
- **Early Rejection**: IP validation occurs before TLS handshake to reduce resource consumption

### Framework Support

- **Actix-web**: Middleware for mTLS authentication and IP validation
- **Rocket**: Fairing for mTLS authentication and IP validation
- **Raw TCP**: Direct TLS connections with mTLS support
- **gRPC**: Experimental adapter for gRPC services (work in progress)

### Security Features

- TLS 1.2+ minimum requirement
- Modern cipher suites (AES-GCM, ChaCha20-Poly1305)
- Secure defaults with required client authentication
- Certificate chain validation against trusted CAs
- YAML/TOML configuration support

## Project Structure

```bash
mtls-rs/
├── Cargo.toml                    # Workspace configuration
├── crates/
│   ├── mtls-core/               # Core library (certificate, IP validation, TLS)
│   ├── mtls-actix/              # Actix-web middleware
│   ├── mtls-rocket/             # Rocket fairing
│   ├── mtls-tcp/                # Raw TCP adapter
│   ├── mtls-grpc/               # gRPC adapter (tonic/grpcio) - Experimental
│   └── mtls-examples/           # Example implementations
├── README.md                    # This file
├── IMPLEMENTATION_GUIDE.md      # Detailed implementation guide
├── SECURITY.md                  # Security considerations and best practices
└── tests/
    └── certs/                   # Test certificates and generation scripts
```

## Quick Start

### Installation

Add the desired crates to your `Cargo.toml`:

```toml
[dependencies]
mtls-core = "0.1.0"
mtls-actix = { version = "0.1.0", optional = true }  # For Actix-web
mtls-rocket = { version = "0.1.0", optional = true } # For Rocket
mtls-tcp = { version = "0.1.0", optional = true }    # For raw TCP
```

### Basic Usage Example (Actix-web)

```rust
use actix_web::{web, App, HttpServer, HttpResponse};
use mtls_actix::MtlsMiddleware;
use mtls_core::{ConnectionValidator, ServerConfig};
use std::path::Path;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Configure mTLS server
    let server_config = ServerConfig::new(
        Path::new("certs/server.crt"),
        Path::new("certs/server.key"),
        Path::new("certs/ca.crt"),
    ).expect("Failed to create server config");

    // Create connection validator
    let validator = ConnectionValidator::create_for_server(server_config)
        .expect("Failed to create validator");

    // Create mTLS middleware
    let mtls_middleware = MtlsMiddleware::new(validator);

    // Build Actix-web server
    HttpServer::new(move || {
        App::new()
            .wrap(mtls_middleware.clone())
            .route("/", web::get().to(|| async { "Hello, mTLS!" }))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

### Basic Usage Example (Rocket)

```rust
use rocket::{get, routes, Rocket, Build};
use rocket::fairing::AdHoc;
use mtls_rocket::MtlsFairing;
use mtls_core::{ConnectionValidator, ServerConfig};
use std::path::Path;

#[get("/")]
fn index() -> &'static str {
    "Hello, mTLS!"
}

#[rocket::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure mTLS server
    let server_config = ServerConfig::new(
        Path::new("certs/server.crt"),
        Path::new("certs/server.key"),
        Path::new("certs/ca.crt"),
    )?;

    // Create connection validator
    let validator = ConnectionValidator::create_for_server(server_config)?;

    // Create mTLS fairing
    let mtls_fairing = MtlsFairing::new(validator);

    // Build Rocket server
    let rocket = rocket::build()
        .attach(mtls_fairing)
        .mount("/", routes![index]);

    rocket.launch().await?;
    Ok(())
}
```

## Certificate Setup

### Generate Test Certificates

The project includes a script to generate test certificates:

```bash
# Generate test certificates
cd tests/certs/
./generate_test_certs.sh
```

### Production Certificates

For production use, generate certificates using a trusted CA:

```bash
# Generate root CA (internal use)
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt

# Generate server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt

# Generate client certificate
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -out client.crt
```

## IP Whitelist Configuration

Create a YAML configuration file:

```yaml
# ip_whitelist.yaml
allowed_networks:
  ipv4:
    - "192.168.1.0/24"
    - "10.0.0.0/8"
  ipv6:
    - "2001:db8::/32"
    - "fd00::/8"
```

Load the configuration:

```rust
use mtls_core::ip::IpWhitelistValidator;
use std::path::Path;

let validator = IpWhitelistValidator::from_yaml_file(Path::new("ip_whitelist.yaml"))
    .expect("Failed to load IP whitelist");
```

## Advanced Features

### Request Guards (Actix-web)

Use the `ValidCertificate` extractor to access certificate information in your handlers:

```rust
use actix_web::get;
use mtls_actix::ValidCertificate;

#[get("/secure")]
async fn secure_endpoint(cert: ValidCertificate) -> String {
    format!(
        "Authenticated client: {} from IP: {}",
        cert.certificate_subject().unwrap_or("Unknown"),
        cert.client_ip()
    )
}
```

### Custom Validation

Implement custom validation logic by extending the `ConnectionValidator`:

```rust
use mtls_core::{ConnectionValidator, ServerConfig, CertificateInfo};
use std::path::Path;

let server_config = ServerConfig::new(
    Path::new("certs/server.crt"),
    Path::new("certs/server.key"),
    Path::new("certs/ca.crt"),
)?;

let mut validator = ConnectionValidator::create_for_server(server_config)?;

// Add custom validation logic
validator.set_custom_validator(Box::new(|cert_info: &CertificateInfo| {
    // Validate certificate subject contains specific organization
    if !cert_info.subject().contains("MyOrganization") {
        return Err("Certificate organization not allowed".into());
    }
    Ok(())
}));
```

## Examples

Complete examples are available in the `mtls-examples` crate:

```bash
# Run Actix example
cargo run --example actix_example --features actix

# Run Rocket example
cargo run --example rocket_example --features rocket

# Run TCP example
cargo run --example tcp_example --features tcp
```

## Security Best Practices

1. **Certificate Management**
   - Store private keys in secure locations with restricted permissions
   - Use hardware security modules (HSMs) for production deployments
   - Implement certificate rotation procedures

2. **Network Security**
   - Combine IP whitelisting with network segmentation
   - Use TLS-terminating proxies for HTTP frameworks
   - Monitor for unusual authentication patterns

3. **Configuration**
   - Use environment variables for sensitive configuration
   - Validate configurations at application startup
   - Regularly review and update IP whitelists

4. **Monitoring**
   - Log authentication successes and failures
   - Monitor certificate expiration dates
   - Implement alerting for security events

For detailed security considerations, see [SECURITY.md](./SECURITY.md).

## Limitations

- **gRPC Support**: The gRPC adapter is experimental and not yet fully implemented
- **Certificate Revocation**: CRL and OCSP are not currently supported
- **Performance**: IP validation occurs synchronously; consider async validation for high-volume applications
- **Proxy Dependency**: HTTP frameworks require TLS-terminating proxies for certificate extraction

## Contributing

Contributions are welcome! Please see the [Contributing Guidelines](CONTRIBUTING.md) for details.

## License

This project is dual-licensed under:

- MIT License ([LICENSE-MIT](./LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.

## Support

For issues, questions, or security concerns:
1. Check the [documentation](./IMPLEMENTATION_GUIDE.md)
2. Review existing [issues](https://github.com/Crellsin/mtls-rs/issues)
3. **For security vulnerabilities**: Please report responsibly via secure channels

---
## ⚠️ Security Disclaimer and Liability Limitation

**CRITICAL SECURITY NOTICE**

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. 

**ABSOLUTELY NO LIABILITY FOR SECURITY VULNERABILITIES OR BREACHES**

THE AUTHORS, CONTRIBUTORS, AND COPYRIGHT HOLDERS OF THIS PROJECT EXPLICITLY AND UNEQUIVOCALLY DISCLAIM ANY AND ALL RESPONSIBILITY FOR:

1. **SECURITY VULNERABILITIES**: Any security vulnerabilities, weaknesses, or flaws in this software, whether known or unknown, discovered or undiscovered.
2. **DATA BREACHES**: Any unauthorized access, data breaches, security incidents, or compromises that may occur through the use of this software.
3. **FINANCIAL LOSSES**: Any direct, indirect, incidental, special, consequential, or punitive damages, including but not limited to loss of profits, revenue, data, or business opportunities.
4. **LEGAL CONSEQUENCES**: Any violations of laws, regulations, or compliance requirements resulting from the use of this software.
5. **MISCONFIGURATION**: Any damages resulting from improper configuration, implementation, or use of this software.
6. **THIRD-PARTY DEPENDENCIES**: Any vulnerabilities or issues arising from dependencies, including but not limited to `rustls`, `x509-parser`, `tokio`, or any other third-party libraries.

**YOU ASSUME ALL RISKS AND FULL RESPONSIBILITY FOR:**

- Implementing, configuring, and maintaining this software in your environment
- Conducting thorough security reviews, penetration testing, and vulnerability assessments
- Ensuring compliance with all applicable laws, regulations, and industry standards
- Proper certificate management, including generation, storage, rotation, and revocation
- Network security, firewall configuration, and access control policies
- Monitoring, logging, and incident response procedures
- Regular updates and patches for all software components
- Backup, disaster recovery, and business continuity planning

**NO WARRANTY OF FITNESS FOR SECURITY PURPOSES**

This software is NOT warranted to be fit for any particular security purpose, regardless of any representations or descriptions. The use of this software does not guarantee the security of your systems, networks, or data.

**INDEMNIFICATION**

By using this software, you agree to indemnify, defend, and hold harmless the authors, contributors, and copyright holders from any and all claims, damages, losses, liabilities, costs, and expenses (including attorneys' fees) arising from your use of this software.

**PROFESSIONAL ADVICE REQUIRED**

This software is a technical tool, not a complete security solution. You should consult with qualified security professionals before deploying this software in any production environment, particularly for critical systems or sensitive data.

**USE AT YOUR OWN EXTREME RISK. YOU HAVE BEEN WARNED.**
**Remember**: You are responsible for implementing proper security measures in your environment. This library is a tool, not a complete security solution. Always conduct security reviews and testing before deployment.
