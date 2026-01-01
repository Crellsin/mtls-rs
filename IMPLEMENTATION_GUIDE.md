# Implementation Guide for mTLS-rs

This guide provides detailed instructions for implementing and using the mTLS authentication system in Rust. It covers configuration, integration with different frameworks, and advanced usage patterns.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Library (mtls-core)](#core-library-mtls-core)
3. [Actix-web Integration](#actix-web-integration)
4. [Rocket Integration](#rocket-integration)
5. [Raw TCP Integration](#raw-tcp-integration)
6. [gRPC Integration (Experimental)](#grpc-integration-experimental)
7. [Configuration Management](#configuration-management)
8. [Certificate Management](#certificate-management)
9. [IP Whitelist Configuration](#ip-whitelist-configuration)
10. [Security Considerations](#security-considerations)
11. [Troubleshooting](#troubleshooting)
12. [Performance Tuning](#performance-tuning)

## Architecture Overview

The mTLS-rs system is built around a core library (`mtls-core`) that provides certificate management, IP validation, and TLS configuration. Framework-specific adapters wrap this core functionality to provide integration with popular Rust web frameworks.

### Key Components

1. **Certificate Manager**: Loads and validates X.509 certificates
2. **IP Whitelist Validator**: Validates IP addresses against configured networks
3. **Connection Validator**: Orchestrates certificate and IP validation
4. **Secure Socket Factory**: Creates TLS-enabled sockets
5. **Framework Adapters**: Middleware/fairings for Actix, Rocket, etc.

## Core Library (mtls-core)

### Basic Usage

```rust
use mtls_core::{ConnectionValidator, ServerConfig, ClientConfig};
use std::path::Path;

// Server-side configuration
let server_config = ServerConfig::new(
    Path::new("certs/server.crt"),
    Path::new("certs/server.key"),
    Path::new("certs/ca.crt"),
)?;

let server_validator = ConnectionValidator::create_for_server(server_config)?;

// Client-side configuration
let client_config = ClientConfig::new(
    Path::new("certs/client.crt"),
    Path::new("certs/client.key"),
)?
.with_ca_cert_path(Path::new("certs/ca.crt"))?;

let client_validator = ConnectionValidator::create_for_client(client_config)?;
```

### Certificate Validation

The core library performs several levels of certificate validation:

1. **Chain Validation**: Verifies the certificate chain against a trusted CA
2. **Key Usage**: Validates certificate key usage extensions
3. **Extended Key Usage**: Checks for `serverAuth` or `clientAuth` as appropriate
4. **Expiration**: Validates certificate validity periods

### IP Whitelist Validation

```rust
use mtls_core::ip::IpWhitelistValidator;

// Create from YAML file
let ip_validator = IpWhitelistValidator::from_yaml_file(Path::new("ip_whitelist.yaml"))?;

// Validate an IP address
let client_ip = "192.168.1.100".parse()?;
ip_validator.validate(client_ip)?;
```

## Actix-web Integration

### Basic Middleware Setup

```rust
use actix_web::{web, App, HttpServer};
use mtls_actix::MtlsMiddleware;
use mtls_core::{ConnectionValidator, ServerConfig};
use std::path::Path;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Configure mTLS
    let server_config = ServerConfig::new(
        Path::new("certs/server.crt"),
        Path::new("certs/server.key"),
        Path::new("certs/ca.crt"),
    )?;
    
    let validator = ConnectionValidator::create_for_server(server_config)?;
    let mtls_middleware = MtlsMiddleware::new(validator);

    // Build server
    HttpServer::new(move || {
        App::new()
            .wrap(mtls_middleware.clone())
            .service(web::resource("/").to(|| async { "Hello, mTLS!" }))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

### Request Guard Usage

The Actix adapter provides a `ValidCertificate` extractor for accessing certificate information:

```rust
use actix_web::{get, web, HttpResponse};
use mtls_actix::ValidCertificate;

#[get("/api/secure")]
async fn secure_api(cert: ValidCertificate) -> HttpResponse {
    if let Some(subject) = cert.certificate_subject() {
        HttpResponse::Ok().body(format!("Authenticated as: {}", subject))
    } else {
        HttpResponse::Unauthorized().body("No valid certificate")
    }
}

// Register in your App
App::new()
    .wrap(mtls_middleware)
    .service(secure_api)
```

### Custom Error Handling

```rust
use actix_web::{error, HttpResponse};
use std::fmt;

#[derive(Debug)]
struct MtlsError(String);

impl fmt::Display for MtlsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "mTLS error: {}", self.0)
    }
}

impl error::ResponseError for MtlsError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::Forbidden().body(self.0.clone())
    }
}

// Use in your handler
#[get("/api/protected")]
async fn protected(cert: ValidCertificate) -> Result<HttpResponse, MtlsError> {
    // Custom validation logic
    if cert.client_ip().to_string() != "192.168.1.100" {
        return Err(MtlsError("IP not allowed".into()));
    }
    Ok(HttpResponse::Ok().body("Access granted"))
}
```

## Rocket Integration

### Fairing Setup

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
    // Configure mTLS
    let server_config = ServerConfig::new(
        Path::new("certs/server.crt"),
        Path::new("certs/server.key"),
        Path::new("certs/ca.crt"),
    )?;
    
    let validator = ConnectionValidator::create_for_server(server_config)?;
    let mtls_fairing = MtlsFairing::new(validator);

    // Build and launch
    let rocket = rocket::build()
        .attach(mtls_fairing)
        .mount("/", routes![index])
        .attach(AdHoc::on_ignite("Configure Address", |rocket| async move {
            rocket.configure(rocket::Config::figment().merge(("address", "127.0.0.1")).merge(("port", 8000)))
        }));

    rocket.launch().await?;
    Ok(())
}
```

### Request Guard (Rocket)

Rocket doesn't have a built-in extractor for certificates in the fairing, but you can access request headers:

```rust
use rocket::{get, Request, request::FromRequest};
use rocket::http::Status;
use rocket::request::Outcome;

#[get("/secure")]
fn secure(request: &Request) -> String {
    // Extract certificate from header (set by proxy)
    let cert_header = request.headers().get_one("X-Client-Cert");
    
    match cert_header {
        Some(cert) => format!("Certificate present: {}", &cert[..50]),
        None => "No certificate".into(),
    }
}
```

## Raw TCP Integration

### Server Implementation

```rust
use mtls_tcp::TcpServer;
use mtls_core::{ConnectionValidator, ServerConfig};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure mTLS server
    let server_config = ServerConfig::new(
        Path::new("certs/server.crt"),
        Path::new("certs/server.key"),
        Path::new("certs/ca.crt"),
    )?;
    
    let validator = ConnectionValidator::create_for_server(server_config)?;
    
    // Create TCP server
    let server = TcpServer::new("127.0.0.1:8443", validator).await?;
    
    println!("TCP server listening on 127.0.0.1:8443");
    
    // Accept connections
    while let Ok((mut stream, addr)) = server.accept().await {
        println!("Connection from: {}", addr);
        
        tokio::spawn(async move {
            let mut buffer = [0; 1024];
            
            // Read data
            match stream.read(&mut buffer).await {
                Ok(n) if n > 0 => {
                    let message = String::from_utf8_lossy(&buffer[..n]);
                    println!("Received: {}", message);
                    
                    // Send response
                    let response = format!("Echo: {}", message);
                    stream.write_all(response.as_bytes()).await.unwrap();
                }
                _ => {}
            }
        });
    }
    
    Ok(())
}
```

### Client Implementation

```rust
use mtls_tcp::TcpClient;
use mtls_core::{ConnectionValidator, ClientConfig};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure mTLS client
    let client_config = ClientConfig::new(
        Path::new("certs/client.crt"),
        Path::new("certs/client.key"),
    )?
    .with_ca_cert_path(Path::new("certs/ca.crt"))?;
    
    let validator = ConnectionValidator::create_for_client(client_config)?;
    
    // Create TCP client
    let mut client = TcpClient::connect("127.0.0.1:8443", validator).await?;
    
    // Send message
    let message = "Hello, mTLS TCP server!";
    client.write_all(message.as_bytes()).await?;
    
    // Read response
    let mut buffer = [0; 1024];
    let n = client.read(&mut buffer).await?;
    let response = String::from_utf8_lossy(&buffer[..n]);
    
    println!("Server response: {}", response);
    
    Ok(())
}
```

## gRPC Integration (Experimental)

**Note**: The gRPC adapter is currently a work in progress. The following shows the intended API.

### Server Implementation (Planned)

```rust
use tonic::transport::Server;
use mtls_grpc::ServerCredentials;
use mtls_core::{ConnectionValidator, ServerConfig};
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure mTLS server
    let server_config = ServerConfig::new(
        Path::new("certs/server.crt"),
        Path::new("certs/server.key"),
        Path::new("certs/ca.crt"),
    )?;
    
    let validator = ConnectionValidator::create_for_server(server_config)?;
    let credentials = ServerCredentials::new(validator);
    
    // Build gRPC server (conceptual - not yet implemented)
    // Server::builder()
    //     .tls_config(credentials.into_tls_config()?)?
    //     .add_service(YourServiceServer::new(YourService))
    //     .serve("127.0.0.1:50051".parse()?)
    //     .await?;
    
    Ok(())
}
```

## Configuration Management

### Environment-Based Configuration

```rust
use std::env;
use std::path::Path;

fn load_certificate_paths() -> (String, String, String) {
    let server_cert = env::var("MTLS_SERVER_CERT")
        .unwrap_or_else(|_| "certs/server.crt".into());
    
    let server_key = env::var("MTLS_SERVER_KEY")
        .unwrap_or_else(|_| "certs/server.key".into());
    
    let ca_cert = env::var("MTLS_CA_CERT")
        .unwrap_or_else(|_| "certs/ca.crt".into());
    
    (server_cert, server_key, ca_cert)
}

// Usage
let (server_cert, server_key, ca_cert) = load_certificate_paths();
let server_config = ServerConfig::new(
    Path::new(&server_cert),
    Path::new(&server_key),
    Path::new(&ca_cert),
)?;
```

### Configuration Struct

```rust
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize)]
struct MtlsConfig {
    server_cert: String,
    server_key: String,
    ca_cert: String,
    allowed_networks: AllowedNetworks,
}

#[derive(Debug, Deserialize)]
struct AllowedNetworks {
    ipv4: Vec<String>,
    ipv6: Vec<String>,
}

impl MtlsConfig {
    fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let config: MtlsConfig = toml::from_str(&contents)?;
        Ok(config)
    }
}
```

## Certificate Management

### Certificate Generation Script

Create a script `generate_certs.sh`:

```bash
#!/bin/bash

# Generate root CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=Root CA"

# Generate server certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=server.example.com"
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
  -set_serial 01 -out server.crt -extensions server_ext

# Generate client certificate
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=client@example.com"
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
  -set_serial 02 -out client.crt -extensions client_ext

# Clean up CSRs
rm -f server.csr client.csr

echo "Certificates generated successfully!"
```

### Certificate Rotation

Implement certificate rotation by monitoring expiration dates:

```rust
use mtls_core::cert::CertificateManager;
use std::path::Path;
use std::time::{SystemTime, Duration};

fn check_certificate_expiration(cert_path: &Path) -> Result<Duration, Box<dyn std::error::Error>> {
    let manager = CertificateManager::new();
    let cert_info = manager.load_certificate(cert_path)?;
    
    let now = SystemTime::now();
    let expiration = cert_info.not_after();
    
    if let Ok(duration) = expiration.duration_since(now) {
        Ok(duration)
    } else {
        Err("Certificate has expired".into())
    }
}

// Schedule rotation when certificate is about to expire
let time_to_expiry = check_certificate_expiration(Path::new("certs/server.crt"))?;
if time_to_expiry < Duration::from_secs(30 * 24 * 60 * 60) { // 30 days
    println!("Certificate expires in {:?}, schedule rotation", time_to_expiry);
}
```

## IP Whitelist Configuration

### YAML Configuration File

```yaml
# ip_whitelist.yaml
allowed_networks:
  ipv4:
    - "10.0.0.0/8"           # Private network
    - "192.168.0.0/16"       # Private network
    - "172.16.0.0/12"        # Private network
    - "203.0.113.0/24"       # Example public network
  
  ipv6:
    - "2001:db8::/32"        # Documentation network
    - "fd00::/8"             # Unique local addresses
  
  # Optional: Individual IPs (will be converted to /32 or /128)
  individual_ips:
    ipv4:
      - "192.168.1.100"
      - "192.168.1.101"
    ipv6:
      - "2001:db8::1"
  
  # Optional: Exclude specific networks/IPs
  excluded:
    ipv4:
      - "10.0.0.100/32"      # Block specific IP
    ipv6:
      - "2001:db8::/64"      # Block specific subnet
```

### Dynamic IP Whitelist Updates

```rust
use mtls_core::ip::IpWhitelistValidator;
use std::sync::Arc;
use tokio::sync::RwLock;

struct DynamicWhitelist {
    validator: Arc<RwLock<IpWhitelistValidator>>,
}

impl DynamicWhitelist {
    async fn update_whitelist(&self, new_config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let new_validator = IpWhitelistValidator::from_yaml_file(Path::new(new_config_path))?;
        
        let mut validator = self.validator.write().await;
        *validator = new_validator;
        
        Ok(())
    }
    
    async fn validate_ip(&self, ip: std::net::IpAddr) -> Result<(), Box<dyn std::error::Error>> {
        let validator = self.validator.read().await;
        validator.validate(ip)?;
        Ok(())
    }
}
```

## Security Considerations

### 1. Private Key Protection

```rust
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn set_secure_permissions(key_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(key_path)?;
    let mut permissions = metadata.permissions();
    
    // Set read-only for owner only (0400)
    permissions.set_mode(0o400);
    fs::set_permissions(key_path, permissions)?;
    
    Ok(())
}

// Apply before loading certificate
set_secure_permissions("certs/server.key")?;
set_secure_permissions("certs/client.key")?;
```

### 2. Certificate Pinning

Implement certificate pinning for additional security:

```rust
use mtls_core::cert::CertificateInfo;
use sha2::{Sha256, Digest};

fn certificate_pinning(cert_info: &CertificateInfo, expected_fingerprint: &str) -> Result<(), String> {
    let certificate = cert_info.certificate();
    let fingerprint = Sha256::digest(certificate.as_ref());
    let fingerprint_hex = hex::encode(fingerprint);
    
    if fingerprint_hex == expected_fingerprint {
        Ok(())
    } else {
        Err("Certificate fingerprint mismatch".into())
    }
}

// Usage in custom validator
validator.set_custom_validator(Box::new(|cert_info: &CertificateInfo| {
    let expected = "a1b2c3d4e5f6..."; // Your expected fingerprint
    certificate_pinning(cert_info, expected)
}));
```

### 3. Rate Limiting

Combine mTLS with rate limiting for defense in depth:

```rust
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{Instant, Duration};

struct RateLimiter {
    requests: Arc<Mutex<HashMap<std::net::IpAddr, Vec<Instant>>>>,
    limit: usize,
    window: Duration,
}

impl RateLimiter {
    async fn check(&self, ip: std::net::IpAddr) -> Result<(), String> {
        let mut requests = self.requests.lock().await;
        let now = Instant::now();
        
        let entry = requests.entry(ip).or_insert_with(Vec::new);
        
        // Remove old requests
        entry.retain(|&time| now.duration_since(time) < self.window);
        
        if entry.len() >= self.limit {
            Err("Rate limit exceeded".into())
        } else {
            entry.push(now);
            Ok(())
        }
    }
}
```

## Troubleshooting

### Common Issues

1. **Certificate Validation Failures**
   - Ensure CA certificate is trusted
   - Check certificate expiration dates
   - Verify certificate chain is complete

2. **IP Whitelist Issues**
   - Confirm CIDR notation is correct
   - Check for overlapping network ranges
   - Verify IP address parsing

3. **Performance Problems**
   - Consider caching validated certificates
   - Use connection pooling for clients
   - Monitor TLS handshake times

### Debug Logging

Enable debug logging to troubleshoot issues:

```rust
use env_logger;
use log::{info, debug, error};

fn setup_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
}

// In your application
setup_logging();
info!("Starting mTLS server");
debug!("Certificate loaded from: {:?}", cert_path);

// The middleware/fairings will log validation events
```

### Health Checks

Implement health check endpoints to monitor mTLS functionality:

```rust
use actix_web::{get, web, HttpResponse};

#[get("/health")]
async fn health_check() -> HttpResponse {
    HttpResponse::Ok().body("OK")
}

#[get("/health/mtls")]
async fn mtls_health_check(cert: ValidCertificate) -> HttpResponse {
    let status = if cert.has_certificate() {
        "mTLS: OK"
    } else {
        "mTLS: No certificate"
    };
    
    HttpResponse::Ok().body(status)
}
```

## Performance Tuning

### Connection Pooling

For client applications, implement connection pooling:

```rust
use std::sync::Arc;
use bb8::{Pool, PooledConnection};
use bb8_tokio_rustls::TlsConnector;

struct MtlsConnectionPool {
    pool: Pool<TlsConnector>,
}

impl MtlsConnectionPool {
    async fn new(
        client_config: ClientConfig,
        host: &str,
        port: u16,
        pool_size: u32,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let validator = ConnectionValidator::create_for_client(client_config)?;
        
        // Create TLS connector (conceptual - adjust based on actual API)
        // let connector = TlsConnector::from(validator);
        
        // Create pool
        // let pool = Pool::builder()
        //     .max_size(pool_size)
        //     .build(connector)
        //     .await?;
        
        // Ok(MtlsConnectionPool { pool })
        Ok(MtlsConnectionPool { pool: unimplemented!() })
    }
    
    async fn get_connection(&self) -> Result<PooledConnection<TlsConnector>, Box<dyn std::error::Error>> {
        // self.pool.get().await.map_err(|e| e.into())
        Ok(unimplemented!())
    }
}
```

### Certificate Caching

Cache validated certificates to reduce validation overhead:

```rust
use lru::LruCache;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::num::NonZeroUsize;

struct CertificateCache {
    cache: Arc<RwLock<LruCache<String, CertificateInfo>>>,
}

impl CertificateCache {
    fn new(capacity: usize) -> Self {
        let cache = LruCache::new(NonZeroUsize::new(capacity).unwrap());
        Self {
            cache: Arc::new(RwLock::new(cache)),
        }
    }
    
    async fn get_or_validate(
        &self,
        cert_pem: &str,
        validator: &ConnectionValidator,
    ) -> Result<CertificateInfo, Box<dyn std::error::Error>> {
        // Check cache
        {
            let cache = self.cache.read().await;
            if let Some(info) = cache.get(cert_pem) {
                return Ok(info.clone());
            }
        }
        
        // Validate and cache
        let cert_info = validator.validate_certificate(cert_pem)?;
        
        {
            let mut cache = self.cache.write().await;
            cache.put(cert_pem.to_string(), cert_info.clone());
        }
        
        Ok(cert_info)
    }
}
```

## Conclusion

This implementation guide covers the essential aspects of using the mTLS-rs library. Remember to:

1. **Test thoroughly** in development before production deployment
2. **Monitor** authentication success/failure rates
3. **Keep certificates and keys** secure with proper permissions
4. **Regularly update** dependencies to address security vulnerabilities
5. **Review security configurations** periodically

For additional help, refer to the crate documentation or submit issues on the project repository.

---

**Security Reminder**: This library is a tool to help implement mTLS authentication. You are responsible for the overall security of your application and infrastructure. Always follow security best practices and conduct regular security audits.
