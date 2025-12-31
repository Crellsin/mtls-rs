# mtls-tcp

Raw TCP adapter for mTLS authentication with IP whitelisting.

## Overview

`mtls-tcp` provides a low-level TCP adapter for integrating mTLS (mutual TLS) authentication and IP whitelisting into your raw TCP applications. It's designed for protocols that operate directly over TCP, such as custom binary protocols, legacy systems, or when you need maximum control over the network layer.

## Features

- **Raw TCP with TLS**: Add mTLS authentication to any TCP-based protocol
- **IP Whitelist Validation**: Reject connections from unauthorized IP addresses before TLS handshake
- **Async Support**: Built on `tokio` for high-performance asynchronous I/O
- **Flexible Integration**: Use as a standalone server/client or integrate with existing TCP applications

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
mtls-tcp = "0.1.0"
```

### Example Server

```rust
use mtls_tcp::TcpServer;
use mtls_core::validator::ConnectionValidator;
use mtls_core::config::ServerConfig;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    // Create TCP server
    let server = TcpServer::new("127.0.0.1:8443", validator).await?;
    
    println!("TCP server listening on 127.0.0.1:8443");

    // Accept and handle connections
    loop {
        let mut connection = server.accept().await?;
        
        tokio::spawn(async move {
            let mut buffer = [0; 1024];
            
            // Read from client
            let n = match connection.read(&mut buffer).await {
                Ok(n) if n == 0 => return,
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Failed to read from socket: {}", e);
                    return;
                }
            };
            
            // Echo back to client
            if let Err(e) = connection.write_all(&buffer[0..n]).await {
                eprintln!("Failed to write to socket: {}", e);
            }
        });
    }
}
```

### Example Client

```rust
use mtls_tcp::TcpClient;
use mtls_core::validator::ConnectionValidator;
use mtls_core::config::ClientConfig;
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    // Create TCP client and connect
    let mut client = TcpClient::connect("127.0.0.1:8443", validator).await?;
    
    println!("Connected to server");

    // Send data
    let message = b"Hello, mTLS TCP server!";
    client.write_all(message).await?;
    
    // Read response
    let mut buffer = [0; 1024];
    let n = client.read(&mut buffer).await?;
    
    println!("Received: {}", String::from_utf8_lossy(&buffer[0..n]));
    
    Ok(())
}
```

## Configuration

### Server Configuration

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
```

### Client Configuration

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

## Architecture

### Server Components

1. **TcpServer**: Listens for incoming TCP connections
2. **Connection Validator**: Validates client certificates and IP addresses
3. **Secure Socket Factory**: Creates TLS-secured sockets
4. **Async Runtime**: Uses `tokio` for non-blocking I/O

### Client Components

1. **TcpClient**: Establishes outgoing TCP connections
2. **Connection Validator**: Validates server certificates and IP addresses
3. **Secure Socket Factory**: Creates TLS-secured client sockets

## Advanced Usage

### Custom Protocol Integration

You can integrate `mtls-tcp` with custom protocols:

```rust
use mtls_tcp::{TcpServer, TcpClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Custom protocol handler
async fn handle_protocol<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    mut reader: R,
    mut writer: W,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read protocol header
    let mut header = [0; 4];
    reader.read_exact(&mut header).await?;
    
    // Process based on header
    // ... custom protocol logic ...
    
    // Write response
    writer.write_all(b"OK").await?;
    
    Ok(())
}

// Use with mtls-tcp
let server = TcpServer::new("127.0.0.1:8443", validator).await?;

loop {
    let connection = server.accept().await?;
    tokio::spawn(async move {
        let (reader, writer) = tokio::io::split(connection);
        handle_protocol(reader, writer).await
    });
}
```

### Connection Pooling

For high-performance applications, you can implement connection pooling:

```rust
use mtls_tcp::TcpClient;
use std::sync::Arc;
use tokio::sync::Mutex;

struct ConnectionPool {
    validator: Arc<ConnectionValidator>,
    connections: Mutex<Vec<TcpClient>>,
    max_size: usize,
}

impl ConnectionPool {
    async fn get_connection(&self, addr: &str) -> Result<TcpClient, Box<dyn std::error::Error>> {
        let mut connections = self.connections.lock().await;
        
        // Try to get an existing connection
        while let Some(conn) = connections.pop() {
            // Check if connection is still usable
            // (implementation depends on your requirements)
            return Ok(conn);
        }
        
        // Create new connection
        let conn = TcpClient::connect(addr, self.validator.clone()).await?;
        Ok(conn)
    }
    
    async fn return_connection(&self, conn: TcpClient) {
        let mut connections = self.connections.lock().await;
        if connections.len() < self.max_size {
            connections.push(conn);
        }
    }
}
```

## Error Handling

Common error scenarios:

- **Connection Refused**: Server not running or wrong address/port
- **Certificate Validation Failed**: Invalid or expired certificates
- **IP Not Whitelisted**: Client IP not in allowed networks
- **TLS Handshake Failed**: Protocol or cipher suite mismatch

## Performance Considerations

### Connection Establishment
- TLS handshake adds overhead to connection establishment
- Consider connection pooling for frequent connections
- Use session resumption when possible

### Memory Usage
- Each TLS connection maintains its own state
- Monitor memory usage with many concurrent connections
- Consider limiting maximum connections

### CPU Usage
- TLS encryption/decryption uses CPU resources
- Use hardware acceleration when available
- Consider load balancing for high traffic

## Security Considerations

### Network Security
- Use strong cipher suites (AES-256-GCM, ChaCha20-Poly1305)
- Disable weak protocols (SSLv3, TLS 1.0, TLS 1.1)
- Regularly update TLS libraries

### Certificate Management
- Use certificates with appropriate key usage
- Implement certificate revocation checking
- Monitor certificate expiration

### Deployment Security
- Run servers with minimal privileges
- Use firewall rules to restrict access
- Enable logging for security audits

## Testing

Test your mTLS TCP applications:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_echo_server() {
        // Start server in background
        let server_handle = tokio::spawn(async {
            start_server().await.unwrap();
        });
        
        // Give server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Create client and test
        let validator = create_test_validator().await.unwrap();
        let mut client = TcpClient::connect("127.0.0.1:8443", validator).await.unwrap();
        
        // Test echo
        let message = b"test";
        client.write_all(message).await.unwrap();
        
        let mut buffer = [0; 4];
        client.read_exact(&mut buffer).await.unwrap();
        
        assert_eq!(&buffer, message);
        
        // Cleanup
        server_handle.abort();
    }
}
```

## Limitations

### Current Limitations
- Requires `tokio` runtime
- No built-in protocol support (raw bytes only)
- No WebSocket or HTTP/2 support (use appropriate adapters)

### Future Improvements
- Support for multiple async runtimes
- Built-in protocol handlers
- Performance optimizations
- More configuration options

## License

Dual-licensed under either:

- MIT License
- Apache License, Version 2.0

at your option.

## Contributing

Contributions are welcome! Please see the main project repository for contribution guidelines.
