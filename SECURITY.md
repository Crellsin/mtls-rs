# Security Considerations for mTLS-rs

This document outlines security considerations for using the `mtls-rs` crate and its adapters.

## Overview

`mtls-rs` provides mutual TLS (mTLS) authentication with IP whitelisting for Rust applications. It is designed to secure network communications by ensuring both client and server authenticate each other using X.509 certificates, with additional IP-based access control.

## Certificate Security

### Certificate Validation
- **Chain Validation**: The library validates certificate chains against a trusted root CA. Ensure your CA certificates are securely stored and managed.
- **Key Usage**: Certificates are validated for appropriate key usage (digitalSignature, keyEncipherment, etc.) based on RFC 5280.
- **Extended Key Usage**: Server certificates require `serverAuth` and client certificates require `clientAuth` for proper validation.
- **Certificate Revocation**: Currently, CRL (Certificate Revocation List) and OCSP (Online Certificate Status Protocol) are not implemented. Consider this limitation in your threat model.

### Certificate Management
- **Private Key Protection**: Private keys should be stored in secure locations with appropriate file permissions. Consider using hardware security modules (HSMs) or key management services for production.
- **Certificate Lifetimes**: Use certificates with appropriate validity periods and implement rotation procedures.
- **CA Security**: Protect your CA private keys. Compromise of the CA key allows issuance of fraudulent certificates.

## IP Whitelisting

### Network Validation
- **Early Rejection**: IP validation occurs before TLS handshake, reducing resource consumption for unauthorized connections.
- **CIDR Support**: Both IPv4 and IPv6 CIDR notation is supported for flexible network definitions.
- **Configuration Security**: IP whitelist configurations should be treated as sensitive security configurations and protected accordingly.

### Limitations
- **IP Spoofing**: IP whitelisting does not prevent IP spoofing in all network configurations. It should be used in conjunction with other security measures in environments where IP spoofing is a concern.
- **Dynamic IPs**: Clients with dynamically assigned IPs may require broader network ranges or alternative authentication methods.

## TLS Configuration

### Protocol Versions
- **Minimum TLS 1.2**: The default configuration requires TLS 1.2 or higher. TLS 1.0 and 1.1 are not supported.
- **Modern Cipher Suites**: Default cipher suites prioritize strong, modern algorithms (AES-GCM, ChaCha20-Poly1305).

### Configuration Security
- **Secure Defaults**: The library enforces secure defaults including required client authentication and server certificate verification.
- **Custom Configurations**: When customizing TLS configurations, ensure you maintain adequate security levels.

## Framework-Specific Considerations

### Actix-web Middleware
- **Header Extraction**: The middleware extracts client certificates from the `X-Client-Cert` header, which must be set by a TLS-terminating proxy. Ensure your proxy properly validates and forwards certificates.
- **IP Extraction**: IP addresses are extracted from request headers (`X-Forwarded-For`) when behind proxies. Configure your proxy to properly set these headers.

### Rocket Fairing
- **Proxy Configuration**: Similar to Actix, Rocket requires a TLS-terminating proxy. The fairing relies on the proxy setting the `X-Client-Cert` header.
- **Request Validation**: The fairing validates IP addresses and certificates before request processing.

### Raw TCP Adapter
- **Direct TLS**: The TCP adapter establishes TLS directly without HTTP, providing pure mTLS connections.
- **Performance**: Direct TLS may have different performance characteristics compared to HTTP-based adapters.

### gRPC Adapter (Experimental)
- **Work in Progress**: The gRPC adapter is currently experimental and not fully implemented for production use.
- **Interceptors**: When implemented, interceptors will validate mTLS and IP whitelisting for gRPC requests.

## Operational Security

### Logging and Monitoring
- **Sensitive Data**: Avoid logging certificate contents or private key material.
- **Audit Logs**: Log authentication successes and failures for security monitoring.
- **Monitoring**: Monitor for unusual patterns of authentication failures or IP whitelist violations.

### Error Handling
- **Information Disclosure**: Error messages should not disclose sensitive information about internal configurations or certificate details to unauthenticated clients.

## Best Practices

### Deployment
1. **Use Production-Grade CAs**: Use certificates from trusted CAs or properly secured internal CAs.
2. **Regular Updates**: Keep dependencies, including `rustls` and `x509-parser`, updated to address security vulnerabilities.
3. **Network Segmentation**: Combine IP whitelisting with network segmentation for defense in depth.
4. **Proxy Configuration**: When using HTTP adapters, ensure TLS-terminating proxies are properly configured and secured.

### Configuration Management
1. **Secure Storage**: Store certificate files and configuration files with appropriate permissions.
2. **Environment Variables**: Consider using environment variables for sensitive configuration in containerized environments.
3. **Configuration Validation**: Validate configurations at application startup to catch misconfigurations early.

### Development
1. **Security Reviews**: Conduct security reviews of custom implementations using this library.
2. **Testing**: Test with invalid certificates, revoked certificates, and unauthorized IPs to ensure proper rejection.
3. **Dependency Scanning**: Regularly scan dependencies for known vulnerabilities.

## Reporting Security Issues

If you discover a security vulnerability in `mtls-rs`, please report it responsibly:
- **Email**: devsecurity@ewasila.com
- **Acknowledgments**: Security researchers who responsibly report vulnerabilities will be acknowledged (if desired).

## References

- [RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://tools.ietf.org/html/rfc5280)
- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [rustls Security Considerations](https://github.com/rustls/rustls#security-considerations)

---

*This document is a living document and will be updated as the library evolves and new security considerations are identified.*
