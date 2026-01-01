//! Example Actix-web server with mTLS authentication.

use actix_web::{web, App, HttpResponse, HttpServer};
use mtls_actix::MtlsMiddleware;
use mtls_core::{ConnectionValidator, ServerConfig};
use std::path::Path;

/// Simple health check endpoint.
async fn health_check() -> HttpResponse {
    HttpResponse::Ok().body("OK")
}

/// Protected endpoint that requires mTLS.
async fn protected() -> HttpResponse {
    HttpResponse::Ok().body("This is a protected endpoint. Your mTLS connection is valid.")
}

/// Run the Actix-web server with mTLS.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load server configuration from test certificates
    let server_config = ServerConfig::new(
        Path::new("tests/certs/server/server.crt"),
        Path::new("tests/certs/server/server.key"),
        Path::new("tests/certs/server/ca.crt"),
    )?;

    // Create connection validator for server
    let validator = ConnectionValidator::create_for_server(server_config)?;

    // Create mTLS middleware
    let mtls_middleware = MtlsMiddleware::new(validator);

    println!("Starting Actix-web server with mTLS on https://127.0.0.1:8444");

    // Start the HTTP server
    HttpServer::new(move || {
        App::new()
            .wrap(mtls_middleware.clone())
            .route("/health", web::get().to(health_check))
            .route("/protected", web::get().to(protected))
    })
    .bind("127.0.0.1:8444")?
    .run()
    .await?;

    Ok(())
}
