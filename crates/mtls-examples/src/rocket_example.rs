//! Example Rocket server with mTLS authentication.

use mtls_core::{ConnectionValidator, ServerConfig};
use mtls_rocket::MtlsFairing;
use rocket::fairing::AdHoc;
use rocket::figment::Figment;
use rocket::{get, routes, Build, Rocket};
use std::path::Path;

/// Health check endpoint.
#[get("/health")]
fn health_check() -> &'static str {
    "OK"
}

/// Protected endpoint that requires mTLS.
#[get("/protected")]
fn protected() -> &'static str {
    "This is a protected endpoint. Your mTLS connection is valid."
}

/// Configure and launch the Rocket server with mTLS.
#[rocket::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load server configuration from test certificates
    let server_config = ServerConfig::new(
        Path::new("tests/certs/server/server.crt"),
        Path::new("tests/certs/server/server.key"),
        Path::new("tests/certs/server/ca.crt"),
    )?;

    // Create connection validator for server
    let validator = ConnectionValidator::create_for_server(server_config)?;

    // Create mTLS fairing
    let mtls_fairing = MtlsFairing::new(validator);

    // Build Rocket with TLS configuration
    // Note: Rocket doesn't natively support TLS in the same way as Actix, so we would typically
    // run it behind a reverse proxy (like nginx) that handles TLS. However, for demonstration,
    // we can use the `rocket_contrib` TLS feature or run without TLS and rely on the fairing
    // to check the X-Client-Cert header (which would be set by the proxy).
    // Since the current fairing only validates IP and checks the header, we'll run without TLS.
    // In production, you should run Rocket behind a TLS-terminating proxy that sets the client certificate header.

    println!("Starting Rocket server with mTLS fairing on http://127.0.0.1:8000");
    println!(
        "Note: In production, run behind a TLS-terminating proxy that sets X-Client-Cert header."
    );

    let rocket = rocket::build()
        .attach(mtls_fairing)
        .attach(AdHoc::on_ignite("Configure Address", |rocket| async move {
            rocket.configure(
                Figment::from(rocket::Config::default())
                    .merge(("address", "127.0.0.1"))
                    .merge(("port", 8000)),
            )
        }))
        .mount("/", routes![health_check, protected]);

    rocket.launch().await?;

    Ok(())
}
