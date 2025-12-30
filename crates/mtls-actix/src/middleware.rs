//! Actix Web middleware for mTLS authentication.

use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::Error;
use mtls_core::validator::ConnectionValidator;
use std::future::{ready, Ready};
use std::rc::Rc;

/// Actix Web middleware for mTLS authentication.
#[derive(Clone)]
pub struct MtlsMiddleware {
    /// Connection validator for mTLS.
    validator: Rc<ConnectionValidator>,
}

impl MtlsMiddleware {
    /// Creates a new MtlsMiddleware with the given connection validator.
    pub fn new(validator: ConnectionValidator) -> Self {
        Self {
            validator: Rc::new(validator),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for MtlsMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = MtlsMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(MtlsMiddlewareService {
            service: Rc::new(service),
            validator: self.validator.clone(),
        }))
    }
}

pub struct MtlsMiddlewareService<S> {
    service: Rc<S>,
    validator: Rc<ConnectionValidator>,
}

impl<S, B> Service<ServiceRequest> for MtlsMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let validator = self.validator.clone();

        Box::pin(async move {
            // TODO: Extract client certificate from request and validate
            // For now, just pass through
            service.call(req).await
        })
    }
}
