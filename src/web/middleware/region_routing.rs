//! Region-based request routing (Sprint 9)

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures::future::LocalBoxFuture;
use std::future::{ready, Ready};

pub struct RegionRouter {
    default_region: String,
}

impl RegionRouter {
    pub fn new(default_region: String) -> Self {
        Self { default_region }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RegionRouter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RegionRouterMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RegionRouterMiddleware {
            service,
            default_region: self.default_region.clone(),
        }))
    }
}

pub struct RegionRouterMiddleware<S> {
    service: S,
    default_region: String,
}

impl<S, B> Service<ServiceRequest> for RegionRouterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Get client IP for geo-location
        let client_ip = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("unknown")
            .to_string();

        // TODO: Determine nearest region based on IP geolocation
        let _target_region = &self.default_region;

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}

pub fn determine_region_from_ip(_ip: &str) -> String {
    // TODO: Implement IP-based geolocation
    "us-east".to_string()
}
