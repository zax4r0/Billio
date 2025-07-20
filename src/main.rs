use axum::{Router, http::Method};
use billio::api::{handlers::api_routes, openapi::ApiDoc};
use billio::config::config::CONFIG;
use billio::core::services::BillioService;
use billio::infrastructure::{
    cache::in_memory::InMemoryCache, logging::in_memory::InMemoryLogging, storage::in_memory::InMemoryStorage,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::info;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let cache = InMemoryCache::new();
    let storage = InMemoryStorage::new();
    let logging = InMemoryLogging::new();
    let billio = Arc::new(BillioService::new(storage, logging, cache, CONFIG.jwt_secret.clone()));

    let app = Router::new()
        .route("/", axum::routing::get(|| async { "OK" }))
        .nest("/api", api_routes(billio))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(CompressionLayer::new())
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([axum::http::header::CONTENT_TYPE]),
        )
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([127, 0, 0, 1], CONFIG.port));
    info!("Server running at http://{}", addr);
    info!("Swagger UI available at http://{}/swagger-ui", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
