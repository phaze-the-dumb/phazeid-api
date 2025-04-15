use std::env;

use apphandler::AppHandler;
use axum::{ routing::{ delete, get, options, post, put }, Extension, Router };
use tokio::net::TcpListener;

mod apphandler;
mod util;
mod api;
mod structs;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  dotenvy::dotenv()?;

  let handler = AppHandler::new().await?;

  let app = Router::new()
    .route("/api/v1/status", options(util::cors::options))
    .route("/api/v1/status", get(api::v1::status::get))

    .route("/api/v1/auth/tunnel", options(util::cors::options))
    .route("/api/v1/auth/tunnel", get(api::v1::auth::tunnel::get))

    .route("/api/v1/verification", options(util::cors::options))
    .route("/api/v1/verification", get(api::v1::verification::get))

    .route("/api/v1/verification/verify_email", options(util::cors::options))
    .route("/api/v1/verification/verify_email", post(api::v1::verify::verify_email::post))

    .route("/api/v1/profile", options(util::cors::options))
    .route("/api/v1/profile", get(api::v1::profile::get))

    .layer(Extension(handler));

  let listener = TcpListener::bind(format!("0.0.0.0:{}", env::var("PORT")?)).await?;
  axum::serve(listener, app).await?;
  
  Ok(())
}