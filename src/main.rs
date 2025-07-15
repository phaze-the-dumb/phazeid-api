use std::env;

use apphandler::AppHandler;
use axum::{ response::IntoResponse, routing::{ delete, get, options, post, put }, Extension, Router };
use reqwest::StatusCode;
use tokio::net::TcpListener;

mod apphandler;
mod util;
mod api;
mod structs;

async fn handler_404() -> impl IntoResponse {
  (StatusCode::NOT_FOUND, "nothing to see here")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  dotenvy::dotenv()?;

  let handler = AppHandler::new().await?;

  let app = Router::new()
    .route("/api/v1/status", options(util::cors::options))
    .route("/api/v1/status", get(api::v1::status::get))

    .route("/api/v1/dev/add_app", options(util::cors::options))
    .route("/api/v1/dev/add_app", put(api::v1::dev::add_app::put))

    .route("/api/v1/auth/tunnel", options(util::cors::options))
    .route("/api/v1/auth/tunnel", get(api::v1::auth::tunnel::get))

    .route("/api/v1/verification", options(util::cors::options))
    .route("/api/v1/verification", get(api::v1::verification::get))

    .route("/api/v1/verification/verify_email", options(util::cors::options))
    .route("/api/v1/verification/verify_email", post(api::v1::verify::verify_email::post))

    .route("/api/v1/verification/verify_mfa", options(util::cors::options))
    .route("/api/v1/verification/verify_mfa", post(api::v1::verify::verify_mfa::post))

    .route("/api/v1/verification/verify_backup", options(util::cors::options))
    .route("/api/v1/verification/verify_backup", post(api::v1::verify::verify_backup::post))

    .route("/api/v1/verification/verify", options(util::cors::options))
    .route("/api/v1/verification/verify", post(api::v1::verify::verify::post))

    .route("/api/v1/profile", options(util::cors::options))
    .route("/api/v1/profile", get(api::v1::profile::get))

    .route("/api/v1/account/logout", options(util::cors::options))
    .route("/api/v1/account/logout", get(api::v1::account::logout::get))

    .route("/api/v1/account/logout_oauth", options(util::cors::options))
    .route("/api/v1/account/logout_oauth", get(api::v1::account::logout_oauth::get))

    .route("/api/v1/account/change_username", options(util::cors::options))
    .route("/api/v1/account/change_username", put(api::v1::account::change_username::put))

    .route("/api/v1/account/change_email", options(util::cors::options))
    .route("/api/v1/account/change_email", put(api::v1::account::change_email::put))

    .route("/api/v1/account/change_email/verify", options(util::cors::options))
    .route("/api/v1/account/change_email/verify", put(api::v1::account::verify_change_email::put))

    .route("/api/v1/account/change_avatar", options(util::cors::options))
    .route("/api/v1/account/change_avatar", put(api::v1::account::change_avatar::put))

    .route("/api/v1/account/enable_mfa", options(util::cors::options))
    .route("/api/v1/account/enable_mfa", get(api::v1::account::enable_mfa::get))

    .route("/api/v1/account/confirm_mfa", options(util::cors::options))
    .route("/api/v1/account/confirm_mfa", put(api::v1::account::confirm_mfa::put))

    .route("/api/v1/account/disable_mfa", options(util::cors::options))
    .route("/api/v1/account/disable_mfa", delete(api::v1::account::disable_mfa::delete))

    .route("/api/v1/account/sessions", options(util::cors::options))
    .route("/api/v1/account/sessions", get(api::v1::account::sessions::get))

    .route("/api/v1/account/sessions_oauth", options(util::cors::options))
    .route("/api/v1/account/sessions_oauth", get(api::v1::account::sessions_oauth::get))

    .route("/api/v1/account/delete", options(util::cors::options))
    .route("/api/v1/account/delete", delete(api::v1::account::delete::del))

    .route("/api/v1/account/deletion_state", options(util::cors::options))
    .route("/api/v1/account/deletion_state", get(api::v1::account::deletion_state::get))

    .route("/api/v1/account/restore", options(util::cors::options))
    .route("/api/v1/account/restore", get(api::v1::account::restore::get))

    .route("/api/v1/account/remove_oauth_app", options(util::cors::options))
    .route("/api/v1/account/remove_oauth_app", get(api::v1::account::remove_oauth_app::get))

    .route("/api/v1/oauth/app", options(util::cors::options))
    .route("/api/v1/oauth/app", get(api::v1::oauth::app::get))

    .route("/api/v1/oauth/authorize", options(util::cors::options))
    .route("/api/v1/oauth/authorize", put(api::v1::oauth::authorize::put))

    .route("/api/v1/oauth/token", options(util::cors::options))
    .route("/api/v1/oauth/token", get(api::v1::oauth::token::get))

    .route("/api/v1/oauth/profile", options(util::cors::options))
    .route("/api/v1/oauth/profile", get(api::v1::oauth::profile::get))

    .route("/api/v1/oauth/to_delete", options(util::cors::options))
    .route("/api/v1/oauth/to_delete", get(api::v1::oauth::to_delete::get))

    .route("/api/v1/patreon/link", options(util::cors::options))
    .route("/api/v1/patreon/link", get(api::v1::patreon::link::get))

    .route("/api/v1/patreon/callback", options(util::cors::options))
    .route("/api/v1/patreon/callback", get(api::v1::patreon::callback::get))

    .route("/api/v1/patreon/refresh", options(util::cors::options))
    .route("/api/v1/patreon/refresh", get(api::v1::patreon::refresh::get))

    .route("/api/v1/patreon/remove", options(util::cors::options))
    .route("/api/v1/patreon/remove", get(api::v1::patreon::remove::get))

    .fallback(handler_404)
    .layer(Extension(handler));

  let listener = TcpListener::bind(format!("0.0.0.0:{}", env::var("PORT")?)).await?;
  axum::serve(listener, app).await?;

  Ok(())
}