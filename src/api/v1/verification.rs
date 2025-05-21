use std::sync::Arc;

use axum::{ extract::Query, http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use serde_json::{ json, Value };

use crate::{ apphandler::AppHandler, structs::apierror::APIError, util::{cors::cors, token} };

pub async fn get(
  headers: HeaderMap,
  Query(query): Query<Value>,
  Extension(app): Extension<Arc<AppHandler>>
) -> impl IntoResponse{
  let token = query["token"].as_str().unwrap().to_owned();

  let identity = token::identify(token.clone(), app).await;
  if identity.is_err() { return Err(APIError::new(500, identity.unwrap_err().to_string())) }

  let ( user, session ) = identity.unwrap();

  if !user.email_verified {
    return Ok((
      StatusCode::OK,
      [
        ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
        ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
        ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() ),
        ( header::ACCEPT, "*".into() )
      ],
      Json(json!({ "ok": true, "procedure": "VERIFY_EMAIL", "endpoint": "/verify-email" }))
    ))
  }

  if user.has_mfa {
    return Ok((
      StatusCode::OK,
      [
        ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
        ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
        ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() ),
        ( header::ACCEPT, "*".into() )
      ],
      Json(json!({ "ok": true, "procedure": "VERIFY_MFA", "endpoint": "/verify-mfa" }))
    ))
  }

  if !session.valid {
    return Ok((
      StatusCode::OK,
      [
        ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
        ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
        ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() ),
        ( header::ACCEPT, "*".into() )
      ],
      Json(json!({ "ok": true, "procedure": "VERIFY", "endpoint": "/verify" }))
    ))
  }

  Ok((
    StatusCode::OK,
    [
      ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
      ( header::ACCESS_CONTROL_ALLOW_METHODS, "POST".into() ),
      ( header::SET_COOKIE, format!("token={}; Max-Age=604800; Domain=localhost; Path=/api; HttpOnly; Secure; SameSite=Strict", token) ),
      ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
    ],
    Json(json!({ "ok": true, "procedure": "NONE", "endpoint": query["next"].as_str().unwrap() }))
  ))
}