use std::sync::Arc;

use axum::{ http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use serde_json::json;

use crate::{ apphandler::AppHandler, structs::apierror::APIError, util::{cors::cors, token} };

pub async fn get(
  headers: HeaderMap,
  Extension(app): Extension<Arc<AppHandler>>
) -> impl IntoResponse{
  let auth = headers.get("authorization");
  if auth.is_none() { return Err(APIError::default()) }

  let auth = auth.unwrap().to_str().unwrap();
  let user = token::identify_oauth(auth.to_string(), "identify".into(), app).await;

  if user.is_err(){ return Err(APIError::new(500, user.unwrap_err().to_string())) }
  let user = user.unwrap();

  Ok((
    StatusCode::OK,
    [
      ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
      ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
      ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
    ],
    Json(json!({
      "id": user._id.to_hex(),
      "username": user.username,
      "email": user.email,
      "avatar": user.avatar
    }))
  ))
}