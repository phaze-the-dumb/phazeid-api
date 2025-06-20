use axum::{ http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Json };
use serde_json::json;

use crate::util::cors::cors;

pub async fn get( headers: HeaderMap ) -> impl IntoResponse{
  (
    StatusCode::OK,
    [
      ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
      ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
      ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
    ],
    Json(json!({  }))
  )
}