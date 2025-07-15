use std::sync::Arc;

use axum::{ http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use bson::doc;
use chrono::Utc;
use serde_json::json;

use crate::{ apphandler::AppHandler, structs::apierror::APIError, util::{ cookies, cors::cors, ip::get_ip_from_request, token } };

pub async fn get(
  headers: HeaderMap,
  Extension(app): Extension<Arc<AppHandler>>
) -> impl IntoResponse{
  let cookies = headers.get("cookie");
  if cookies.is_none() { return Err(APIError::default(&headers)) }

  let cookies = cookies.unwrap().to_str().unwrap().to_owned();
  let cookies = cookies::parse(cookies);

  let token = cookies.get("token").unwrap().clone();

  let identity = token::identify(token, app.clone(), get_ip_from_request(&headers).unwrap()).await;
  if identity.is_err() { return Err(APIError::new(500, identity.unwrap_err().to_string(), &headers)) }

  let ( user, session ) = identity.unwrap();
  let verified = token::verified(&user, &session);

  if verified.is_err() {
    return Ok((
      StatusCode::OK,
      [
        ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
        ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
        ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
      ],
      Json(verified.unwrap_err())
    ))
  }

  let now = Utc::now().timestamp();
  if !user.patreon_id.is_some() { return Err(APIError::new(400, "Not linked".into(), &headers)) }

  app.users.update_one(doc! { "_id": user._id }, doc! {
    "$set": {
      "patreon_id": None::<String>,
      "patreon_tiers": Vec::<String>::new(),
      "patreon_last_update": now,
      "patreon_refresh_token": None::<String>,
      "patreon_token": None::<String>,
      "patreon_token_expires": 0
    }
  }).await.unwrap();

  Ok((
    StatusCode::OK,
    [
      ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
      ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
      ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
    ],
    Json(json!({
      "endpoint": "/settings"
    }))
  ))
}