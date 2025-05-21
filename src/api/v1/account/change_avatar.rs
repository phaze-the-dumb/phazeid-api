use std::sync::Arc;

use axum::{ extract::Multipart, http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use chrono::Utc;
use serde_json::json;
use bson::doc;

use crate::{ apphandler::AppHandler, structs::apierror::APIError, util::{ avatar, cookies, cors::cors, token } };

pub async fn put( 
  headers: HeaderMap,
  Extension(app): Extension<Arc<AppHandler>>,
  mut multipart: Multipart
) -> impl IntoResponse{
  let cookies = headers.get("cookie");
  if cookies.is_none() { return Err(APIError::default()) }
  
  let cookies = cookies.unwrap().to_str().unwrap().to_owned();
  let cookies = cookies::parse(cookies);

  let token = cookies.get("token").unwrap().clone();

  let identity = token::identify(token, app.clone()).await;
  if identity.is_err() { return Err(APIError::new(500, identity.unwrap_err().to_string())) }

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
  if user.last_avatar_change + 15 > now { return Err(APIError::new(429, "Rate limited".into())) }

  let file = multipart.next_field().await.unwrap().unwrap();
  if file.content_type().unwrap() != "image/png" { return Err(APIError::default()) }

  let res = avatar::upload(user._id, user.avatar, file, app.r2()).await;
  if res.is_err() { return Err(APIError::new(500, "Could not upload avatar".into())) }

  app.users.update_one(doc! { "_id": user._id }, doc! { "$set": {
    "last_avatar_change": now,
    "avatar": res.unwrap()
  } }).await.unwrap();
  
  Ok((
    StatusCode::OK,
    [
      ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
      ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
      ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
    ],
    Json(json!({
      "ok": true,
    }))
  ))
}