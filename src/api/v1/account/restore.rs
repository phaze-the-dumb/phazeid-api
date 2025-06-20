use std::{ fs, sync::Arc };

use axum::{ http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use chrono::Utc;
use serde_json::json;
use bson::doc;

use crate::{ apphandler::AppHandler, structs::apierror::APIError, util::{ cookies, cors::cors, email, ip::get_ip_from_request, token } };

pub async fn get(
  headers: HeaderMap,
  Extension(app): Extension<Arc<AppHandler>>
) -> impl IntoResponse{
  let cookies = headers.get("cookie");
  if cookies.is_none() { return Err(APIError::default()) }
  
  let cookies = cookies.unwrap().to_str().unwrap().to_owned();
  let cookies = cookies::parse(cookies);

  let token = cookies.get("token").unwrap().clone();

  let identity = token::identify(token, app.clone(), get_ip_from_request(&headers).unwrap()).await;
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

  if user.deletion_flagged_after.is_none(){ return Err(APIError::new(500, "Account is not flagged for deletion.".into())) }
  let deleting_at = user.deletion_flagged_after.unwrap();

  let now = Utc::now().timestamp();
  if deleting_at < now { return Err(APIError::new(500, "Account doesn't exist.".into())) }

  app.users.update_one(doc! { "_id": user._id }, doc! { "$set": { "deletion_flagged_after": None::<i64> } }).await.unwrap();

  email::send(
    ( user.username.as_str(), user.email.as_str() ),
    "Welcome Back!",
    &fs::read_to_string("templates/email/restored_alert.html").unwrap()
      .replace("{{USERNAME}}", &user.username)
  ).await.unwrap();

  Ok((
    StatusCode::OK,
    [
      ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
      ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
      ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
    ],
    Json(json!({
      "endpoint": "/profile"
    }))
  ))
}