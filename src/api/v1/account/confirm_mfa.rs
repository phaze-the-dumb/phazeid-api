use std::sync::Arc;

use axum::{ http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use serde::Deserialize;
use serde_json::json;
use bson::doc;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::{ apphandler::AppHandler, structs::apierror::APIError, util::{ cookies, cors::cors, token } };

#[derive(Deserialize)]
pub struct ConfirmMfaRequest{
  pub code: String
}

pub async fn put( 
  headers: HeaderMap,
  Extension(app): Extension<Arc<AppHandler>>,
  Json(body): Json<ConfirmMfaRequest>,
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

  let account_secret = Secret::Raw(user.mfa_string.unwrap().as_bytes().to_vec());

  let totp = TOTP::new(
    Algorithm::SHA1, 
    6, 1, 30, 
    account_secret.to_bytes().unwrap(), 
    Some("Phaze ID".to_string()), 
    user.username
  ).unwrap();

  let valid = totp.check_current(&body.code).unwrap();
  if !valid { return Err(APIError::new(500, "Invalid Code".into())) }

  app.users.update_one(doc! { "_id": user._id }, doc! { "$set": {
    "has_mfa": true
  } }).await.unwrap();

  Ok((
    StatusCode::OK,
    [
      ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
      ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
      ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
    ],
    Json(json!({ 
      "ok": true
    }))
  ))
}