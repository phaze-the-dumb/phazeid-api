use std::sync::Arc;

use axum::{ http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use serde::Deserialize;
use serde_json::json;
use bson::doc;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::{ apphandler::AppHandler, structs::apierror::APIError, util::{ cors::cors, token } };

#[derive(Deserialize)]
pub struct VerifyEmailRequestBody{
  code: String,
  token: String
}

pub async fn post(
  headers: HeaderMap,
  Extension(app): Extension<Arc<AppHandler>>,
  Json(body): Json<VerifyEmailRequestBody>
) -> impl IntoResponse{
  let identity = token::identify(body.token.clone(), app.clone()).await;
  if identity.is_err() { return Err(APIError::new(500, identity.unwrap_err().to_string())) }

  let ( user, session ) = identity.unwrap();
  if !user.email_verified { return Err(APIError::new(400, "Email not verified".into())) }

  let account_secret = Secret::Raw(user.mfa_string.unwrap().as_bytes().to_vec());

  let totp = TOTP::new(
    Algorithm::SHA1, 
    6, 1, 30, 
    account_secret.to_bytes().unwrap(), 
    Some("Phaze ID".to_string()), 
    user.username
  ).unwrap();

  let valid = totp.check_current(&body.code).unwrap();
  if valid{
    app.users.update_one(
      doc! { "_id": user._id }, 
      doc! { "$set": { "email_verified": true, "email_verification_code": "" } }
    ).await.unwrap();

    if !session.valid{
      app.sessions.update_one(
        doc! { "_id": session._id }, 
        doc! { "$set": { "valid": true } }
      ).await.unwrap();
    }

    Ok((
      StatusCode::OK,
      [
        ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
        ( header::ACCESS_CONTROL_ALLOW_METHODS, "POST".into() ),
        ( header::SET_COOKIE, format!("token={}; Max-Age=604800; Domain=localhost; Path=/api; HttpOnly; Secure; SameSite=Strict", body.token) ),
        ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
      ],
      Json(json!({ "ok": true, "PROCEDURE": "PROFILE", "endpoint": format!("/profile#{}", user._id.to_hex()) }))
    ))
  } else{
    Err(APIError::new(400, "Invalid Code".into()))
  }
}