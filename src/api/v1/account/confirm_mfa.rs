use std::sync::Arc;

use argon2::{ password_hash::SaltString, Argon2, PasswordHasher };
use axum::{ http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use rand::{ distributions::Alphanumeric, rngs::OsRng, Rng };
use serde::Deserialize;
use serde_json::json;
use bson::doc;
use totp_rs::{ Algorithm, Secret, TOTP };

use crate::{ apphandler::AppHandler, structs::apierror::APIError, util::{ cookies, cors::cors, encrypt, token } };

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

  let account_secret = user.mfa_string.clone().unwrap();
  let account_secret = Secret::Raw(encrypt::decrypt_from_user(&user, account_secret).as_bytes().to_vec());

  let totp = TOTP::new(
    Algorithm::SHA1, 
    6, 1, 30, 
    account_secret.to_bytes().unwrap(), 
    Some("Phaze ID".to_string()), 
    user.username
  ).unwrap();

  let valid = totp.check_current(&body.code).unwrap();
  if !valid { return Err(APIError::new(500, "Invalid Code".into())) }

  let mut raw_codes = vec![];
  let mut codes = vec![];

  let argon2 = Argon2::default();

  for _i in 0..6 {
    let raw_code: String = rand::thread_rng().sample_iter(&Alphanumeric).take(8).map(char::from).collect();
    raw_codes.push(raw_code.clone());

    let salt = SaltString::generate(&mut OsRng);
    let hash_code = argon2.hash_password(raw_code.as_bytes(), &salt).unwrap().to_string();
    codes.push(hash_code);
  }

  app.users.update_one(doc! { "_id": user._id }, doc! { "$set": {
    "has_mfa": true,
    "backup_codes": codes
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
      "backup_codes": raw_codes
    }))
  ))
}