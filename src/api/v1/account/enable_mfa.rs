use std::sync::Arc;

use axum::{ http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use rand::{distributions::Alphanumeric, Rng};
use serde_json::json;
use bson::doc;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::{ apphandler::AppHandler, structs::apierror::APIError, util::{ cookies, cors::cors, token } };

pub async fn get( 
  headers: HeaderMap,
  Extension(app): Extension<Arc<AppHandler>>
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

  if user.has_mfa{
    Ok((
      StatusCode::OK,
      [
        ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
        ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
        ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
      ],
      Json(json!({
        "ok": true,
        "is_enabled": true
      }))
    ))
  } else{
    let raw_secret: String = rand::thread_rng().sample_iter(&Alphanumeric).take(16).map(char::from).collect();
    let account_secret = Secret::Raw(raw_secret.as_bytes().to_vec());

    let totp = TOTP::new(
      Algorithm::SHA1, 
      6, 1, 30, 
      account_secret.to_bytes().unwrap(), 
      Some("Phaze ID".to_string()), 
      user.username
    ).unwrap();

    app.users.update_one(doc! { "_id": user._id }, doc! { "$set": {
      "mfa_string": raw_secret
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
        "is_enabled": false,
        "qr": totp.get_qr_base64(),
        "txt": totp.get_secret_base32()
      }))
    ))
  }
}