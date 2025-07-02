use std::sync::Arc;

use axum::{ http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use serde::Deserialize;
use serde_json::json;
use bson::doc;

use crate::{ apphandler::AppHandler, structs::apierror::APIError, util::{ cors::cors, ip::get_ip_from_request, token } };

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
  let identity = token::identify(body.token.clone(), app.clone(), get_ip_from_request(&headers).unwrap()).await;
  if identity.is_err() { return Err(APIError::new(500, identity.unwrap_err().to_string(), &headers)) }

  let ( user, session ) = identity.unwrap();
  if user.email_verified { return Err(APIError::new(400, "Email already verified".into(), &headers)) }

  if body.code.eq(&user.email_verification_code){
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
        ( header::SET_COOKIE, format!("token={}; Max-Age=604800; Domain=idapi-jye3bcyp.phazed.xyz; Path=/api; HttpOnly; Secure; SameSite=Strict", body.token) ),
        ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
      ],
      Json(json!({ "PROCEDURE": "NEXT" }))
    ))
  } else{
    Err(APIError::new(400, "Invalid Code".into(), &headers))
  }
}