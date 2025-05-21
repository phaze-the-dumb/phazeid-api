use std::sync::Arc;

use axum::{ http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use serde::Deserialize;
use serde_json::json;
use bson::doc;

use crate::{ apphandler::AppHandler, structs::apierror::APIError, util::{ cookies, cors::cors, token } };

#[derive(Deserialize)]
pub struct VerifyEmailRequest{
  pub code: String
}

pub async fn put( 
  headers: HeaderMap,
  Extension(app): Extension<Arc<AppHandler>>,
  Json(body): Json<VerifyEmailRequest>
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

  if body.code.eq(&user.email_update.verification_code){
    app.users.update_one(
      doc! { "_id": user._id }, 
      doc! { "$set": { 
        "email_update.email": "",
        "email_update.verification_code": "",
        "email": user.email_update.email
      } }
    ).await.unwrap();

    Ok((
      StatusCode::OK,
      [
        ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
        ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
        ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
      ],
      Json(json!({
        "ok": true,
        "endpoint": "/settings"
      }))
    ))
  } else{
    Err(APIError::default())
  }
}