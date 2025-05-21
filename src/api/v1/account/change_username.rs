use std::{env, sync::Arc};

use axum::{ http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use bson::doc;

use crate::{ apphandler::AppHandler, structs::{apierror::APIError, tunnel::TurnstileRes}, util::{ cookies, cors::cors, token } };

#[derive(Deserialize)]
pub struct ChangeUsernameRequest{
  pub value: String,
  pub token: String
}

pub async fn put( 
  headers: HeaderMap,
  Extension(app): Extension<Arc<AppHandler>>,
  Json(body): Json<ChangeUsernameRequest>
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

  if body.value.eq("") { return Err(APIError::new(400, "NO.".into())); }  
  
  let now = Utc::now().timestamp();
  if user.last_username_change + 900 > now { return Err(APIError::new(429, "Username has been changed in the last 15 minutes. Please wait to change it again.".into())) }

  let client = reqwest::Client::new();
  let dat = client.post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
    .body(serde_json::to_string(&json!({
      "secret": env::var("CF_TURNSTILE_SECRET").unwrap(),
      "response": body.token
    })).unwrap())
    .header("Content-Type", "application/json")
    .send().await.unwrap().text().await.unwrap();

  let dat: TurnstileRes = serde_json::from_str(&dat).unwrap();
  if !dat.success { return Err(APIError::new(400, "Invalid Captcha.".into())); }

  let user_to_check = app.users.find_one(doc! { "username": &body.value }).await.unwrap();
  if user_to_check.is_some(){
    return Err(APIError::new(400, "Username already in use.".into())); }

  app.users.update_one(doc! { "_id": user._id }, doc! { "$set": {
    "username": body.value,
    "last_username_change": now
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
      "endpoint": "/settings"
    }))
  ))
}