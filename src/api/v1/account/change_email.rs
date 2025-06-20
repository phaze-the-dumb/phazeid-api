use std::{env, fs, sync::Arc};

use axum::{ http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use chrono::Utc;
use rand::{distributions::Alphanumeric, Rng};
use serde::Deserialize;
use serde_json::json;
use bson::doc;

use crate::{ apphandler::AppHandler, structs::{apierror::APIError, tunnel::TurnstileRes}, util::{ cookies, cors::cors, email, ip::get_ip_from_request, token } };

#[derive(Deserialize)]
pub struct ChangeEmailRequest{
  pub value: String,
  pub token: String
}

pub async fn put( 
  headers: HeaderMap,
  Extension(app): Extension<Arc<AppHandler>>,
  Json(body): Json<ChangeEmailRequest>
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

  if body.value.eq("") { return Err(APIError::new(400, "NO.".into())); }

  let now = Utc::now().timestamp();
  if user.last_email_change + 900 > now { return Err(APIError::new(429, "Email has been changed in the last 15 minutes. Please wait to change it again.".into())) }

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

  let user_to_check = app.users.find_one(doc! { "email": &body.value }).await.unwrap();
  if user_to_check.is_some(){
    return Err(APIError::new(400, "Email already in use.".into())); }

  let code = rand::thread_rng().sample_iter(&Alphanumeric).take(6).map(char::from).collect::<String>();

  app.users.update_one(doc! { "_id": user._id }, doc! { "$set": { 
    "email_update.email": body.value,
    "email_update.verification_code": &code,
    "last_email_change": now
  } }).await.unwrap();

  email::send(
    ( user.username.as_str(), user.email.as_str() ), 
    "PhazeID Email Verification",
    &fs::read_to_string("templates/email/email_verification.html").unwrap()
      .replace("{{USERNAME}}", &user.username)
      .replace("{{CODE}}", &code)
  ).await.unwrap();

  Ok((
    StatusCode::OK,
    [
      ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
      ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
      ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
    ],
    Json(json!({
      "endpoint": "/account/email/verify"
    }))
  ))
}