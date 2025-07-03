use std::{env, sync::Arc};

use argon2::{ password_hash::SaltString, Argon2, PasswordHasher };
use axum::{ extract::Query, http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use bson::{doc, oid::ObjectId};
use chrono::Utc;
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use serde::Deserialize;
use serde_json::json;

use crate::{ apphandler::AppHandler, structs::{apierror::APIError, oauthcode::OAuthCode, tunnel::TurnstileRes}, util::{ cookies, cors::cors, ip::get_ip_from_request, token } };

#[derive(serde::Deserialize, Debug)]
pub struct OAuthApplicationRequestQuery{
  pub response_type: String,
  pub client_id: String,
  pub redirect_uri: String,
  pub scope: String
}

#[derive(Deserialize)]
pub struct OAuthApplicationRequest{
  pub token: String
}

const SCOPES: [ &'static str; 1 ] = [ "identify" ];

pub async fn put(
  headers: HeaderMap,
  Query(query): Query<OAuthApplicationRequestQuery>,
  Extension(app): Extension<Arc<AppHandler>>,
  Json(body): Json<OAuthApplicationRequest>
) -> impl IntoResponse{
  let cookies = headers.get("cookie");
  if cookies.is_none() { return Err(APIError::default(&headers)) }
  
  let cookies = cookies.unwrap().to_str().unwrap().to_owned();
  let cookies = cookies::parse(cookies);

  let token = cookies.get("token").unwrap().clone();

  let identity = token::identify(token, app.clone(), get_ip_from_request(&headers).unwrap()).await;
  if identity.is_err() { return Err(APIError::new(500, identity.unwrap_err().to_string(), &headers)) }

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

  if query.response_type != "code" && query.response_type != "code_skip" { return Err(APIError::new(400, "Invalid Response Type.".into(), &headers)); }

  let oauth_app = app.oauth_apps.find_one(doc! { "_id": ObjectId::parse_str(query.client_id).unwrap() }).await.unwrap();
  if oauth_app.is_none(){ return Err(APIError::new(500, "Invalid App".into(), &headers)) }

  let oauth_app = oauth_app.unwrap();
  if !oauth_app.redirect_uris.contains(&query.redirect_uri){ return Err(APIError::new(500, "Invalid Redirect URI".into(), &headers)) }

  if query.response_type == "code_skip" {
    if !oauth_app.allow_skip { return Err(APIError::new(400, "Invalid Response Type.".into(), &headers)); }
  } else{
    let client = reqwest::Client::new();
    let dat = client.post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
      .body(serde_json::to_string(&json!({
        "secret": env::var("CF_TURNSTILE_SECRET").unwrap(),
        "response": body.token
      })).unwrap())
      .header("Content-Type", "application/json")
      .send().await.unwrap().text().await.unwrap();

    let dat: TurnstileRes = serde_json::from_str(&dat).unwrap();
    if !dat.success { return Err(APIError::new(400, "Invalid Captcha.".into(), &headers)); }
  }

  let scopes = query.scope.split(",");
  for scope in scopes.clone() {
    if !SCOPES.contains(&scope){ return Err(APIError::new(500, "Invalid Scopes".into(), &headers)) } }

  let token: String = rand::thread_rng().sample_iter(&Alphanumeric).take(64).map(char::from).collect();

  let argon2 = Argon2::default();
  let salt = SaltString::generate(&mut OsRng);

  let now = Utc::now().timestamp();

  let ocode = OAuthCode {
    _id: ObjectId::new(),
    token: argon2.hash_password(token.as_bytes(), &salt).unwrap().to_string(),

    app: oauth_app._id,
    redirect_uri: query.redirect_uri,

    created_on: now,
    expires_on: now + 60, // Expires in 1 minute. (OAuth 2.0 spec says max 10 min)

    refresh: false,

    user_id: user._id,
    scopes: scopes.map(|x| x.into()).collect()
  };

  app.oauth_codes.delete_many(doc! { "user_id": user._id, "app": oauth_app._id }).await.unwrap();
  app.oauth_codes.insert_one(&ocode).await.unwrap();

  if !user.allowed_apps.contains(&oauth_app._id){
    app.users.update_one(doc! { "_id": user._id }, doc! {
      "$push": { "allowed_apps": oauth_app._id }
    }).await.unwrap();
  }

  Ok((
    StatusCode::OK,
    [
      ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
      ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
      ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
    ],
    Json(json!({
      "code": format!("{}{}", ocode._id.to_hex(), token)
    }))
  ))
}