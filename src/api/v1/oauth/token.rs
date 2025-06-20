use std::sync::Arc;

use argon2::{ password_hash::{ Encoding, SaltString }, Argon2, PasswordHash, PasswordVerifier, PasswordHasher };
use axum::{ extract::Query, http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use bson::{ doc, oid::ObjectId };
use chrono::Utc;
use rand::{ distributions::Alphanumeric, rngs::OsRng, Rng };
use serde_json::json;

use crate::{ apphandler::AppHandler, structs::{ apierror::APIError, oauthsession::OAuthSession }, util::cors::cors };

#[derive(serde::Deserialize, Debug)]
pub struct OAuthApplicationRequestQuery{
  pub grant_type: String,
  pub client_id: String,
  pub redirect_uri: String,
  pub code: String
}

pub async fn get(
  headers: HeaderMap,
  Query(query): Query<OAuthApplicationRequestQuery>,
  Extension(app): Extension<Arc<AppHandler>>
) -> impl IntoResponse{
  if query.grant_type != "authorization_code" { return Err(APIError::new(400, "Invalid Grant Type.".into())); }

  let oauth_app = app.oauth_apps.find_one(doc! { "_id": ObjectId::parse_str(&query.client_id).unwrap() }).await.unwrap();
  if oauth_app.is_none(){ return Err(APIError::new(500, "Invalid App".into())) }

  let oauth_app = oauth_app.unwrap();
  if !oauth_app.redirect_uris.contains(&query.redirect_uri){ return Err(APIError::new(500, "Invalid Redirect URI".into())) }

  let auth = headers.get("Authorization").unwrap().to_str().unwrap();
  if !auth.starts_with("Bearer "){ return Err(APIError::new(401, "Invalid App Key".into())) }

  let argon2 = Argon2::default();
  let now = Utc::now().timestamp();

  let auth = auth.split_at(7).1;

  let valid = argon2.verify_password(auth.as_bytes(), &PasswordHash::parse(&oauth_app.key, Encoding::B64).unwrap()).is_ok();
  if !valid { return Err(APIError::new(500, "Invalid App Key".into())) }

  let ( token_id, token ) = query.code.split_at(24);

  let oauth_code = app.oauth_codes.find_one(doc! { "_id": ObjectId::parse_str(token_id).unwrap() }).await.unwrap();
  if oauth_code.is_none(){ return Err(APIError::new(500, "Invalid OAuth Code.".into())) }

  let oauth_code = oauth_code.unwrap();
  if oauth_code.expires_on < now {
    app.oauth_codes.delete_one(doc! { "_id": oauth_code._id }).await.unwrap();
    return Err(APIError::new(500, "Invalid OAuth Code.".into()))
  }

  if
    query.redirect_uri != oauth_code.redirect_uri ||
    query.client_id != oauth_code.app.to_hex()
  {
    return Err(APIError::new(500, "Invalid OAuth Code.".into()))
  }

  let valid = argon2.verify_password(token.as_bytes(), &PasswordHash::parse(&oauth_code.token, Encoding::B64).unwrap()).is_ok();
  if !valid { return Err(APIError::new(500, "Invalid OAuth Code.".into())) }

  let token: String = rand::thread_rng().sample_iter(&Alphanumeric).take(64).map(char::from).collect();
  let salt = SaltString::generate(&mut OsRng);

  let oauth_session = OAuthSession {
    _id: ObjectId::new(),
    token: argon2.hash_password(token.as_bytes(), &salt).unwrap().to_string(),

    created_on: now,
    expires_on: now + 3_600,

    app_id: oauth_app._id,
    app_name: oauth_app.name,

    user_id: oauth_code.user_id,
    scopes: oauth_code.scopes
  };

  app.oauth_sessions.insert_one(&oauth_session).await.unwrap();
  app.oauth_codes.delete_one(doc! { "_id": oauth_code._id }).await.unwrap();

  Ok((
    StatusCode::OK,
    [
      ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
      ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
      ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
    ],
    Json(json!({
      "access_token": format!("{}{}", oauth_session._id.to_hex(), token),
      "token_type": "Bearer",
      "expires_in": 3600,
      "refresh_token": None::<String>
    }))
  ))
}