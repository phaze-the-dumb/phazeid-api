use std::sync::Arc;

use argon2::{password_hash::Encoding, Argon2, PasswordHash, PasswordVerifier};
use axum::{ extract::Query, http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use serde_json::json;
use bson::{doc, oid::ObjectId};

use crate::{ apphandler::AppHandler, structs::apierror::APIError, util::cors::cors };

#[derive(serde::Deserialize, Debug)]
pub struct OAuthApplicationToDeleteQuery{
  pub client_id: String,
}

pub async fn get(
  headers: HeaderMap,
  Query(query): Query<OAuthApplicationToDeleteQuery>,
  Extension(app): Extension<Arc<AppHandler>>
) -> impl IntoResponse{
  let oauth_app = app.oauth_apps.find_one(doc! { "_id": ObjectId::parse_str(&query.client_id).unwrap() }).await.unwrap();
  if oauth_app.is_none(){ return Err(APIError::new(500, "Invalid App".into())) }

  let oauth_app = oauth_app.unwrap();

  let auth = headers.get("Authorization").unwrap().to_str().unwrap();
  if !auth.starts_with("Bearer "){ return Err(APIError::new(401, "Invalid App Key".into())) }

  let argon2 = Argon2::default();
  let auth = auth.split_at(7).1;

  let valid = argon2.verify_password(auth.as_bytes(), &PasswordHash::parse(&oauth_app.key, Encoding::B64).unwrap()).is_ok();
  if !valid { return Err(APIError::new(500, "Invalid App Key".into())) }

  let mut cursor = app.users.find(doc! { "apps_to_delete_data": oauth_app._id }).await.unwrap();
  let mut users = Vec::new();

  while cursor.advance().await.unwrap() {
    let user = cursor.deserialize_current().unwrap();
    users.push(user);
  }

  Ok((
    StatusCode::OK,
    [
      ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
      ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
      ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
    ],
    Json(json!({ "users": users }))
  ))
}