use std::sync::Arc;

use argon2::{ password_hash::SaltString, Argon2, PasswordHasher };
use axum::{ http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use bson::{doc, oid::ObjectId};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use serde::Deserialize;
use serde_json::json;

use crate::{ apphandler::AppHandler, structs::{ apierror::APIError, oauthapp::OAuthApplication }, util::{ cookies, cors::cors, ip::get_ip_from_request, token } };

#[derive(Deserialize)]
pub struct AppApplicationRequest{
  pub name: String,
  pub redirect_uris: Vec<String>
}

pub async fn put(
  headers: HeaderMap,
  Extension(app): Extension<Arc<AppHandler>>,
  Json(body): Json<AppApplicationRequest>
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

  if !user.roles.contains(&"DEV".to_string()){ return Err(APIError::new(404, "nothing to see here".into(), &headers)) }
  let token: String = rand::thread_rng().sample_iter(&Alphanumeric).take(64).map(char::from).collect();

  let argon2 = Argon2::default();
  let salt = SaltString::generate(&mut OsRng);

  let oapp = OAuthApplication {
    _id: ObjectId::new(),
    name: body.name,
    allow_skip: false,
    key: argon2.hash_password(token.as_bytes(), &salt).unwrap().to_string(),
    redirect_uris: body.redirect_uris,
    owner_id: user._id
  };

  app.oauth_apps.insert_one(&oapp).await.unwrap();

  Ok((
    StatusCode::OK,
    [
      ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
      ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
      ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
    ],
    Json(json!({
      "_id": oapp._id,
      "key": token
    }))
  ))
}