use std::{ str::FromStr, sync::Arc };

use crate::{ apphandler::AppHandler, structs::{ session::Session, user::User } };
use anyhow::anyhow;
use argon2::{ password_hash::Encoding, Argon2, PasswordHash, PasswordVerifier };
use bson::{ doc, oid::ObjectId };
use chrono::Utc;
use serde_json::{ json, Value };

pub fn verified( user: &User, session: &Session ) -> anyhow::Result<(), Value> {
  if !user.email_verified { return Err(json!({  "procedure": "VERIFY_EMAIL", "endpoint": "/verify-email" })) }
  if !session.valid {
    if user.has_mfa { return Err(json!({  "procedure": "VERIFY_MFA", "endpoint": "/verify-mfa" })) }
    else            { return Err(json!({  "procedure": "VERIFY", "endpoint": "/verify" })) }
  }

  Ok(())
}

pub async fn identify_oauth( auth: String, scope: String, app: Arc<AppHandler> ) -> anyhow::Result<User> {
  if !auth.starts_with("Bearer "){ return Err(anyhow!("Invalid Token")) }

  let argon2 = Argon2::default();
  let now = Utc::now().timestamp();

  let auth = auth.split_at(7).1;
  let ( token_id, token ) = auth.split_at(24);

  let oauth_session = app.oauth_sessions.find_one(doc! { "_id": ObjectId::parse_str(token_id).unwrap() }).await.unwrap();
  if oauth_session.is_none(){ return Err(anyhow!("Invalid Token")) }

  let oauth_session = oauth_session.unwrap();

  if oauth_session.expires_on < now{
    app.oauth_sessions.delete_one(doc! { "_id": oauth_session._id }).await.unwrap();
    return Err(anyhow!("Invalid Token"))
  }

  let valid = argon2.verify_password(token.as_bytes(), &PasswordHash::parse(&oauth_session.token, Encoding::B64).unwrap()).is_ok();
  if !valid { return Err(anyhow!("Invalid Token")) }

  if !oauth_session.scopes.contains(&scope){ return Err(anyhow!("Invalid Token")) }

  let user = app.users.find_one(doc! { "_id": oauth_session.user_id }).await.unwrap();
  if user.is_none(){
    app.oauth_sessions.delete_one(doc! { "_id": oauth_session._id }).await.unwrap();
    return Err(anyhow!("Invalid Token"))
  }

  Ok(user.unwrap())
}

pub async fn identify( token: String, app: Arc<AppHandler>, ip: String ) -> anyhow::Result<( User, Session )> {
  if token.len() < 64 { return Err(anyhow!("Token is too short")) }

  let ( token, token_id ) = token.split_at(64);
  let token_id = ObjectId::from_str(token_id);

  if token_id.is_err(){ return Err(anyhow!("Invalid token ID")) }
  let token_id = token_id.unwrap();

  let session = app.sessions.find_one(doc! { "_id": token_id }).await.unwrap();

  if session.is_none(){ return Err(anyhow!("No session")) }
  let session = session.unwrap();

  if ip.ne(&session.loc.ip){ return Err(anyhow!("Invalid session")); }

  let now = Utc::now().timestamp();
  if session.expires_on < now {
    app.sessions.delete_many(doc! { "expires_on": { "$lt": now } }).await.unwrap();
    return Err(anyhow!("Invalid session"))
  }

  let argon2 = Argon2::default();
  if argon2.verify_password(token.as_bytes(), &PasswordHash::parse(&session.token, Encoding::B64).unwrap()).is_err()
    { return Err(anyhow!("Invalid session")) }

  let user = app.users.find_one(doc! { "_id": session.user_id }).await.unwrap();
  
  if user.is_none(){ return Err(anyhow!("No user")) }
  let user = user.unwrap();

  Ok(( user, session ))
}

pub async fn identify_reset( token: String, app: Arc<AppHandler> ) -> anyhow::Result<User> {
  if token.len() < 64 { return Err(anyhow!("Token is too short")) }

  let ( token, user_id ) = token.split_at(64);
  let user_id = ObjectId::from_str(user_id);

  if user_id.is_err(){ return Err(anyhow!("Invalid token ID")) }
  let user_id = user_id.unwrap();

  let user = app.users.find_one(doc! { "_id": user_id }).await.unwrap();

  if user.is_none(){ return Err(anyhow!("No session")) }
  let user = user.unwrap();

  if user.password_change_token.is_none(){ return Err(anyhow!("No reset available")); }

  let now = Utc::now().timestamp();
  if user.password_change_token_generated + 900 < now {
    app.users.update_one(doc! { "_id": user._id }, doc! { "$set": { "password_change_token": None::<String> } }).await.unwrap();
    return Err(anyhow!("Invalid session"))
  }

  let argon2 = Argon2::default();
  if argon2.verify_password(token.as_bytes(), &PasswordHash::parse(&user.password_change_token.clone().unwrap(), Encoding::B64).unwrap()).is_err()
    { return Err(anyhow!("Invalid session")) }

  Ok(user)
}