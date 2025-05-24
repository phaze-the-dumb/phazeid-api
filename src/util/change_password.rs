use std::{fs, sync::Arc};

use argon2::{ password_hash::{ Encoding, SaltString }, Argon2, PasswordHash, PasswordVerifier, PasswordHasher };
use axum::extract::ws::{ Message, WebSocket };
use chrono::Utc;
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use regex::Regex;
use rsa::RsaPublicKey;
use anyhow::bail;
use bson::doc;

use crate::{ apphandler::AppHandler, util::encrypt::encrypt };
use super::{ email, token };

pub async fn try_reset_password( email: String, remote_pub_key: &RsaPublicKey, ws: &mut WebSocket, app: Arc<AppHandler> ) -> anyhow::Result<()>{
  let regex = Regex::new(r"^([^\x00-\x20\x22\x28\x29\x2c\x2e\x3a-\x3c\x3e\x40\x5b-\x5d\x7f-\xff]+|\x22([^\x0d\x22\x5c\x80-\xff]|\x5c[\x00-\x7f])*\x22)(\x2e([^\x00-\x20\x22\x28\x29\x2c\x2e\x3a-\x3c\x3e\x40\x5b-\x5d\x7f-\xff]+|\x22([^\x0d\x22\x5c\x80-\xff]|\x5c[\x00-\x7f])*\x22))*\x40([^\x00-\x20\x22\x28\x29\x2c\x2e\x3a-\x3c\x3e\x40\x5b-\x5d\x7f-\xff]+|\x5b([^\x0d\x5b-\x5d\x80-\xff]|\x5c[\x00-\x7f])*\x5d)(\x2e([^\x00-\x20\x22\x28\x29\x2c\x2e\x3a-\x3c\x3e\x40\x5b-\x5d\x7f-\xff]+|\x5b([^\x0d\x5b-\x5d\x80-\xff]|\x5c[\x00-\x7f])*\x5d))*$").unwrap();
  if !regex.is_match(&email){
    // 1 - Error, 0 - Error Code "Invalid Email"
    ws.send(Message::Text(encrypt("10".to_owned(), &remote_pub_key).unwrap().into())).await.unwrap();
    bail!("Invalid Email");
  }

  let user = app.users.find_one(doc! { "email": email }).await.unwrap();
  if user.is_none(){
    // User doesn't exist, but most sites seem to return an ok under this case for some reason?
    ws.send(Message::Text(encrypt("0".into(), &remote_pub_key)?.into())).await?;
    return Ok(())
  }

  let user = user.unwrap();

  let token: String = rand::thread_rng().sample_iter(&Alphanumeric).take(64).map(char::from).collect();
  
  let salt = SaltString::generate(&mut OsRng);

  let argon2 = Argon2::default();
  let token_hash = argon2.hash_password(token.as_bytes(), &salt).unwrap().to_string();

  let now = Utc::now().timestamp();
  app.users.update_one(doc! { "_id": user._id }, doc! { "$set": { 
    "password_change_token": token_hash,
    "password_change_token_generated": now
  } }).await.unwrap();

  email::send(
    ( user.username.as_str(), user.email.as_str() ), 
    "PhazeID Password Reset",
    &fs::read_to_string("templates/email/password_reset.html").unwrap()
      .replace("{{USERNAME}}", &user.username)
      .replace("{{URL}}", &format!("http://localhost:5173/reset#{}{}", token, user._id.to_hex()))
  ).await.unwrap();

  ws.send(Message::Text(encrypt("0".into(), &remote_pub_key)?.into())).await?;
  Ok(())
}

pub async fn try_change_password_without_account( password: String, token: String, remote_pub_key: &RsaPublicKey, ws: &mut WebSocket, app: Arc<AppHandler> ) -> anyhow::Result<()>{  
  if
    password.len() > 50
  {
    // 1 - Error, 2 - Error Code "Password must be less than 50 characters"
    ws.send(Message::Text(encrypt("12".to_owned(), &remote_pub_key).unwrap().into())).await.unwrap();
    bail!("Password must be less than 50 characters");
  }
 
  let identity = token::identify_reset(token, app.clone()).await;
  if identity.is_err() {
    // 1 - Error, 0 - Error Code "Invalid Token"
    ws.send(Message::Text(encrypt("10".to_owned(), &remote_pub_key)?.into())).await?;
    bail!("Invalid Token");
  }

  let user = identity.unwrap();

  let now = Utc::now().timestamp();
  if user.last_password_change + 900 > now {
    // 1 - Error, 0 - Error Code "Password has been changed in the last 15 minutes. Please wait to change it again."
    ws.send(Message::Text(encrypt("11".to_owned(), &remote_pub_key)?.into())).await?;
    bail!("Password has been changed in the last 15 minutes. Please wait to change it again.");
  }

  let argon2 = Argon2::default();

  let salt = SaltString::generate(&mut OsRng);
  let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();

  let now = Utc::now().timestamp();
  app.users.update_one(doc! { "_id": user._id }, doc! { "$set": {
    "password": password_hash,
    "last_password_change": now
  } }).await.unwrap();

  ws.send(Message::Text(encrypt("0".into(), &remote_pub_key)?.into())).await?;
  Ok(())
}

pub async fn try_change_password( new_password: String, old_password: String, token: String, remote_pub_key: &RsaPublicKey, ws: &mut WebSocket, app: Arc<AppHandler> ) -> anyhow::Result<()>{  
  if
    old_password.len() > 50 ||
    new_password.len() > 50
  {
    // 1 - Error, 0 - Error Code "Password must be less than 50 characters"
    ws.send(Message::Text(encrypt("12".to_owned(), &remote_pub_key).unwrap().into())).await.unwrap();
    bail!("Password must be less than 50 characters");
  }
 
  let identity = token::identify(token, app.clone()).await;
  if identity.is_err() {
    // 1 - Error, 0 - Error Code "Invalid Token"
    ws.send(Message::Text(encrypt("10".to_owned(), &remote_pub_key)?.into())).await?;
    bail!("Invalid Token");
  }

  let ( user, session ) = identity.unwrap();
  let verified = token::verified(&user, &session);

  if verified.is_err() {
    // 1 - Error, 0 - Error Code "Invalid Token"
    ws.send(Message::Text(encrypt("10".to_owned(), &remote_pub_key)?.into())).await?;
    bail!("Invalid Token");
  }

  let now = Utc::now().timestamp();
  if user.last_password_change + 900 > now {
    // 1 - Error, 0 - Error Code "Password has been changed in the last 15 minutes. Please wait to change it again."
    ws.send(Message::Text(encrypt("13".to_owned(), &remote_pub_key)?.into())).await?;
    bail!("Password has been changed in the last 15 minutes. Please wait to change it again.");
  }

  let argon2 = Argon2::default();

  let pass = argon2.verify_password(old_password.as_bytes(), &PasswordHash::parse(&user.password, Encoding::B64).unwrap());
  if pass.is_err(){
    // 1 - Error, 0 - Error Code "Incorrect Username or Password"
    ws.send(Message::Text(encrypt("11".to_owned(), &remote_pub_key)?.into())).await?;
    bail!("Incorrect Password");
  }
  let salt = SaltString::generate(&mut OsRng);
  let password_hash = argon2.hash_password(new_password.as_bytes(), &salt).unwrap().to_string();

  let now = Utc::now().timestamp();
  app.users.update_one(doc! { "_id": user._id }, doc! { "$set": {
    "password": password_hash,
    "last_password_change": now
  } }).await.unwrap();

  ws.send(Message::Text(encrypt("0".into(), &remote_pub_key)?.into())).await?;
  Ok(())
}