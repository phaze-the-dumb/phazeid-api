use std::{env, fs, sync::Arc};

use argon2::{ password_hash::{Encoding, SaltString}, Argon2, PasswordHash, PasswordHasher, PasswordVerifier };
use axum::extract::ws::{ Message, WebSocket };
use chrono::Utc;
use rand::{ distributions::Alphanumeric, rngs::OsRng, Rng };
use rsa::RsaPublicKey;
use bson::{ doc, oid::ObjectId };
use anyhow::bail;

use crate::{ apphandler::AppHandler, structs::{ipinfo::IPInfo, session::Session, user::User} };

use super::{email, encrypt::encrypt};

pub async fn try_login( ip: &str, username: String, password: String, remote_pub_key: &RsaPublicKey, ws: &mut WebSocket, app: Arc<AppHandler> ) -> anyhow::Result<User>{
  if
    username.eq("") ||
    username.len() > 50 ||
    password.len() > 50
  {
    // 1 - Error, 0 - Error Code "Password and Username must be less than 50 characters"
    ws.send(Message::Text(encrypt("10".to_owned(), &remote_pub_key)?.into())).await?;
    bail!("Password and Username must be less than 50 characters");
  }

  let user = app.users.find_one(doc! { "username": &username }).await?;
  if user.is_none(){
    // 1 - Error, 0 - Error Code "Incorrect Username or Password"
    ws.send(Message::Text(encrypt("11".to_owned(), &remote_pub_key)?.into())).await?;
    bail!("Incorrect Username or Password");
  }

  let user = user.unwrap();
  
  if user.account_locked{
    if user.locked_until < Utc::now().timestamp(){
      app.users.update_one(doc! { "_id": user._id }, doc! { "$set": { "account_locked": false } }).await?;
    } else{
      // 1 - Error, 0 - Error Code "Account locked until 000"
      ws.send(Message::Text(encrypt(format!("12{}", user.locked_until.to_string()), &remote_pub_key)?.into())).await?;
      bail!("Account locked until 000");
    }
  }

  if user.login_attempts > 4{
    let locked_until = Utc::now().timestamp() + 900;
    app.users.update_one(doc! { "_id": user._id }, doc! { 
      "$set": {
        "account_locked": true,
        "locked_until": locked_until,
        "login_attempts": 0
      }
    }).await?;

    // 1 - Error, 0 - Error Code "Account locked until 000"
    ws.send(Message::Text(encrypt(format!("12{}", locked_until.to_string()), &remote_pub_key)?.into())).await?;
    bail!("Account locked until 000");
  }

  let argon2 = Argon2::default();

  let pass = argon2.verify_password(password.as_bytes(), &PasswordHash::parse(&user.password, Encoding::B64).unwrap());
  if pass.is_err(){
    app.users.update_one(doc! { "_id": user._id }, doc! { "$inc": { "login_attempts": 1 } }).await.unwrap();

    // 1 - Error, 0 - Error Code "Incorrect Username or Password"
    ws.send(Message::Text(encrypt("11".to_owned(), &remote_pub_key)?.into())).await?;
    bail!("Incorrect Username or Password");
  }

  let ip_info = reqwest::get(format!("https://ipinfo.io/{}?token={}", ip, env::var("IPINFO_KEY").unwrap())).await.unwrap();
  let ip_info: IPInfo = serde_json::from_str(&ip_info.text().await.unwrap()).unwrap();

  let now = Utc::now().timestamp();
  let token: String = rand::thread_rng().sample_iter(&Alphanumeric).take(64).map(char::from).collect();

  app.sessions.delete_many(doc! { "valid": false, "user_id": user._id }).await.unwrap();
  app.sessions.delete_many(doc! { "expires_on": { "$lt": now }, "user_id": user._id }).await.unwrap();

  let salt = SaltString::generate(&mut OsRng);

  let session = Session {
    _id: ObjectId::new(),

    token: argon2.hash_password(token.as_bytes(), &salt).unwrap().to_string(),

    created_on: now,
    expires_on: now + 2629800, // Session expires in a month

    loc: ip_info,

    valid: false,
    challenge_code: None,

    user_id: user._id
  };

  app.sessions.insert_one(&session).await.unwrap();
  app.users.update_one(doc! { "_id": user._id }, doc! { "$set": { "login_attempts": 0 } }).await.unwrap();

  ws.send(Message::Text(encrypt(format!("0{}{}", token, session._id), &remote_pub_key)?.into())).await?;

  email::send(
    ( user.username.as_str(), user.email.as_str() ), 
    "PhazeID Login",
    &fs::read_to_string("templates/email/login_alert.html").unwrap()
      .replace("{{USERNAME}}", &user.username)
      .replace("{{IP}}", &session.loc.ip)
  ).await.unwrap();

  Ok(user)
}