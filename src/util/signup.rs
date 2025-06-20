use std::{env, fs, sync::Arc};

use argon2::{ password_hash::SaltString, Argon2, PasswordHasher };
use axum::extract::ws::{ Message, WebSocket };
use chrono::Utc;
use rand::{distributions::Alphanumeric, rngs::OsRng, seq::SliceRandom, Rng};
use regex::Regex;
use rsa::RsaPublicKey;
use bson::{ doc, oid::ObjectId };
use anyhow::bail;

use crate::{ apphandler::AppHandler, structs::{ ipinfo::IPInfo, session::Session, user::{User, UserEmailUpdate} } };

use super::{ email, encrypt::encrypt };

const DEFAULT_AVIS: [&str; 1] = [ "default" ];

pub async fn try_signup( ip: &str, username: String, password: String, email: String, remote_pub_key: &RsaPublicKey, ws: &mut WebSocket, app: Arc<AppHandler> ) -> anyhow::Result<User>{
  if
    username.eq("") ||
    username.len() > 50 ||
    password.len() > 50
  {
    // 1 - Error, 0 - Error Code "Password and Username must be less than 50 characters"
    ws.send(Message::Text(encrypt("10".to_owned(), &remote_pub_key).unwrap().into())).await.unwrap();
    bail!("Password and Username must be less than 50 characters");
  }

  let regex = Regex::new(r"^([^\x00-\x20\x22\x28\x29\x2c\x2e\x3a-\x3c\x3e\x40\x5b-\x5d\x7f-\xff]+|\x22([^\x0d\x22\x5c\x80-\xff]|\x5c[\x00-\x7f])*\x22)(\x2e([^\x00-\x20\x22\x28\x29\x2c\x2e\x3a-\x3c\x3e\x40\x5b-\x5d\x7f-\xff]+|\x22([^\x0d\x22\x5c\x80-\xff]|\x5c[\x00-\x7f])*\x22))*\x40([^\x00-\x20\x22\x28\x29\x2c\x2e\x3a-\x3c\x3e\x40\x5b-\x5d\x7f-\xff]+|\x5b([^\x0d\x5b-\x5d\x80-\xff]|\x5c[\x00-\x7f])*\x5d)(\x2e([^\x00-\x20\x22\x28\x29\x2c\x2e\x3a-\x3c\x3e\x40\x5b-\x5d\x7f-\xff]+|\x5b([^\x0d\x5b-\x5d\x80-\xff]|\x5c[\x00-\x7f])*\x5d))*$").unwrap();
  if !regex.is_match(&email){
    // 1 - Error, 1 - Error Code "Invalid Email"
    ws.send(Message::Text(encrypt("11".to_owned(), &remote_pub_key).unwrap().into())).await.unwrap();
    bail!("Invalid Email");
  }

  let user = app.users.find_one(doc! { "username": &username }).await.unwrap();
  if user.is_some(){
    // 1 - Error, 2 - Error Code "Username in Use"
    ws.send(Message::Text(encrypt("12".to_owned(), &remote_pub_key).unwrap().into())).await.unwrap();
    bail!("Username in Use");
  }

  let user = app.users.find_one(doc! { "email": &email }).await.unwrap();
  if user.is_some(){
    // 1 - Error, 3 - Error Code "Email in Use"
    ws.send(Message::Text(encrypt("13".to_owned(), &remote_pub_key).unwrap().into())).await.unwrap();
    bail!("Email in Use");
  }

  let ip_info = reqwest::get(format!("https://ipinfo.io/{}?token={}", ip, env::var("IPINFO_KEY").unwrap())).await.unwrap();
  let ip_info: IPInfo = serde_json::from_str(&ip_info.text().await.unwrap()).unwrap();

  let salt = SaltString::generate(&mut OsRng);

  let argon2 = Argon2::default();
  let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();

  let token: String = rand::thread_rng().sample_iter(&Alphanumeric).take(64).map(char::from).collect();
  let now = Utc::now().timestamp();

  let user = User {
    _id: ObjectId::new(),

    username,
    password: password_hash,

    last_username_change: 0,
    last_password_change: 0,
    last_email_change: 0,
    last_avatar_change: 0,

    password_change_token: None,
    password_change_token_generated: 0,

    login_attempts: 0,
    account_locked: false,
    locked_until: 0,

    email,
    email_verification_code: rand::thread_rng().sample_iter(&Alphanumeric).take(6).map(char::from).collect(),
    email_verified: false,
    email_update: UserEmailUpdate::default(),

    avatar: DEFAULT_AVIS.choose(&mut rand::thread_rng()).unwrap().to_string(),

    has_mfa: false,
    mfa_string: None,
    backup_codes: vec![],

    roles: vec![],

    allowed_apps: vec![],

    patreon_id: None,
    patreon_tiers: vec![],
    patreon_last_update: 0,
    patreon_refresh_token: None,

    deletion_flagged_after: None,
    apps_to_delete_data: vec![]
  };

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

  email::send(
    ( user.username.as_str(), user.email.as_str() ), 
    "Welcome to PhazeID",
    &fs::read_to_string("templates/email/signup_verification.html").unwrap()
      .replace("{{USERNAME}}", &user.username)
      .replace("{{CODE}}", &user.email_verification_code)
  ).await.unwrap();

  app.users.insert_one(&user).await.unwrap();
  app.sessions.insert_one(&session).await.unwrap();

  // 0 - No Error
  ws.send(Message::Text(encrypt(format!("0{}{}", token, session._id), &remote_pub_key).unwrap().into())).await.unwrap();
  Ok(user)
}