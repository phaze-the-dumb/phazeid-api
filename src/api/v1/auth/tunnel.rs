use axum::{ extract::{ ws::{ Message, WebSocket }, WebSocketUpgrade }, http::HeaderMap, response::IntoResponse, Extension };
use base64::prelude::*;
use rsa::{ pkcs8::{DecodePublicKey, EncodePublicKey}, RsaPrivateKey, RsaPublicKey };
use serde_json::json;
use std::{ env, sync::Arc };

use crate::{ apphandler::AppHandler, structs::tunnel::{ ClientCommand, TurnstileRes }, util::{ change_password::{try_change_password, try_change_password_without_account, try_reset_password}, cookies, decrypt::decrypt, encrypt::encrypt, login::try_login, signup::try_signup } };

pub async fn get(
  headers: HeaderMap,
  Extension(app): Extension<Arc<AppHandler>>,
  ws: WebSocketUpgrade
) -> impl IntoResponse{
  ws.on_upgrade(| socket | handle_socket(socket, app, headers))
}

async fn handle_socket( mut ws: WebSocket, app: Arc<AppHandler>, headers: HeaderMap ){
  // if !headers.contains_key("cf-connecting-ip"){ return }

  let auth = ws.recv().await.unwrap().unwrap().into_text();
  if auth.is_err(){ return; }

  let auth = auth.unwrap();
  let auth = auth.as_str();
  
  let client = reqwest::Client::new();
  let dat = client.post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
    .body(serde_json::to_string(&json!({
      "secret": env::var("CF_TURNSTILE_SECRET").unwrap(),
      "response": auth
    })).unwrap())
    .header("Content-Type", "application/json")
    .send().await.unwrap().text().await.unwrap();

  let dat: TurnstileRes = serde_json::from_str(&dat).unwrap();
  if !dat.success { return; }

  let bits = 1028;

  let priv_key = RsaPrivateKey::new(&mut rand::thread_rng(), bits).expect("failed to generate a key");
  let pub_key = RsaPublicKey::from(&priv_key);

  let enc_data = BASE64_STANDARD.encode(RsaPublicKey::to_public_key_der(&pub_key).unwrap());
  ws.send(Message::text(enc_data)).await.unwrap();

  let auth = ws.recv().await.unwrap().unwrap().into_text();
  if auth.is_err(){ return; }

  let buf = BASE64_STANDARD.decode(auth.unwrap().as_str()).unwrap();
  let remote_pub_key = RsaPublicKey::from_public_key_der(&buf).unwrap();

  ws.send(Message::Text(encrypt("OK".to_owned(), &remote_pub_key).unwrap().into())).await.unwrap();

  let auth = ws.recv().await;
  if auth.is_none(){ return; }
  
  let auth = auth.unwrap();
  if auth.is_err(){ return; }
  
  let auth = auth.unwrap().into_text();
  if auth.is_err(){ return; }

  let auth = auth.unwrap();
  let auth = auth.as_str().split_at(2);

  let val = ClientCommand {
    cmd: auth.0.to_owned(),
    data: auth.1.to_owned()
  };

  match val.cmd.as_str(){
    "AL" => {
      let data = val.data.split_at(172);

      let username = decrypt(data.0.to_owned(), &priv_key).unwrap();
      let password = decrypt(data.1.to_owned(), &priv_key).unwrap();

      try_login(
        // headers.get("cf-connecting-ip").unwrap().to_str().unwrap(), 
        "1.1.1.1", // Will replace once in prod, just for testing.
        username, password, &remote_pub_key, &mut ws, app.clone()
      ).await.unwrap();
    },
    "AS" => {
      let data = val.data.split_at(172);
      let data1 = data.1.split_at(172);

      let username = decrypt(data.0.to_owned(), &priv_key).unwrap();
      let password = decrypt(data1.0.to_owned(), &priv_key).unwrap();
      let email = decrypt(data1.1.to_owned(), &priv_key).unwrap();

      try_signup(
        //headers.get("cf-connecting-ip").unwrap().to_str().unwrap(), 
        "1.1.1.1", // Will replace once in prod, just for testing.
        username, password, email, &remote_pub_key, &mut ws, app.clone()
      ).await.unwrap();
    },
    "EP" => {
      let cookies = headers.get("cookie");
      if cookies.is_none() { return; }
      
      let cookies = cookies.unwrap().to_str().unwrap().to_owned();
      let cookies = cookies::parse(cookies);

      if cookies.get("token").is_none(){ return; }

      let data = val.data.split_at(172);

      let new_password = decrypt(data.0.to_owned(), &priv_key).unwrap();
      let old_password = decrypt(data.1.to_owned(), &priv_key).unwrap();

      try_change_password(
        new_password, old_password, cookies.get("token").unwrap().clone(), 
        &remote_pub_key, &mut ws, app.clone()
      ).await.unwrap();
    },
    "RP" => {
      let email = decrypt(val.data.to_owned(), &priv_key).unwrap();
      
      try_reset_password(email, &remote_pub_key, &mut ws, app).await.unwrap();
    },
    "NP" => {
      let data = val.data.split_at(88);

      let token = data.0.to_owned();
      let password = decrypt(data.1.to_owned(), &priv_key).unwrap();

      try_change_password_without_account(
        password, token, &remote_pub_key,
        &mut ws, app.clone()
      ).await.unwrap();
    }
    _ => { return; }
  }
}