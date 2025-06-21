use std::{env, sync::Arc};

use axum::{ http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use bson::doc;
use chrono::Utc;
use serde_json::{json, Value};

use crate::{ apphandler::AppHandler, structs::{apierror::APIError, patreon::PatreonTokenRes}, util::{ cookies, cors::cors, encrypt::{decrypt_from_user, encrypt_to_user}, ip::get_ip_from_request, token } };

pub async fn get( 
  headers: HeaderMap,
  Extension(app): Extension<Arc<AppHandler>>
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

  let now = Utc::now().timestamp();
  if user.patreon_id.is_none() || user.patreon_last_update + 3600 > now { return Err(APIError::new(429, "You can only refresh once an hour.".into())) }

  let client = reqwest::Client::new();
  let access_token;

  let mut refresh_token_update = None;
  let mut token_update = None;
  let mut expires_update = None;

  if user.patreon_token_expires < now{
    let refresh_token = decrypt_from_user(&user, user.clone().patreon_refresh_token.unwrap());

    let res = client.post("https://www.patreon.com/api/oauth2/token")
      .body(format!("refresh_token={}&grant_type=refresh_token&client_id={}&client_secret={}&redirect_uri=http://localhost:5173/account/patreon", refresh_token, env::var("PATREON_CLIENT_ID").unwrap(), env::var("PATREON_CLIENT_SECRET").unwrap()))
      .header("Content-Type", "application/x-www-form-urlencoded")
      .send().await.unwrap();

    if res.status() != 200 { return Err(APIError::new(500, format!("Invalid Patreon Code. Patreon Error: {}", res.status()))) }
    let dat = res.text().await.unwrap();

    let dat: PatreonTokenRes = serde_json::from_str(&dat).unwrap();
    access_token = dat.access_token.clone();

    refresh_token_update = Some(encrypt_to_user(&user, dat.refresh_token));
    token_update = Some(encrypt_to_user(&user, dat.access_token));
    expires_update = Some(now + dat.expires_in as i64);
  } else{
    access_token = decrypt_from_user(&user, user.clone().patreon_token.unwrap());
  }

  let user_res = client.get("https://www.patreon.com/api/oauth2/v2/identity?fields%5Btier%5D=title,amount_cents&fields%5Bmember%5D=patron_status,is_follower,full_name&include=memberships.currently_entitled_tiers")
    .header("Authorization", format!("Bearer {}", access_token))
    .send().await.unwrap();

  if user_res.status() != 200 { return Err(APIError::new(500, format!("Invalid Patreon Code (2). Patreon Error: {}", user_res.status()))) }

  let user_dat = user_res.text().await.unwrap();
  let user_dat: Value = serde_json::from_str(&user_dat).unwrap();

  let included = user_dat["included"].as_array().unwrap();

  let mut patreon_tiers = vec![];

  let membership_ids = user_dat["data"]["relationships"]["memberships"]["data"].as_array().unwrap();
  for membership_id in membership_ids{
    let id = membership_id["id"].as_str().unwrap();
    let member = included.iter().find(| x | x["id"].as_str().unwrap() == id).unwrap();

    let id = member["relationships"]["currently_entitled_tiers"]["data"].as_array().unwrap()[0]["id"].as_str().unwrap();
    if id == env::var("PATREON_TIER_ID").unwrap() { patreon_tiers.push("PATREON"); }
    else if id == env::var("PATREON_VIP_TIER_ID").unwrap() { patreon_tiers.push("VIP_PATREON"); }
  }

  app.users.update_one(doc! { "_id": user._id }, doc! {
    "$set": {
      "patreon_id": user_dat["data"]["id"].as_str().unwrap(),
      "patreon_tiers": patreon_tiers.clone(),
      "patreon_last_update": now,
      "patreon_refresh_token": if refresh_token_update.is_some() { refresh_token_update.unwrap() } else { user.clone().patreon_refresh_token.unwrap() },
      "patreon_token": if token_update.is_some() { token_update.unwrap() } else { user.clone().patreon_token.unwrap() },
      "patreon_token_expires": if expires_update.is_some() { expires_update.unwrap() } else { user.clone().patreon_token_expires }
    }
  }).await.unwrap();

  Ok((
    StatusCode::OK,
    [
      ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
      ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
      ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
    ],
    Json(json!({
      "patreon_tiers": patreon_tiers
    }))
  ))
}