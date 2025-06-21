use std::env;

use axum::{ response::{ IntoResponse, Redirect } };

pub async fn get() -> impl IntoResponse{
  Redirect::to(&format!("https://www.patreon.com/oauth2/authorize?response_type=code&client_id={}&scope=identity&redirect_uri=http://localhost:5173/account/patreon", env::var("PATREON_CLIENT_ID").unwrap()))
}