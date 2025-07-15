use std::env;

use axum::{ extract::Query, response::{ IntoResponse, Redirect } };

#[derive(serde::Deserialize)]
pub struct PatreonLinkQuery{
  state: String
}

pub async fn get(
  Query(query): Query<PatreonLinkQuery>
) -> impl IntoResponse{
  Redirect::to(&format!("https://www.patreon.com/oauth2/authorize?response_type=code&client_id={}&scope=identity&redirect_uri=https://id.phazed.xyz/account/patreon&state={}", env::var("PATREON_CLIENT_ID").unwrap(), query.state))
}