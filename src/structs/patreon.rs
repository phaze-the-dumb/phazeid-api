use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct PatreonTokenRes{
  pub token_type: String,
  pub access_token: String,
  pub expires_in: i32,
  pub refresh_token: String
}