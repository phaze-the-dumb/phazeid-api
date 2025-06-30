use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct IPInfo{
  pub ip: String,
  pub hostname: Option<String>,
  pub city: String,
  pub region: String,
  pub country: String,
  pub loc: String,
  pub org: String,
  pub postal: String,
  pub timezone: String
}