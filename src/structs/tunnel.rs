use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct TurnstileRes{
  pub success: bool,

  #[serde(rename = "error-codes")]
  pub error_codes: Vec<String>
}

#[derive(Debug)]
pub struct ClientCommand{
  pub cmd: String,
  pub data: String
}