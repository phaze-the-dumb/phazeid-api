use axum::http::HeaderMap;
use anyhow::{ Result, bail };

pub fn get_ip_from_request( headers: &HeaderMap ) -> Result<String> {
  if !headers.contains_key("cf-connecting-ip"){ bail!("No IP") }
  Ok(headers.get("cf-connecting-ip").unwrap().to_str().unwrap().to_owned())
}