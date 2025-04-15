use base64::prelude::*;
use rsa::{ Oaep, RsaPublicKey };
use sha2::Sha256;

pub fn encrypt( dat: String, key: &RsaPublicKey ) -> anyhow::Result<String>{
  let val = key.encrypt(&mut rand::thread_rng(), Oaep::new::<Sha256>(), dat.as_bytes())?;

  Ok(BASE64_STANDARD.encode(val))
}