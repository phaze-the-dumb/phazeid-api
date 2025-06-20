use base64::prelude::*;
use rsa::{Oaep, RsaPrivateKey};
use sha2::Sha256;

pub fn decrypt( dat: String, key: &RsaPrivateKey ) -> anyhow::Result<String>{
  let bytes = BASE64_STANDARD.decode(dat)?;
  let val = key.decrypt(Oaep::new::<Sha256>(), bytes.as_slice())?;

  Ok(String::from_utf8(val)?)
}