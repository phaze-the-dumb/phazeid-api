use core::str;
use std::env;

use aes_gcm::{ aead::Aead, AeadCore, Aes256Gcm, Key, KeyInit };
use base64::prelude::*;
use rand::rngs::OsRng;
use rsa::{ Oaep, RsaPublicKey };
use sha2::{ digest::{ consts::U12, typenum::ToInt }, Sha256 };

use crate::structs::user::User;

pub fn encrypt( dat: String, key: &RsaPublicKey ) -> anyhow::Result<String>{
  let val = key.encrypt(&mut rand::thread_rng(), Oaep::new::<Sha256>(), dat.as_bytes())?;

  Ok(BASE64_STANDARD.encode(val))
}

pub fn get_user_encryption_key( user: &User ) -> [u8; 32]{
  let salt = env::var("ROOT_KEY_SALT").unwrap();
  let salt = salt.as_bytes();

  //                                                                 v KEEP THIS THE SAME!!!
  let key: [u8; 32] = blake3::Hasher::new_derive_key("id.phazed.xyz 1748375760977 user-key")
    .update(env::var("ROOT_KEY").unwrap().as_bytes())
    .update(&user._id.bytes())
    .update(salt)
    .finalize()
    .into();

  return key;
}

pub fn encrypt_to_user( user: &User, dat: String ) -> String {
  let key = get_user_encryption_key(user);
  let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

  let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

  let ciphertext = cipher.encrypt(&nonce, dat.as_bytes().as_ref()).unwrap();
  BASE64_STANDARD.encode([ nonce.as_slice(), ciphertext.as_slice() ].concat())
}

pub fn decrypt_from_user( user: &User, dat: String ) -> String {
  let key = get_user_encryption_key(user);
  let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

  let raw = BASE64_STANDARD.decode(dat).unwrap();
  let ( nonce, ciphertext ) = raw.split_at(U12::to_int()); // Length of nonce (96-bit / 12-byte)

  let plaintext = cipher.decrypt(nonce.into(), ciphertext.as_ref()).unwrap();
  str::from_utf8(plaintext.as_slice()).unwrap().to_owned()
}