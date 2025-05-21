use core::str;

use axum::extract::multipart::Field;
use bson::oid::ObjectId;
use anyhow::bail;
use rand::{distributions::Alphanumeric, Rng};

use crate::apphandler::R2;

pub async fn upload<'a>( user_id: ObjectId, current_avatar: String, image: Field<'a>, r2: &R2 ) -> anyhow::Result<String>{
  let buff = image.bytes().await?;

  if buff[0] != 0x89
    || buff[1] != 0x50
    || buff[2] != 0x4E
    || buff[3] != 0x47
    || buff[4] != 0x0D
    || buff[5] != 0x0A
    || buff[6] != 0x1A
    || buff[7] != 0x0A
  { bail!("Image is not a PNG file"); } // Check it's a PNG file

  let chunk_type = str::from_utf8(&buff[12..16])?;
  if chunk_type != "IHDR" { bail!("Image is not a PNG file") } // The first chunk of any PNG file should always be IHDR

  let width = u32::from_le_bytes([buff[19], buff[18], buff[17], buff[16]]);
  let height = u32::from_le_bytes([buff[23], buff[22], buff[21], buff[20]]);

  if
    width != 300 ||
    height != 300 { bail!("Image is not correct dimensions") }

  r2.delete_file(format!("/id/avatars/{}/{}.png", user_id, current_avatar)).await?;

  let avatar_id: String = rand::thread_rng().sample_iter(&Alphanumeric).take(16).map(char::from).collect();
  r2.upload_file(format!("/id/avatars/{}/{}.png", user_id, avatar_id), &buff, "image/png").await.unwrap();

  Ok(avatar_id)
}