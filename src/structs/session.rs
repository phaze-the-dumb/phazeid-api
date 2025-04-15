use bson::oid::ObjectId;
use serde::{ Deserialize, Serialize };

use super::ipinfo::IPInfo;

#[derive(Debug, Serialize, Deserialize)]
pub struct Session{
  pub _id: ObjectId,
  pub token: String,
  pub created_on: i64,
  pub expires_on: i64,
  pub loc: IPInfo,
  pub valid: bool,
  pub challenge_code: Option<String>,
  pub user_id: ObjectId
}