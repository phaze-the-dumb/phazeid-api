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

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicSession{
  pub _id: String,
  pub created_on: i64,
  pub expires_on: i64,
  pub loc: IPInfo,
  pub is_this: bool
}

impl PublicSession{
  pub fn from_session( session: Session, is_this: bool ) -> Self{
    PublicSession {
      _id: session._id.to_hex(),
      created_on: session.created_on,
      expires_on: session.expires_on,
      loc: session.loc,
      is_this
    }
  } 
}