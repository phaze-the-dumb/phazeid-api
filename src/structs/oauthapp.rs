use bson::oid::ObjectId;
use serde::{ Deserialize, Serialize };

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OAuthApplication{
  pub _id: ObjectId,

  pub name: String,
  pub allow_skip: bool,

  pub key: String,
  pub redirect_uris: Vec<String>,

  pub owner_id: ObjectId
}