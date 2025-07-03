use bson::oid::ObjectId;
use serde::{ Deserialize, Serialize };

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OAuthCode{
  pub _id: ObjectId,
  pub token: String,

  pub app: ObjectId,
  pub redirect_uri: String,

  pub created_on: i64,
  pub expires_on: i64,

  pub refresh: bool,

  pub user_id: ObjectId,
  pub scopes: Vec<String>
}