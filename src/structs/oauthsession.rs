use bson::oid::ObjectId;
use serde::{ Deserialize, Serialize };

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OAuthSession{
  pub _id: ObjectId,

  pub token: String,

  pub created_on: i64,
  pub expires_on: i64,

  pub app_id: ObjectId,
  pub app_name: String,

  pub user_id: ObjectId,
  pub scopes: Vec<String>
}