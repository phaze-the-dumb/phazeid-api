use bson::oid::ObjectId;
use serde::{ Deserialize, Serialize };

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct UserEmailUpdate{
  pub email: String,
  pub verification_code: String
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User{
  pub _id: ObjectId,

  pub username: String,
  pub password: String,

  pub last_username_change: i64,
  pub last_password_change: i64,
  pub last_email_change: i64,
  pub last_avatar_change: i64,

  pub password_change_token: Option<String>,

  pub login_attempts: u32,
  pub account_locked: bool,
  pub locked_until: i64,

  pub email: String,
  pub email_verification_code: String,
  pub email_verified: bool,
  pub email_update: UserEmailUpdate,

  pub avatar: String,

  pub has_mfa: bool,
  pub mfa_string: Option<String>,

  pub roles: Vec<String>,
  pub allowed_apps: Vec<String>,

  pub patreon_id: Option<String>,
  pub patreon_tiers: Vec<String>,
  pub patreon_last_update: u64,
  pub patreon_refresh_token: Option<String>
}