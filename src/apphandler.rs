use std::{env, sync::Arc};

use mongodb::{options::ClientOptions, Client, Collection};
use s3::{ creds::Credentials, Bucket, Region };

use crate::structs::{session::Session, user::User};

#[derive(Debug)]
pub struct AppHandler{
  pub users: Collection<User>,
  pub sessions: Collection<Session>,

  r2: R2
}

impl AppHandler{
  pub async fn new() -> anyhow::Result<Arc<Self>>{
    let db_opts = ClientOptions::parse(env::var("MONGODB_URI")?).await?;
    let client = Client::with_options(db_opts)?;

    let db = client.database("PhazeID");

    Ok(Arc::new(Self {
      users: db.collection("Users"),
      sessions: db.collection("Sessions"),

      r2: R2::new().unwrap()
    }))
  }

  pub fn r2( &self ) -> &R2 { &self.r2 }
}

// Define R2 API stuffs
#[derive(Debug)]
pub struct R2{
  bucket: Box<Bucket>
}

impl R2{
  pub fn new() -> anyhow::Result<Self>{
    let bucket = Bucket::new(
      "phazecdn",
      Region::R2 { account_id: env::var("CF_ACCOUNT_ID").unwrap() },
      Credentials::from_env().unwrap()
    )?.with_path_style();

    Ok(Self {
      bucket
    })
  }

  pub async fn upload_file( &self, key: String, dat: &[u8], content_type: &str ) -> anyhow::Result<()> {
    self.bucket.put_object_with_content_type(key.as_str(), dat, content_type).await?;
    Ok(())
  }

  pub async fn delete_file( &self, key: String ) -> anyhow::Result<()> {
    self.bucket.delete_object(key.as_str()).await?;
    Ok(())
  }
}