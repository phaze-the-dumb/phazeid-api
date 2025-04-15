use std::{env, sync::Arc};

use mongodb::{options::ClientOptions, Client, Collection};

use crate::structs::{session::Session, user::User};

#[derive(Debug)]
pub struct AppHandler{
  pub users: Collection<User>,
  pub sessions: Collection<Session>,
}

impl AppHandler{
  pub async fn new() -> anyhow::Result<Arc<Self>>{
    let db_opts = ClientOptions::parse(env::var("MONGODB_URI")?).await?;
    let client = Client::with_options(db_opts)?;

    let db = client.database("PhazeID");

    Ok(Arc::new(Self {
      users: db.collection("Users"),
      sessions: db.collection("Sessions"),
    }))
  }
}