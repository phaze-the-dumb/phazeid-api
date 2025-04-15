use std::env;

use mail_send::{ mail_builder::MessageBuilder, SmtpClientBuilder };

pub async fn send( recipient: ( &str, &str ), subject: &str, html: &str ) -> anyhow::Result<()>{
  let message = MessageBuilder::new()
    .from(( "PhazeID", "no-reply@phazed.xyz" ))
    .to(vec![ recipient ])
    .subject(subject)
    .html_body(html);

  SmtpClientBuilder::new("mail.phazed.xyz", 465)
    .credentials(( "no-reply@phazed.xyz", env::var("EMAIL_KEY")?.as_str() ))
    .connect()
    .await?
    .send(message).await?;

  Ok(())
}