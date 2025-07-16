use std::env;

use mail_send::{ mail_builder::MessageBuilder, SmtpClientBuilder };

pub async fn send( recipient: ( &str, &str ), subject: &str, html: &str ) -> anyhow::Result<()>{
  let message = MessageBuilder::new()
    .from(( "PhazeID", "no-reply@phaz.uk" ))
    .to(vec![ recipient ])
    .subject(subject)
    .html_body(html);

  SmtpClientBuilder::new("smtp.porkbun.com", 587)
    .implicit_tls(false)
    .credentials(( "no-reply@phaz.uk", env::var("EMAIL_KEY")?.as_str() ))
    .connect()
    .await?
    .send(message).await?;

  Ok(())
}