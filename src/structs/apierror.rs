use axum::{ body::Body, http::HeaderMap, response::{ IntoResponse, Response } };

use crate::util::cors::ALLOWED_ORIGINS;

pub struct APIError{
  code: u16,
  msg: String,
  origin: String
}

impl APIError{
  pub fn default( headers: &HeaderMap ) -> Self{
    let origin = headers.get("Origin");

    Self {
      code: 500,
      msg: "Internal Server Error".to_owned(),
      origin: if origin.is_none() {
        "https://phaz.uk".into()
      } else{
        origin.unwrap().to_str().unwrap().to_owned()
      }
    }
  }

  pub fn new( code: u16, msg: String, headers: &HeaderMap  ) -> Self{
    let origin = headers.get("Origin");

    Self {
      code,
      msg,
      origin: if origin.is_none() {
        "https://phaz.uk".into()
      } else{
        origin.unwrap().to_str().unwrap().to_owned()
      }
    }
  }
}

impl IntoResponse for APIError{
  fn into_response(self) -> Response {
    let origin = if ALLOWED_ORIGINS.contains(&self.origin.as_str()){
      self.origin.to_owned()
    } else{
      "".into()
    };

    Response::builder()
      .status(self.code)
      .header("access-control-allow-credentials", "true")
      .header("access-control-allow-origin", origin)
      .header("access-control-allow-methods", "GET,POST,PUT,DELETE,OPTIONS")
      .body(Body::from(self.msg))
      .unwrap()
  }
}