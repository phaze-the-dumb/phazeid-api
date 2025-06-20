use axum::{ body::Body, response::{ IntoResponse, Response } };

use crate::util::cors;

pub struct APIError{
  code: u16,
  msg: String
}

impl APIError{
  pub fn default() -> Self{
    Self {
      code: 500,
      msg: "Internal Server Error".to_owned()
    }
  }

  pub fn new( code: u16, msg: String ) -> Self{
    Self {
      code,
      msg
    }
  }
}

impl IntoResponse for APIError{
  fn into_response(self) -> Response {
    Response::builder()
      .status(self.code)
      .header("access-control-allow-credentials", "true")
      .header("access-control-allow-origin", cors::ORIGIN)
      .header("access-control-allow-methods", "GET,POST,PUT,DELETE,OPTIONS")
      .body(Body::from(self.msg))
      .unwrap()
  }
}