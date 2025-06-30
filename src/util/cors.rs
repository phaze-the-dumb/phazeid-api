use axum::{ http::{ header, HeaderMap, StatusCode }, response::IntoResponse };

const ALLOWED_ORIGINS: [ &'static str; 2 ] = [ "https://id.phaz.uk", "https://id.phazed.xyz" ];

pub const ORIGIN: &'static str = "https://id.phaz.uk";

pub async fn options( headers: HeaderMap ) -> impl IntoResponse{
  let origin = headers.get("Origin").unwrap().to_str().unwrap();
  let method = headers.get("Access-Control-Request-Method").unwrap().to_str().unwrap();

  if ALLOWED_ORIGINS.contains(&origin){
    (
      StatusCode::OK,
      [
        ( header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.to_owned() ),
        ( header::ACCESS_CONTROL_ALLOW_METHODS, method.into() ),
        ( header::ACCESS_CONTROL_ALLOW_HEADERS, "content-type".into() ),
        ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
      ],
      "200 OK"
    )
  } else{
    (
      StatusCode::INTERNAL_SERVER_ERROR,
      [
        ( header::ACCESS_CONTROL_ALLOW_ORIGIN, "https://phaz.uk".into() ),
        ( header::ACCESS_CONTROL_ALLOW_METHODS, "*".into() ),
        ( header::ACCESS_CONTROL_ALLOW_HEADERS, "*".into() ),
        ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "false".into() )
      ],
      "500 Internal Server Error"
    )
  }
}

pub fn cors( headers: &HeaderMap ) -> String{
  let origin = headers.get("Origin");
  if origin.is_none() { return "".into() }

  let origin = origin.unwrap().to_str().unwrap();

  if ALLOWED_ORIGINS.contains(&origin){
    origin.to_owned() 
  } else{
    "".into()
  }
}