use std::sync::Arc;

use axum::{ extract::Query, http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use bson::{doc, oid::ObjectId};
use serde_json::json;

use crate::{ apphandler::AppHandler, structs::apierror::APIError, util::{ cookies, cors::cors, ip::get_ip_from_request, token } };

#[derive(serde::Deserialize, Debug)]
pub struct OAuthApplicationRequestQuery{
  pub client_id: String,
  pub redirect_uri: String
}

pub async fn get( 
  headers: HeaderMap,
  Query(query): Query<OAuthApplicationRequestQuery>,
  Extension(app): Extension<Arc<AppHandler>>
) -> impl IntoResponse{
  let cookies = headers.get("cookie");
  if cookies.is_none() { return Err(APIError::default()) }
  
  let cookies = cookies.unwrap().to_str().unwrap().to_owned();
  let cookies = cookies::parse(cookies);

  let token = cookies.get("token").unwrap().clone();

  let identity = token::identify(token, app.clone(), get_ip_from_request(&headers).unwrap()).await;
  if identity.is_err() { return Err(APIError::new(500, identity.unwrap_err().to_string())) }

  let ( user, session ) = identity.unwrap();
  let verified = token::verified(&user, &session);

  if verified.is_err() {
    return Ok((
      StatusCode::OK,
      [
        ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
        ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
        ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
      ],
      Json(verified.unwrap_err())
    ))
  }

  let oauth_app = app.oauth_apps.find_one(doc! { "_id": ObjectId::parse_str(query.client_id).unwrap() }).await.unwrap();
  if oauth_app.is_none(){
    return Ok((
      StatusCode::OK,
      [
        ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
        ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
        ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
      ],
      Json(json!({
        "name": "Invalid App",

        "valid": false,
        "error": "App doesn't exist"
      }))
    ))
  }

  let oauth_app = oauth_app.unwrap();

  if oauth_app.redirect_uris.contains(&query.redirect_uri){
    Ok((
      StatusCode::OK,
      [
        ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
        ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
        ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
      ],
      Json(json!({
        "name": oauth_app.name,
        "allow_skip": oauth_app.allow_skip,

        "valid": true,
        "error": "None"
      }))
    ))
  } else{
    Ok((
      StatusCode::OK,
      [
        ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
        ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
        ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
      ],
      Json(json!({ 
        
        "name": "Invalid App",

        "valid": false,
        "error": "Invalid redirect URL for application"
      }))
    ))
  }
}