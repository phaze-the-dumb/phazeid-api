use std::{collections::HashMap, sync::Arc};

use axum::{ extract::Query, http::{ header, HeaderMap, StatusCode }, response::IntoResponse, Extension, Json };
use serde_json::json;
use bson::{doc, oid::ObjectId};

use crate::{ apphandler::AppHandler, structs::apierror::APIError, util::{ cookies, cors::cors, ip::get_ip_from_request, token } };

pub async fn get( 
  headers: HeaderMap,
  Query(query): Query<HashMap<String, String>>,
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

  let specific_session = query.get("session");
  if specific_session.is_some(){
    let specific_session = specific_session.unwrap();

    app.oauth_sessions.delete_one(doc! {
      "_id": ObjectId::parse_str(specific_session).unwrap(),
      "user_id": user._id // Include user ID to only let users delete their sessions.
    }).await.unwrap();

    Ok((
      StatusCode::OK,
      [
        ( header::ACCESS_CONTROL_ALLOW_ORIGIN, cors(&headers) ),
        ( header::ACCESS_CONTROL_ALLOW_METHODS, "GET".into() ),
        ( header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".into() )
      ],
      Json(json!({
        "endpoint": "/login"
      }))
    ))
  } else{
    Err(APIError::new(500, "Invalid Session".into()))
  }
}