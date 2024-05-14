mod raw_token;
mod error;

mod raw_login;

use raw_token::verify_token;
use raw_login::password_login;
use error::AuthError;

use axum::{
  routing::{ get, post },
  Json, 
  Router,
  http::{StatusCode, header::HeaderMap},
};

use serde::{ Serialize, Deserialize };

#[tokio::main]
async fn main() {
  let app = Router::new()
    .route("/public_key", get(public_key))
    .route("/login", post(login))
    .route("/verify_token", post(verify_login_state));
  let listener = tokio::net::TcpListener::bind("0.0.0.0:2086").await.unwrap();
  axum::serve(listener, app).await.unwrap();
}

async fn public_key() -> String {
  raw_token::PUBLIC_KEY.to_string()
}

#[derive(Serialize, Deserialize)]
struct LoginParams {
  username: String,
  password: String,
}

async fn login(
  Json(payload): Json<LoginParams>
) -> (StatusCode, String) {
  match password_login(payload.username, payload.password) {
    Ok(token)=> (StatusCode::OK, token),
    Err(err)=> (StatusCode::FORBIDDEN, err.to_string()),
  }
}

async fn verify_login_state(
  headers: HeaderMap,
) -> (StatusCode, String) {
  let token = match headers.get("token") {
    Some(token)=> token,
    None=> {
      return (StatusCode::FORBIDDEN, AuthError::MissingToken.to_string());
    },
  };
  match verify_token(token.to_str().unwrap_or_default().to_string()) {
    Ok(_)=> (StatusCode::OK, "".to_string()),
    Err(err)=> (StatusCode::FORBIDDEN, err.to_string()),
  }
}