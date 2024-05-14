use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
  #[error("account does not exist")]
  AccountNotExist,
  #[error("wrong password")]
  WrongPassword,
  #[error("Missing parameter token")]
  MissingToken,
}