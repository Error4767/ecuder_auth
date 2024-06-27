use crate::raw_token::{ TokenPayload, generate_token };
use crate::error::AuthError;

use chrono::{Duration, Local};
use serde::{ Serialize, Deserialize };

use sha2::{Sha256, Digest};

#[derive(Serialize, Deserialize, Clone)]
struct UserInfo {
  id: String,
  username: String,
  #[serde(rename = "passwordHash")]
  password_hash: String,
  #[serde(rename = "passwordSalt")]
  password_salt: String,
  #[serde(rename = "userDirectory")]
  user_directory: String,
}
type UserInfoList = Vec<UserInfo>;

pub fn password_login(username: String, password: String)-> Result<String, Box<dyn std::error::Error>> {
  let user_list: UserInfoList  = serde_json::from_str(&std::fs::read_to_string("./accounts.json")?)?;
  // 如果找不到用户，就返回错误
  let index = user_list.iter().position(|user| user.username == username)
    .ok_or_else(|| AuthError::AccountNotExist)?;
  let user = &user_list[index];
  // 密码验证
  if user.password_hash != parse_to_password_hash(format!("{}{}", password, user.password_salt)) {
    return Err(Box::new(AuthError::WrongPassword));
  }
  // 生成 token
  let payload = TokenPayload {
    id: user.username.to_string(),
    username: user.username.to_string(),
    user_directory: user.user_directory.to_string(),
    exp: Local::now().checked_add_signed(Duration::days(7)).unwrap().timestamp() as usize,
  };
  Ok(generate_token(&payload)?)
}

// 转化密码hash
pub fn parse_to_password_hash(input: String)-> String {
  return format!("{:x}", &Sha256::digest(input));
}