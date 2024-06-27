use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use sha2::{ Sha256, Digest };

fn main() {
  let rand_string: String = thread_rng()
    .sample_iter(&Alphanumeric)
    .take(32)
    .map(char::from)
    .collect();
  println!("input password:");
  let mut input_content = String::new();
  // 输入
  std::io::stdin().read_line(&mut input_content).unwrap();
  // 去除空白
  input_content = input_content.trim().to_string();
  println!("password: {}", input_content);
  println!("salt: {}", rand_string);
  println!("password hash: {}", format!("{:x}", Sha256::digest(&input_content)));
  println!("password salt hash: {}", format!("{:x}", Sha256::digest(format!("{}{}", input_content, rand_string))));
}