use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::env;

pub static SECRET: Lazy<String> =
    Lazy::new(|| env::var("RUSTDESK_API_JWT_KEY").unwrap_or_default());

/// JWT payload claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub user_id: u32,
    pub exp: usize,
}

/// 生成 JWT token，`exp_secs` 为有效期（秒）
pub fn generate_token(user_id: u32, exp_secs: i64) -> Result<String, String> {
    if SECRET.is_empty() {
        return Err("JWT secret is not configured (set RUSTDESK_API_JWT_KEY)".into());
    }

    let claims = Claims {
        user_id,
        exp: (chrono::Utc::now() + chrono::Duration::seconds(exp_secs)).timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET.as_bytes()),
    )
    .map_err(|e| e.to_string())
}

/// 验证 JWT token，过期校验由 jsonwebtoken 库自动完成
pub fn verify_token(token: &str) -> Result<Claims, String> {
    if SECRET.is_empty() {
        return Err("JWT secret is not configured (set RUSTDESK_API_JWT_KEY)".into());
    }

    // Validation::new(HS256) 默认启用 validate_exp，无需手动检查过期
    let validation = Validation::new(Algorithm::HS256);

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(SECRET.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| format!("Token verification failed: {e}"))
}
