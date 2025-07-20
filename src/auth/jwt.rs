use crate::core::errors::BillioError;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,  // User ID
    pub role: String, // Role (e.g., "USER" or "ADMIN")
    pub exp: usize,   // Expiration timestamp
}

pub struct JwtService {
    secret: String,
}

impl JwtService {
    pub fn new(secret: String) -> Self {
        JwtService { secret }
    }

    pub fn generate_token(&self, user_id: &str, role: &str) -> Result<String, BillioError> {
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as usize + 3600) // 1 hour expiry
            .map_err(|e| BillioError::InternalServerError(format!("Time error: {}", e)))?;

        let claims = Claims {
            sub: user_id.to_string(),
            role: role.to_string(),
            exp: expiration,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|e| BillioError::InternalServerError(format!("JWT encoding error: {}", e)))
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, BillioError> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|e| BillioError::UnauthorizedSettlementConfirmation(format!("Invalid token: {}", e)))?;

        Ok(token_data.claims)
    }
}
