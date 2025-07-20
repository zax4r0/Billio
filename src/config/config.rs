use dotenv::dotenv;
use once_cell::sync::Lazy;
use std::env;

pub struct Config {
    pub port: u16,
    pub database_url: String,
    pub log_level: String,
    pub jwt_secret: String, // Added for JWT
}

impl core::fmt::Debug for Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config")
            .field("port", &self.port)
            .field("database_url", &"<redacted>")
            .field("log_level", &self.log_level)
            .field("jwt_secret", &"<redacted>")
            .finish()
    }
}

impl Config {
    fn from_env() -> Self {
        dotenv().ok();

        Self {
            port: env::var("PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(3000),
            database_url: env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite::memory:".to_string()),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            jwt_secret: env::var("JWT_SECRET").unwrap_or_else(|_| "secret".to_string()), // Use a secure secret in production
        }
    }
}

pub static CONFIG: Lazy<Config> = Lazy::new(Config::from_env);
