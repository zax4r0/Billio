use dotenv::dotenv;
use once_cell::sync::Lazy;
use std::env;

#[derive(Debug)]
pub struct Config {
    pub port: u16,
    pub database_url: String,
    pub log_level: String,
}

impl Config {
    fn from_env() -> Self {
        dotenv().ok();

        Self {
            port: env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3000),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite::memory:".to_string()),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
        }
    }
}

// Global static accessible everywhere
pub static CONFIG: Lazy<Config> = Lazy::new(Config::from_env);
