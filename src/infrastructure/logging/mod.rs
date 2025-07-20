pub mod in_memory;

use crate::core::errors::BillioError;
use crate::core::models::audit::AppLog;
use async_trait::async_trait;

#[async_trait]
pub trait LoggingService: Send + Sync {
    async fn log_action(
        &self,
        action: &str,
        details: serde_json::Value,
        user_id: Option<&str>,
    ) -> Result<(), BillioError>;
    async fn get_logs(&self) -> Result<Vec<AppLog>, BillioError>;
}
