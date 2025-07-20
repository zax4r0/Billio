use crate::core::errors::BillioError;
use crate::core::models::audit::AppLog;
use crate::infrastructure::logging::LoggingService;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone)]
pub struct InMemoryLogging {
    logs: Arc<RwLock<Vec<AppLog>>>,
}

impl InMemoryLogging {
    pub fn new() -> Self {
        InMemoryLogging {
            logs: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

#[async_trait]
impl LoggingService for InMemoryLogging {
    async fn log_action(
        &self,
        action: &str,
        details: serde_json::Value,
        user_id: Option<&str>,
    ) -> Result<(), BillioError> {
        let mut logs = self.logs.write().await;
        logs.push(AppLog {
            id: Uuid::new_v4().to_string(),
            action: action.to_string(),
            user_id: user_id.map(String::from),
            details: serde_json::from_value(details)
                .map_err(|e| BillioError::LoggingError(format!("Failed to serialize log details: {}", e)))?,
            timestamp: chrono::Utc::now(),
        });
        Ok(())
    }

    async fn get_logs(&self) -> Result<Vec<AppLog>, BillioError> {
        let logs = self.logs.read().await;
        Ok(logs.clone())
    }
}
