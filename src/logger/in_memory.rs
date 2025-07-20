use crate::error::BillioError;
use crate::logger::LoggingService;
use crate::models::audit::AppLog;
use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

pub struct InMemoryLogging {
    logs: tokio::sync::Mutex<Vec<AppLog>>,
}

impl InMemoryLogging {
    pub fn new() -> Self {
        InMemoryLogging {
            logs: tokio::sync::Mutex::new(Vec::new()),
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
        // For production: Use a logging queue or batch writes
        let mut logs = self.logs.lock().await;
        logs.push(AppLog {
            id: Uuid::new_v4().to_string(),
            action: action.to_string(),
            user_id: user_id.map(String::from),
            details: serde_json::from_value(details).unwrap_or_default(),
            timestamp: Utc::now(),
        });
        Ok(())
    }

    async fn get_logs(&self) -> Result<Vec<AppLog>, BillioError> {
        Ok(self.logs.lock().await.clone())
    }
}
