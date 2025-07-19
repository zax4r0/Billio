use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppLog {
    pub id: String,
    pub action: String,
    pub user_id: Option<String>,
    pub details: HashMap<String, serde_json::Value>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupAudit {
    pub id: String,
    pub group_id: String,
    pub action: String,
    pub user_id: Option<String>,
    pub details: HashMap<String, serde_json::Value>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
