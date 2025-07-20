use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct AppLog {
    pub id: String,
    pub action: String,
    pub user_id: Option<String>,
    pub details: HashMap<String, serde_json::Value>,
    #[serde(with = "chrono::serde::ts_seconds")]
    #[schema(value_type = String, example = "2024-06-01T12:34:56Z")]
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct GroupAudit {
    pub id: String,
    pub group_id: String,
    pub action: String,
    pub user_id: Option<String>,
    pub details: HashMap<String, serde_json::Value>,
    #[serde(with = "chrono::serde::ts_seconds")]
    #[schema(value_type = String, example = "2024-06-01T12:34:56Z")]
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
