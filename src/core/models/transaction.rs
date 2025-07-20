use super::user::User;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct Transaction {
    pub id: String,
    pub group_id: String,
    pub description: String,
    pub amount: f64,
    pub paid_by: User,
    pub shares: HashMap<String, f64>,
    #[serde(with = "chrono::serde::ts_seconds")]
    #[schema(value_type = String, example = "2024-06-01T12:34:56Z")]
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub is_reversed: bool,
    pub reverses: Option<String>,
    pub reversed_by: Option<String>,
}
