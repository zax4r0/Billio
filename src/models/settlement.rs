use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct Settlement {
    pub id: String,
    pub group_id: String,
    pub from_user_id: String,
    pub to_user_id: String,
    pub amount: f64,
    pub remarks: Option<String>,
    pub transaction_ids: Option<Vec<String>>,
    #[serde(with = "chrono::serde::ts_seconds")]
    #[schema(value_type = String, example = "2024-06-01T12:34:56Z")]
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub is_confirmed: bool,
    pub confirmed_by: Option<String>,
}
