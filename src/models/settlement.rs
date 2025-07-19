use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settlement {
    pub id: String,
    pub group_id: String,
    pub from_user_id: String,
    pub to_user_id: String,
    pub amount: f64,
    pub remarks: Option<String>,
    pub transaction_ids: Option<Vec<String>>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub is_confirmed: bool,
    pub confirmed_by: Option<String>,
}
