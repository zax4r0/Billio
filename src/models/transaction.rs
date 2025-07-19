use super::user::User;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub group_id: String,
    pub description: String,
    pub amount: f64,
    pub paid_by: User,
    pub splits: HashMap<String, f64>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub is_reversed: bool,
    pub reverses: Option<String>,
    pub reversed_by: Option<String>,
}
