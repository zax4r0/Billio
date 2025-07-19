use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Balance {
    pub user_id: String,
    pub owes_to: String,
    pub amount: f64,
}
