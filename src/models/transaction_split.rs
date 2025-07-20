use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize,ToSchema)]
pub struct Balance {
    pub user_id: String,
    pub owes_to: String,
    pub amount: f64,
}
