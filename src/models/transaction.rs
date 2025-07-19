use super::transaction_split::TransactionSplit;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub enum SplitType {
    Equal,
    Custom,
}

#[derive(Clone, Debug)]
pub struct Transaction {
    pub id: Uuid,
    pub group_id: Uuid,
    pub payer_id: Uuid,
    pub added_by: Uuid,
    pub amount: f64,
    pub description: String,
    pub splits: Vec<TransactionSplit>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}
