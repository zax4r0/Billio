use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct TransactionSplit {
    pub user_id: Uuid,
    pub share: f64,
}
