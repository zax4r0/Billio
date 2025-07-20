use crate::core::errors::BillioError;
use crate::core::models::{
    audit::GroupAudit, group::Group, settlement::Settlement, transaction::Transaction, user::User,
};
use async_trait::async_trait;

#[async_trait]
pub trait Storage: Send + Sync {
    async fn create_user_if_not_exists(&self, user: User) -> Result<User, BillioError>;
    async fn get_user(&self, user_id: &str) -> Result<Option<User>, BillioError>;
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, BillioError>;
    async fn save_group(&self, group: Group) -> Result<(), BillioError>;
    async fn get_group(&self, group_id: &str) -> Result<Option<Group>, BillioError>;
    async fn get_group_by_join_link(&self, join_link: &str) -> Result<Option<Group>, BillioError>;
    async fn revoke_join_link(&self, join_link: &str) -> Result<(), BillioError>;
    async fn delete_group(&self, group_id: &str) -> Result<(), BillioError>;
    async fn save_transaction(&self, transaction: Transaction) -> Result<(), BillioError>;
    async fn get_transaction(&self, transaction_id: &str) -> Result<Option<Transaction>, BillioError>;
    async fn get_effective_transactions(&self, group_id: &str) -> Result<Vec<Transaction>, BillioError>;
    async fn save_settlement(&self, settlement: Settlement) -> Result<(), BillioError>;
    async fn get_settlement(&self, settlement_id: &str) -> Result<Option<Settlement>, BillioError>;
    async fn get_settlements(&self, group_id: &str) -> Result<Vec<Settlement>, BillioError>;
    async fn get_pending_settlements(&self, group_id: &str) -> Result<Vec<Settlement>, BillioError>;
    async fn get_user_groups(&self, user_id: &str) -> Result<Vec<Group>, BillioError>;
    async fn is_group_member(&self, group_id: &str, user_id: &str) -> Result<bool, BillioError>;
    async fn save_group_audit(&self, audit: GroupAudit) -> Result<(), BillioError>;
    async fn get_group_audits(&self, group_id: &str) -> Result<Vec<GroupAudit>, BillioError>;
}

pub mod in_memory;
