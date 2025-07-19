pub mod in_memory;

use crate::error::SplitwiseError;
use crate::models::{
    audit::{AppLog, GroupAudit},
    group::Group,
    settlement::Settlement,
    transaction::Transaction,
    user::User,
};
use async_trait::async_trait;

#[async_trait]
pub trait Storage: Send + Sync {
    async fn create_user_if_not_exists(&self, user: User) -> Result<User, SplitwiseError>;
    async fn get_user(&self, id: &str) -> Result<Option<User>, SplitwiseError>;
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, SplitwiseError>;
    async fn save_group(&self, group: Group) -> Result<(), SplitwiseError>;
    async fn get_group(&self, id: &str) -> Result<Option<Group>, SplitwiseError>;
    async fn get_group_by_join_link(&self, link: &str) -> Result<Option<Group>, SplitwiseError>;
    async fn revoke_join_link(&self, link: &str) -> Result<(), SplitwiseError>;
    async fn save_transaction(&self, transaction: Transaction) -> Result<(), SplitwiseError>;
    async fn get_transaction(&self, id: &str) -> Result<Option<Transaction>, SplitwiseError>;
    async fn get_transactions_by_group(&self, group_id: &str) -> Result<Vec<Transaction>, SplitwiseError>;
    // Removed: save_balance, get_balances
    async fn get_transactions_by_user(&self, user_id: &str) -> Result<Vec<Transaction>, SplitwiseError>;
    async fn get_settlements_by_user(&self, user_id: &str) -> Result<Vec<Settlement>, SplitwiseError>;
    async fn save_settlement(&self, settlement: Settlement) -> Result<(), SplitwiseError>;
    async fn get_settlement(&self, id: &str) -> Result<Option<Settlement>, SplitwiseError>;
    async fn get_pending_settlements(&self, group_id: &str, user_id: &str) -> Result<Vec<Settlement>, SplitwiseError>;
    async fn save_app_log(&self, log: AppLog) -> Result<(), SplitwiseError>;
    async fn get_app_logs(&self) -> Result<Vec<AppLog>, SplitwiseError>;
    async fn save_group_audit(&self, audit: GroupAudit) -> Result<(), SplitwiseError>;
    async fn get_group_audits(&self, group_id: &str) -> Result<Vec<GroupAudit>, SplitwiseError>;
    async fn is_group_member(&self, group_id: &str, user_id: &str) -> Result<bool, SplitwiseError>;
    async fn get_user_groups(&self, user_id: &str) -> Result<Vec<Group>, SplitwiseError>;
    async fn delete_group(&self, group_id: &str) -> Result<(), SplitwiseError>;
}
