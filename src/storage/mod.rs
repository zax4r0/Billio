pub mod in_memory;

use crate::error::BillioError;
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
    async fn create_user_if_not_exists(&self, user: User) -> Result<User, BillioError>;
    async fn get_user(&self, id: &str) -> Result<Option<User>, BillioError>;
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, BillioError>;
    async fn save_group(&self, group: Group) -> Result<(), BillioError>;
    async fn get_group(&self, id: &str) -> Result<Option<Group>, BillioError>;
    async fn get_group_by_join_link(&self, link: &str) -> Result<Option<Group>, BillioError>;
    async fn revoke_join_link(&self, link: &str) -> Result<(), BillioError>;
    async fn save_transaction(&self, transaction: Transaction) -> Result<(), BillioError>;
    async fn get_transaction(&self, id: &str) -> Result<Option<Transaction>, BillioError>;
    async fn get_transactions_by_group(&self, group_id: &str) -> Result<Vec<Transaction>, BillioError>;
    // Removed: save_balance, get_balances
    async fn get_transactions_by_user(&self, user_id: &str) -> Result<Vec<Transaction>, BillioError>;
    async fn get_settlements_by_user(&self, user_id: &str) -> Result<Vec<Settlement>, BillioError>;
    async fn save_settlement(&self, settlement: Settlement) -> Result<(), BillioError>;
    async fn get_settlement(&self, id: &str) -> Result<Option<Settlement>, BillioError>;
    async fn get_pending_settlements(&self, group_id: &str, user_id: &str) -> Result<Vec<Settlement>, BillioError>;
    async fn save_app_log(&self, log: AppLog) -> Result<(), BillioError>;
    async fn get_app_logs(&self) -> Result<Vec<AppLog>, BillioError>;
    async fn save_group_audit(&self, audit: GroupAudit) -> Result<(), BillioError>;
    async fn get_group_audits(&self, group_id: &str) -> Result<Vec<GroupAudit>, BillioError>;
    async fn is_group_member(&self, group_id: &str, user_id: &str) -> Result<bool, BillioError>;
    async fn get_user_groups(&self, user_id: &str) -> Result<Vec<Group>, BillioError>;
    async fn delete_group(&self, group_id: &str) -> Result<(), BillioError>;
}
