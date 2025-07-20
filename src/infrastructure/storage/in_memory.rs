use crate::core::errors::BillioError;
use crate::core::models::{
    audit::GroupAudit, group::Group, settlement::Settlement, transaction::Transaction, user::User,
};
use crate::infrastructure::storage::Storage;
use async_trait::async_trait;
use bcrypt::hash;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct InMemoryStorage {
    users: Arc<RwLock<HashMap<String, User>>>,
    users_by_email: Arc<RwLock<HashMap<String, User>>>,
    groups: Arc<RwLock<HashMap<String, Group>>>,
    groups_by_join_link: Arc<RwLock<HashMap<String, String>>>,
    transactions: Arc<RwLock<HashMap<String, Transaction>>>,
    settlements: Arc<RwLock<HashMap<String, Settlement>>>,
    group_audits: Arc<RwLock<HashMap<String, Vec<GroupAudit>>>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        InMemoryStorage {
            users: Arc::new(RwLock::new(HashMap::new())),
            users_by_email: Arc::new(RwLock::new(HashMap::new())),
            groups: Arc::new(RwLock::new(HashMap::new())),
            groups_by_join_link: Arc::new(RwLock::new(HashMap::new())),
            transactions: Arc::new(RwLock::new(HashMap::new())),
            settlements: Arc::new(RwLock::new(HashMap::new())),
            group_audits: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl Storage for InMemoryStorage {
    async fn create_user_if_not_exists(&self, user: User) -> Result<User, BillioError> {
        let mut users_by_email = self.users_by_email.write().await;
        if users_by_email.contains_key(&user.email) {
            return Ok(User {
                id: String::new(),
                name: String::new(),
                email: user.email,
                password: String::new(),
            });
        }
        let hashed_user = User {
            id: user.id.clone(),
            name: user.name.clone(),
            email: user.email.clone(),
            password: hash(&user.password, bcrypt::DEFAULT_COST)
                .map_err(|e| BillioError::InternalServerError(format!("Password hashing error: {}", e)))?,
        };
        users_by_email.insert(user.email.clone(), hashed_user.clone());
        let mut users = self.users.write().await;
        users.insert(user.id.clone(), hashed_user.clone());
        Ok(hashed_user)
    }

    async fn get_user(&self, user_id: &str) -> Result<Option<User>, BillioError> {
        let users = self.users.read().await;
        Ok(users.get(user_id).cloned())
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, BillioError> {
        let users_by_email = self.users_by_email.read().await;
        Ok(users_by_email.get(email).cloned())
    }

    async fn save_group(&self, group: Group) -> Result<(), BillioError> {
        let mut groups = self.groups.write().await;
        let mut groups_by_join_link = self.groups_by_join_link.write().await;
        groups.insert(group.id.clone(), group.clone());
        groups_by_join_link.insert(group.join_link.clone(), group.id.clone());
        Ok(())
    }

    async fn get_group(&self, group_id: &str) -> Result<Option<Group>, BillioError> {
        let groups = self.groups.read().await;
        Ok(groups.get(group_id).cloned())
    }

    async fn get_group_by_join_link(&self, join_link: &str) -> Result<Option<Group>, BillioError> {
        let groups_by_join_link = self.groups_by_join_link.read().await;
        let groups = self.groups.read().await;
        Ok(groups_by_join_link
            .get(join_link)
            .and_then(|group_id| groups.get(group_id).cloned()))
    }

    async fn revoke_join_link(&self, join_link: &str) -> Result<(), BillioError> {
        let mut groups_by_join_link = self.groups_by_join_link.write().await;
        groups_by_join_link.remove(join_link);
        Ok(())
    }

    async fn delete_group(&self, group_id: &str) -> Result<(), BillioError> {
        let mut groups = self.groups.write().await;
        if let Some(group) = groups.remove(group_id) {
            let mut groups_by_join_link = self.groups_by_join_link.write().await;
            groups_by_join_link.remove(&group.join_link);
        }
        Ok(())
    }

    async fn save_transaction(&self, transaction: Transaction) -> Result<(), BillioError> {
        let mut transactions = self.transactions.write().await;
        transactions.insert(transaction.id.clone(), transaction);
        Ok(())
    }

    async fn get_transaction(&self, transaction_id: &str) -> Result<Option<Transaction>, BillioError> {
        let transactions = self.transactions.read().await;
        Ok(transactions.get(transaction_id).cloned())
    }

    async fn get_effective_transactions(&self, group_id: &str) -> Result<Vec<Transaction>, BillioError> {
        let transactions = self.transactions.read().await;
        Ok(transactions
            .values()
            .filter(|t| t.group_id == group_id && !t.is_reversed)
            .cloned()
            .collect())
    }

    async fn save_settlement(&self, settlement: Settlement) -> Result<(), BillioError> {
        let mut settlements = self.settlements.write().await;
        settlements.insert(settlement.id.clone(), settlement);
        Ok(())
    }

    async fn get_settlement(&self, settlement_id: &str) -> Result<Option<Settlement>, BillioError> {
        let settlements = self.settlements.read().await;
        Ok(settlements.get(settlement_id).cloned())
    }

    async fn get_settlements(&self, group_id: &str) -> Result<Vec<Settlement>, BillioError> {
        let settlements = self.settlements.read().await;
        Ok(settlements
            .values()
            .filter(|s| s.group_id == group_id)
            .cloned()
            .collect())
    }

    async fn get_pending_settlements(&self, group_id: &str) -> Result<Vec<Settlement>, BillioError> {
        let settlements = self.settlements.read().await;
        Ok(settlements
            .values()
            .filter(|s| s.group_id == group_id && !s.is_confirmed)
            .cloned()
            .collect())
    }

    async fn get_user_groups(&self, user_id: &str) -> Result<Vec<Group>, BillioError> {
        let groups = self.groups.read().await;
        Ok(groups
            .values()
            .filter(|g| g.members.iter().any(|m| m.user.id == user_id))
            .cloned()
            .collect())
    }

    async fn is_group_member(&self, group_id: &str, user_id: &str) -> Result<bool, BillioError> {
        let groups = self.groups.read().await;
        Ok(groups
            .get(group_id)
            .map(|g| g.members.iter().any(|m| m.user.id == user_id))
            .unwrap_or(false))
    }

    async fn save_group_audit(&self, audit: GroupAudit) -> Result<(), BillioError> {
        let mut group_audits = self.group_audits.write().await;
        group_audits
            .entry(audit.group_id.clone())
            .or_insert_with(Vec::new)
            .push(audit);
        Ok(())
    }

    async fn get_group_audits(&self, group_id: &str) -> Result<Vec<GroupAudit>, BillioError> {
        let group_audits = self.group_audits.read().await;
        Ok(group_audits.get(group_id).cloned().unwrap_or_default())
    }
}
