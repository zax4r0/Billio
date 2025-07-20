use crate::error::BillioError;
use crate::models::{
    audit::{AppLog, GroupAudit},
    group::Group,
    settlement::Settlement,
    transaction::Transaction,
    user::User,
};
use crate::storage::Storage;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;

pub struct InMemoryStorage {
    users: Mutex<HashMap<String, User>>,
    emails: Mutex<HashMap<String, String>>, // email -> user_id
    groups: Mutex<HashMap<String, Group>>,
    join_links: Mutex<HashMap<String, String>>, // link -> group_id
    transactions: Mutex<HashMap<String, Transaction>>,
    settlements: Mutex<HashMap<String, Settlement>>,
    app_logs: Mutex<Vec<AppLog>>,
    group_audits: Mutex<HashMap<String, Vec<GroupAudit>>>,
    // Indexes for faster user-based queries
    user_transactions: Mutex<HashMap<String, HashSet<String>>>, // user_id -> transaction_ids
    user_settlements: Mutex<HashMap<String, HashSet<String>>>,  // user_id -> settlement_ids
}

impl InMemoryStorage {
    pub fn new() -> Self {
        InMemoryStorage {
            users: Mutex::new(HashMap::new()),
            emails: Mutex::new(HashMap::new()),
            groups: Mutex::new(HashMap::new()),
            join_links: Mutex::new(HashMap::new()),
            transactions: Mutex::new(HashMap::new()),
            settlements: Mutex::new(HashMap::new()),
            app_logs: Mutex::new(Vec::new()),
            group_audits: Mutex::new(HashMap::new()),
            user_transactions: Mutex::new(HashMap::new()),
            user_settlements: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Storage for InMemoryStorage {
    async fn create_user_if_not_exists(&self, user: User) -> Result<User, BillioError> {
        // For production: Use database transactions
        let mut emails = self.emails.lock().await;
        if emails.contains_key(&user.email) {
            return Err(BillioError::EmailAlreadyRegistered(user.email));
        }
        emails.insert(user.email.clone(), user.id.clone());
        let mut users = self.users.lock().await;
        let user_id = user.id.clone();
        users.insert(user_id.clone(), user);
        Ok(users.get(&user_id).cloned().unwrap())
    }

    async fn get_user(&self, id: &str) -> Result<Option<User>, BillioError> {
        // For production: Add caching
        Ok(self.users.lock().await.get(id).cloned())
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, BillioError> {
        // For production: Use database index on email
        let user_id = self.emails.lock().await.get(email).cloned();
        Ok(match user_id {
            Some(id) => self.users.lock().await.get(&id).cloned(),
            None => None,
        })
    }

    async fn save_group(&self, group: Group) -> Result<(), BillioError> {
        // For production: Use database transactions
        let mut groups = self.groups.lock().await;
        let mut join_links = self.join_links.lock().await;
        join_links.insert(group.join_link.clone(), group.id.clone());
        groups.insert(group.id.clone(), group);
        Ok(())
    }

    async fn get_group(&self, id: &str) -> Result<Option<Group>, BillioError> {
        // For production: Add caching
        Ok(self.groups.lock().await.get(id).cloned())
    }

    async fn get_group_by_join_link(&self, link: &str) -> Result<Option<Group>, BillioError> {
        // For production: Use database index on join_link
        let group_id = self.join_links.lock().await.get(link).cloned();
        Ok(match group_id {
            Some(id) => self.groups.lock().await.get(&id).cloned(),
            None => None,
        })
    }

    async fn revoke_join_link(&self, link: &str) -> Result<(), BillioError> {
        // For production: Ensure atomic revocation
        self.join_links.lock().await.remove(link);
        Ok(())
    }

    async fn save_transaction(&self, transaction: Transaction) -> Result<(), BillioError> {
        // For production: Use database transactions
        let mut transactions = self.transactions.lock().await;
        let mut user_transactions = self.user_transactions.lock().await;
        transactions.insert(transaction.id.clone(), transaction.clone());
        // Update user index
        user_transactions
            .entry(transaction.paid_by.id.clone())
            .or_insert_with(HashSet::new)
            .insert(transaction.id.clone());
        for user_id in transaction.shares.keys() {
            user_transactions
                .entry(user_id.clone())
                .or_insert_with(HashSet::new)
                .insert(transaction.id.clone());
        }
        Ok(())
    }

    async fn get_transaction(&self, id: &str) -> Result<Option<Transaction>, BillioError> {
        // For production: Use database query
        Ok(self.transactions.lock().await.get(id).cloned())
    }

    async fn get_transactions_by_group(&self, group_id: &str) -> Result<Vec<Transaction>, BillioError> {
        // For production: Use database query with index
        Ok(self
            .transactions
            .lock()
            .await
            .values()
            .filter(|tx| tx.group_id == group_id)
            .cloned()
            .collect())
    }

    async fn get_transactions_by_user(&self, user_id: &str) -> Result<Vec<Transaction>, BillioError> {
        // For production: Use database index on user_id for faster queries
        let transactions = self.transactions.lock().await;
        let user_transactions = self.user_transactions.lock().await;
        Ok(user_transactions
            .get(user_id)
            .map(|tx_ids| {
                tx_ids
                    .iter()
                    .filter_map(|tx_id| transactions.get(tx_id).cloned())
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn get_settlements_by_user(&self, user_id: &str) -> Result<Vec<Settlement>, BillioError> {
        // For production: Use database index on user_id
        let settlements = self.settlements.lock().await;
        let user_settlements = self.user_settlements.lock().await;
        Ok(user_settlements
            .get(user_id)
            .map(|settle_ids| {
                settle_ids
                    .iter()
                    .filter_map(|settle_id| settlements.get(settle_id).cloned())
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn save_settlement(&self, settlement: Settlement) -> Result<(), BillioError> {
        // For production: Use database transactions
        let mut settlements = self.settlements.lock().await;
        let mut user_settlements = self.user_settlements.lock().await;
        settlements.insert(settlement.id.clone(), settlement.clone());
        // Update user index
        user_settlements
            .entry(settlement.from_user_id.clone())
            .or_insert_with(HashSet::new)
            .insert(settlement.id.clone());
        user_settlements
            .entry(settlement.to_user_id.clone())
            .or_insert_with(HashSet::new)
            .insert(settlement.id.clone());
        Ok(())
    }

    async fn get_settlement(&self, id: &str) -> Result<Option<Settlement>, BillioError> {
        // For production: Use database query
        Ok(self.settlements.lock().await.get(id).cloned())
    }

    async fn get_pending_settlements(&self, group_id: &str, user_id: &str) -> Result<Vec<Settlement>, BillioError> {
        // For production: Use database query with index
        Ok(self
            .settlements
            .lock()
            .await
            .values()
            .filter(|s| s.group_id == group_id && s.to_user_id == user_id && !s.is_confirmed)
            .cloned()
            .collect())
    }

    async fn save_app_log(&self, log: AppLog) -> Result<(), BillioError> {
        // For production: Batch writes
        self.app_logs.lock().await.push(log);
        Ok(())
    }

    async fn get_app_logs(&self) -> Result<Vec<AppLog>, BillioError> {
        Ok(self.app_logs.lock().await.clone())
    }

    async fn save_group_audit(&self, audit: GroupAudit) -> Result<(), BillioError> {
        // For production: Use database transactions
        let mut audits = self.group_audits.lock().await;
        audits
            .entry(audit.group_id.clone())
            .or_insert_with(Vec::new)
            .push(audit);
        Ok(())
    }

    async fn get_group_audits(&self, group_id: &str) -> Result<Vec<GroupAudit>, BillioError> {
        // For production: Add pagination
        Ok(self
            .group_audits
            .lock()
            .await
            .get(group_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn is_group_member(&self, group_id: &str, user_id: &str) -> Result<bool, BillioError> {
        // For production: Use database query
        let groups = self.groups.lock().await;
        if let Some(group) = groups.get(group_id) {
            Ok(group.members.iter().any(|m| m.user.id == user_id))
        } else {
            Err(BillioError::GroupNotFound(group_id.to_string()))
        }
    }

    async fn get_user_groups(&self, user_id: &str) -> Result<Vec<Group>, BillioError> {
        // For production: Use database query with index
        Ok(self
            .groups
            .lock()
            .await
            .values()
            .filter(|g| g.members.iter().any(|m| m.user.id == user_id))
            .cloned()
            .collect())
    }

    async fn delete_group(&self, group_id: &str) -> Result<(), BillioError> {
        // For production: Use database transactions
        let mut groups = self.groups.lock().await;
        if groups.remove(group_id).is_none() {
            return Err(BillioError::GroupNotFound(group_id.to_string()));
        }
        // Also remove join link
        let mut join_links = self.join_links.lock().await;
        if let Some((link, _)) = join_links
            .iter()
            .find(|(_, gid)| gid == &group_id)
            .map(|(l, _)| (l.clone(), ()))
        {
            join_links.remove(&link);
        }
        Ok(())
    }
}
