use crate::error::SplitwiseError;
use crate::models::{
    audit::{AppLog, GroupAudit},
    group::Group,
    settlement::Settlement,
    transaction::Transaction,
    transaction_split::Balance,
    user::User,
};
use crate::storage::Storage;
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::Mutex;

pub struct InMemoryStorage {
    users: Mutex<HashMap<String, User>>,
    emails: Mutex<HashMap<String, String>>, // email -> user_id
    groups: Mutex<HashMap<String, Group>>,
    join_links: Mutex<HashMap<String, String>>, // link -> group_id
    transactions: Mutex<HashMap<String, Transaction>>,
    balances: Mutex<HashMap<String, HashMap<String, f64>>>, // user_id -> (owes_to -> amount)
    settlements: Mutex<HashMap<String, Settlement>>,
    app_logs: Mutex<Vec<AppLog>>,
    group_audits: Mutex<HashMap<String, Vec<GroupAudit>>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        InMemoryStorage {
            users: Mutex::new(HashMap::new()),
            emails: Mutex::new(HashMap::new()),
            groups: Mutex::new(HashMap::new()),
            join_links: Mutex::new(HashMap::new()),
            transactions: Mutex::new(HashMap::new()),
            balances: Mutex::new(HashMap::new()),
            settlements: Mutex::new(HashMap::new()),
            app_logs: Mutex::new(Vec::new()),
            group_audits: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Storage for InMemoryStorage {
    async fn save_user(&self, user: User) -> Result<(), SplitwiseError> {
        let mut emails = self.emails.lock().await;
        if emails.contains_key(&user.email) {
            return Err(SplitwiseError::EmailAlreadyRegistered(user.email));
        }
        emails.insert(user.email.clone(), user.id.clone());
        let mut users = self.users.lock().await;
        users.insert(user.id.clone(), user);
        Ok(())
    }

    async fn get_user(&self, id: &str) -> Result<Option<User>, SplitwiseError> {
        Ok(self.users.lock().await.get(id).cloned())
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, SplitwiseError> {
        // For production: Use database index on email
        let user_id = self.emails.lock().await.get(email).cloned();
        Ok(match user_id {
            Some(id) => self.users.lock().await.get(&id).cloned(),
            None => None,
        })
    }

    async fn save_group(&self, group: Group) -> Result<(), SplitwiseError> {
        // For production: Use database transactions
        let mut groups = self.groups.lock().await;
        let mut join_links = self.join_links.lock().await;
        join_links.insert(group.join_link.clone(), group.id.clone());
        groups.insert(group.id.clone(), group);
        Ok(())
    }

    async fn get_group(&self, id: &str) -> Result<Option<Group>, SplitwiseError> {
        // For production: Add caching
        Ok(self.groups.lock().await.get(id).cloned())
    }

    async fn get_group_by_join_link(&self, link: &str) -> Result<Option<Group>, SplitwiseError> {
        // For production: Use database index on join_link
        let group_id = self.join_links.lock().await.get(link).cloned();
        Ok(match group_id {
            Some(id) => self.groups.lock().await.get(&id).cloned(),
            None => None,
        })
    }

    async fn revoke_join_link(&self, link: &str) -> Result<(), SplitwiseError> {
        // For production: Ensure atomic revocation
        self.join_links.lock().await.remove(link);
        Ok(())
    }

    async fn save_transaction(&self, transaction: Transaction) -> Result<(), SplitwiseError> {
        self.transactions
            .lock()
            .await
            .insert(transaction.id.clone(), transaction);
        Ok(())
    }

    async fn get_transaction(&self, id: &str) -> Result<Option<Transaction>, SplitwiseError> {
        Ok(self.transactions.lock().await.get(id).cloned())
    }

    async fn get_transactions_by_group(
        &self,
        group_id: &str,
    ) -> Result<Vec<Transaction>, SplitwiseError> {
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

    async fn save_balance(
        &self,
        user_id: &str,
        owes_to: &str,
        amount: f64,
    ) -> Result<(), SplitwiseError> {
        let mut balances = self.balances.lock().await;
        let user_balances = balances
            .entry(user_id.to_string())
            .or_insert_with(HashMap::new);
        let current = user_balances.get(owes_to).copied().unwrap_or(0.0);
        user_balances.insert(owes_to.to_string(), current + amount);
        Ok(())
    }

    async fn get_balances(&self, user_id: &str) -> Result<Vec<Balance>, SplitwiseError> {
        Ok(self
            .balances
            .lock()
            .await
            .get(user_id)
            .map(|b| {
                b.iter()
                    .map(|(owes_to, amount)| Balance {
                        user_id: user_id.to_string(),
                        owes_to: owes_to.to_string(),
                        amount: *amount,
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn save_settlement(&self, settlement: Settlement) -> Result<(), SplitwiseError> {
        // For production: Use database transactions
        self.settlements
            .lock()
            .await
            .insert(settlement.id.clone(), settlement);
        Ok(())
    }

    async fn get_settlement(&self, id: &str) -> Result<Option<Settlement>, SplitwiseError> {
        Ok(self.settlements.lock().await.get(id).cloned())
    }

    async fn get_pending_settlements(
        &self,
        group_id: &str,
        user_id: &str,
    ) -> Result<Vec<Settlement>, SplitwiseError> {
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

    async fn save_app_log(&self, log: AppLog) -> Result<(), SplitwiseError> {
        // For production: Batch writes
        self.app_logs.lock().await.push(log);
        Ok(())
    }

    async fn get_app_logs(&self) -> Result<Vec<AppLog>, SplitwiseError> {
        Ok(self.app_logs.lock().await.clone())
    }

    async fn save_group_audit(&self, audit: GroupAudit) -> Result<(), SplitwiseError> {
        let mut audits = self.group_audits.lock().await;
        audits
            .entry(audit.group_id.clone())
            .or_insert_with(Vec::new)
            .push(audit);
        Ok(())
    }

    async fn get_group_audits(&self, group_id: &str) -> Result<Vec<GroupAudit>, SplitwiseError> {
        // For production: Add pagination
        Ok(self
            .group_audits
            .lock()
            .await
            .get(group_id)
            .cloned()
            .unwrap_or_default())
    }
}
