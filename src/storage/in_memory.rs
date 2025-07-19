use crate::models::*;
use crate::{error::ExpenseServiceError, storage::Storage};
use log::{debug, info, warn};
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

#[derive(Clone)]
pub struct InMemoryStorage {
    users: HashMap<Uuid, User>,
    groups: BTreeMap<Uuid, Group>,
    transactions: Vec<Transaction>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        info!("Initializing InMemoryStorage");
        InMemoryStorage {
            users: HashMap::new(),
            groups: BTreeMap::new(),
            transactions: Vec::new(),
        }
    }
}

impl Storage for InMemoryStorage {
    fn add_user_to_group(&mut self, group_user: GroupUser) -> Result<(), ExpenseServiceError> {
        info!(
            "Adding user {} to group {}",
            group_user.user_id, group_user.group_id
        );
        let group = self.groups.get_mut(&group_user.group_id).ok_or_else(|| {
            warn!("Group {} not found", group_user.group_id);
            ExpenseServiceError::GroupNotFound
        })?;

        if group
            .users
            .iter()
            .any(|gu| gu.user_id == group_user.user_id)
        {
            warn!(
                "User {} already in group {}",
                group_user.user_id, group_user.group_id
            );
            return Err(ExpenseServiceError::UserAlreadyInGroup);
        }

        debug!(
            "User {} added to group {}",
            group_user.user_id, group_user.group_id
        );
        group.users.push(group_user);
        Ok(())
    }

    fn create_group(&mut self, group: Group) -> Result<Group, ExpenseServiceError> {
        info!("Creating group with ID: {}", group.id);
        if self.groups.contains_key(&group.id) {
            warn!("Group {} already exists", group.id);
            return Err(ExpenseServiceError::GroupAlreadyExists);
        }
        self.groups.insert(group.id, group.clone());
        debug!("Group created: {:?}", group);
        Ok(group)
    }

    fn create_transaction(&mut self, tx: Transaction) -> Result<Transaction, ExpenseServiceError> {
        info!("Creating transaction with ID: {}", tx.id);
        if self.transactions.iter().any(|t| t.id == tx.id) {
            warn!("Transaction {} already exists", tx.id);
            return Err(ExpenseServiceError::TransactionAlreadyExists);
        }
        self.transactions.push(tx.clone());
        debug!("Transaction created: {:?}", tx);
        Ok(tx)
    }

    fn create_user(&mut self, user: User) -> Result<User, ExpenseServiceError> {
        info!("Creating user with ID: {}", user.id);
        if self.users.contains_key(&user.id) {
            warn!("User {} already exists", user.id);
            return Err(ExpenseServiceError::UserAlreadyExists);
        }
        if self.users.values().any(|u| u.email == user.email) {
            warn!("Email {} already in use", user.email);
            return Err(ExpenseServiceError::EmailInUse);
        }
        self.users.insert(user.id, user.clone());
        debug!("User created: {:?}", user);
        Ok(user)
    }

    fn get_group(&self, group_id: Uuid) -> Option<Group> {
        debug!("Fetching group {}", group_id);
        let group = self.groups.get(&group_id).cloned();
        if group.is_none() {
            warn!("Group {} not found", group_id);
        }
        group
    }

    fn get_group_user_role(&self, group_id: Uuid, user_id: Uuid) -> Option<Role> {
        debug!("Fetching role for user {} in group {}", user_id, group_id);
        let group = self.groups.get(&group_id)?;
        let role = group
            .users
            .iter()
            .find(|&gu| gu.user_id == user_id)
            .map(|gu| gu.role.clone());
        debug!(
            "Role for user {} in group {}: {:?}",
            user_id, group_id, role
        );
        role
    }

    fn get_transaction(&self, tx_id: Uuid) -> Option<Transaction> {
        debug!("Fetching transaction {}", tx_id);
        let tx = self.transactions.iter().find(|&tx| tx.id == tx_id).cloned();
        if tx.is_none() {
            warn!("Transaction {} not found", tx_id);
        }
        tx
    }

    fn get_user(&self, user_id: Uuid) -> Option<User> {
        debug!("Fetching user {}", user_id);
        let user = self.users.get(&user_id).cloned();
        if user.is_none() {
            warn!("User {} not found", user_id);
        }
        user
    }

    fn list_audit_logs(&self) -> Vec<AuditLogEntry> {
        debug!("Listing audit logs (not supported in InMemoryStorage)");
        vec![] // In-memory storage does not support audit logs
    }

    fn list_groups(&self) -> Vec<Group> {
        debug!("Listing all groups");
        let groups: Vec<Group> = self.groups.values().cloned().collect();
        debug!("Found {} groups", groups.len());
        groups
    }

    fn list_transactions(&self, group_id: Uuid) -> Vec<Transaction> {
        debug!("Listing transactions for group {}", group_id);
        let transactions: Vec<Transaction> = self
            .transactions
            .iter()
            .filter(|&tx| tx.group_id == group_id)
            .cloned()
            .collect();
        debug!(
            "Found {} transactions for group {}",
            transactions.len(),
            group_id
        );
        transactions
    }

    fn list_group_users(&self, group_id: Uuid) -> Vec<GroupUser> {
        debug!("Listing users for group {}", group_id);
        let users = self
            .groups
            .get(&group_id)
            .map_or(vec![], |group| group.users.iter().cloned().collect());
        debug!("Found {} users in group {}", users.len(), group_id);
        users
    }

    fn remove_user_from_group(
        &mut self,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), ExpenseServiceError> {
        info!("Removing user {} from group {}", user_id, group_id);
        let group = self.groups.get_mut(&group_id).ok_or_else(|| {
            warn!("Group {} not found", group_id);
            ExpenseServiceError::GroupNotFound
        })?;

        if let Some(pos) = group.users.iter().position(|gu| gu.user_id == user_id) {
            group.users.remove(pos);
            debug!("User {} removed from group {}", user_id, group_id);
            Ok(())
        } else {
            warn!("User {} not found in group {}", user_id, group_id);
            Err(ExpenseServiceError::NotGroupMember)
        }
    }

    fn update_group(&mut self, group: Group) -> Result<Group, ExpenseServiceError> {
        info!("Updating group {}", group.id);
        if self.groups.contains_key(&group.id) {
            self.groups.insert(group.id, group.clone());
            debug!("Group updated: {:?}", group);
            Ok(group)
        } else {
            warn!("Group {} not found", group.id);
            Err(ExpenseServiceError::GroupNotFound)
        }
    }

    fn update_group_user_role(
        &mut self,
        group_id: Uuid,
        user_id: Uuid,
        role: Role,
    ) -> Result<(), ExpenseServiceError> {
        info!(
            "Updating role for user {} in group {} to {:?}",
            user_id, group_id, role
        );
        let group = self.groups.get_mut(&group_id).ok_or_else(|| {
            warn!("Group {} not found", group_id);
            ExpenseServiceError::GroupNotFound
        })?;

        if let Some(gu) = group.users.iter_mut().find(|gu| gu.user_id == user_id) {
            gu.role = role;
            debug!("Role updated for user {} in group {}", user_id, group_id);
            Ok(())
        } else {
            warn!("User {} not found in group {}", user_id, group_id);
            Err(ExpenseServiceError::NotGroupMember)
        }
    }

    fn update_transaction(&mut self, tx: Transaction) -> Result<Transaction, ExpenseServiceError> {
        info!("Updating transaction {}", tx.id);
        if let Some(existing_tx) = self.transactions.iter_mut().find(|t| t.id == tx.id) {
            *existing_tx = tx.clone();
            debug!("Transaction updated: {:?}", tx);
            Ok(tx)
        } else {
            warn!("Transaction {} not found", tx.id);
            Err(ExpenseServiceError::TransactionNotFound)
        }
    }

    fn update_user(&mut self, user: User) -> Result<User, ExpenseServiceError> {
        info!("Updating user {}", user.id);
        if self.users.contains_key(&user.id) {
            if self
                .users
                .values()
                .any(|u| u.email == user.email && u.id != user.id)
            {
                warn!("Email {} already in use", user.email);
                return Err(ExpenseServiceError::EmailInUse);
            }
            self.users.insert(user.id, user.clone());
            debug!("User updated: {:?}", user);
            Ok(user)
        } else {
            warn!("User {} not found", user.id);
            Err(ExpenseServiceError::UserNotFound)
        }
    }

    fn is_group_member(&self, group_id: Uuid, user_id: Uuid) -> bool {
        debug!(
            "Checking if user {} is member of group {}",
            user_id, group_id
        );
        let is_member = self.groups.get(&group_id).map_or(false, |group| {
            group.users.iter().any(|gu| gu.user_id == user_id)
        });
        debug!(
            "User {} is_member of group {}: {}",
            user_id, group_id, is_member
        );
        is_member
    }
}
