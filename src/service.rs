use crate::error::ExpenseServiceError;
use crate::logger::AuditLogger;
use crate::models::*;
use crate::{constants::SPLIT_TOLERANCE, storage::Storage};
use chrono::Utc;
use log::{debug, info, warn};
use serde_json;
use std::collections::HashMap;
use uuid::Uuid;

pub struct ExpenseService<'a> {
    pub storage: &'a mut dyn Storage,
    pub audit_logger: &'a mut dyn AuditLogger,
}

impl<'a> ExpenseService<'a> {
    pub fn new(storage: &'a mut dyn Storage, audit_logger: &'a mut dyn AuditLogger) -> Self {
        info!("Initializing ExpenseService");
        Self {
            storage,
            audit_logger,
        }
    }

    // USER MANAGEMENT

    pub fn create_user(
        &mut self,
        email: String,
        password_hash: String,
        name: String,
    ) -> Result<User, ExpenseServiceError> {
        info!("Creating user with email: {}", email);
        let now = Utc::now();
        let user = User {
            id: Uuid::new_v4(),
            email,
            name,
            password_hash,
            created_at: now,
            updated_at: now,
        };

        let created = self.storage.create_user(user.clone())?;
        debug!("User created with ID: {}", created.id);

        self.audit_logger.log(AuditLogEntry::new(
            created.id,
            AuditAction::CreateUser,
            &serde_json::json!({ "user_id": created.id }),
            now,
        ));

        Ok(created)
    }

    pub fn update_user(&mut self, user: User) -> Result<User, ExpenseServiceError> {
        info!("Updating user with ID: {}", user.id);
        let updated = self.storage.update_user(user.clone())?;
        debug!("User updated: {:?}", updated);

        self.audit_logger.log(AuditLogEntry::new(
            user.id,
            AuditAction::UpdateUser,
            &serde_json::json!({ "user_id": user.id }),
            Utc::now(),
        ));

        Ok(updated)
    }

    // GROUP MANAGEMENT

    pub fn create_group(
        &mut self,
        owner: &User,
        name: String,
        strict_editing: bool,
    ) -> Result<Group, ExpenseServiceError> {
        info!("Creating group '{}' for owner ID: {}", name, owner.id);
        let now = Utc::now();
        let join_link = Self::generate_join_link();

        let group_id = Uuid::new_v4();
        let group = Group {
            id: group_id,
            name,
            owner_id: owner.id,
            strict_editing,
            join_link,
            created_at: now,
            updated_at: now,
            users: vec![GroupUser {
                group_id: group_id, // Use group_id instead of group.id
                user_id: owner.id,
                role: Role::Owner,
                joined_at: now,
            }], // Start with owner in group
        };

        let created = self.storage.create_group(group.clone())?;
        debug!("Group created with ID: {}", created.id);

        self.audit_logger.log(AuditLogEntry::new(
            owner.id,
            AuditAction::CreateGroup,
            &serde_json::json!({ "group_id": created.id }),
            now,
        ));

        Ok(created)
    }

    pub fn update_group(
        &mut self,
        user: &User,
        group: Group,
        new_name: Option<String>,
        new_strict_editing: Option<bool>,
    ) -> Result<Group, ExpenseServiceError> {
        info!("Updating group ID: {} by user ID: {}", group.id, user.id);
        let role = self
            .storage
            .get_group_user_role(group.id, user.id)
            .ok_or(ExpenseServiceError::NotGroupMember)?;
        if role != Role::Owner {
            warn!(
                "User {} attempted to update group {} without owner role",
                user.id, group.id
            );
            return Err(ExpenseServiceError::NotAuthorized);
        }

        let mut updated_group = group;
        if let Some(name) = new_name {
            updated_group.name = name;
        }
        if let Some(strict) = new_strict_editing {
            updated_group.strict_editing = strict;
        }
        updated_group.updated_at = Utc::now();

        let res = self.storage.update_group(updated_group.clone())?;
        debug!("Group updated: {:?}", res);

        self.audit_logger.log(AuditLogEntry::new(
            user.id,
            AuditAction::UpdateGroup,
            &serde_json::json!({ "group_id": res.id }),
            Utc::now(),
        ));

        Ok(res)
    }

    pub fn transfer_ownership(
        &mut self,
        current_owner: &User,
        group: &Group,
        new_owner_id: Uuid,
    ) -> Result<(), ExpenseServiceError> {
        info!(
            "Transferring ownership of group {} from user {} to user {}",
            group.id, current_owner.id, new_owner_id
        );
        let role = self
            .storage
            .get_group_user_role(group.id, current_owner.id)
            .ok_or(ExpenseServiceError::NotGroupMember)?;
        if role != Role::Owner {
            warn!(
                "User {} attempted to transfer ownership of group {} without owner role",
                current_owner.id, group.id
            );
            return Err(ExpenseServiceError::NotAuthorized);
        }
        if !self.storage.is_group_member(group.id, new_owner_id) {
            warn!(
                "New owner {} is not a member of group {}",
                new_owner_id, group.id
            );
            return Err(ExpenseServiceError::NotGroupMember);
        }

        let mut updated_group = group.clone();
        updated_group.owner_id = new_owner_id;
        updated_group.updated_at = Utc::now();

        self.storage.update_group(updated_group)?;
        self.storage
            .update_group_user_role(group.id, current_owner.id, Role::Member)?;
        self.storage
            .update_group_user_role(group.id, new_owner_id, Role::Owner)?;

        self.audit_logger.log(AuditLogEntry::new(
            current_owner.id,
            AuditAction::TransferOwnership,
            &serde_json::json!({ "group_id": group.id, "new_owner_id": new_owner_id }),
            Utc::now(),
        ));

        debug!("Ownership transferred for group {}", group.id);
        Ok(())
    }

    pub fn join_group_by_link(
        &mut self,
        user: &User,
        join_link: &str,
    ) -> Result<GroupUser, ExpenseServiceError> {
        info!(
            "User {} attempting to join group via link: {}",
            user.id, join_link
        );
        let group = self
            .storage
            .list_groups()
            .into_iter()
            .find(|g| g.join_link == join_link)
            .ok_or_else(|| {
                warn!("Invalid join link: {}", join_link);
                ExpenseServiceError::InvalidJoinLink
            })?;

        if self.storage.is_group_member(group.id, user.id) {
            warn!("User {} already in group {}", user.id, group.id);
            return Err(ExpenseServiceError::UserAlreadyInGroup);
        }

        let now = Utc::now();
        let membership = GroupUser {
            group_id: group.id,
            user_id: user.id,
            role: Role::Member,
            joined_at: now,
        };
        self.storage.add_user_to_group(membership.clone())?;

        self.audit_logger.log(AuditLogEntry::new(
            user.id,
            AuditAction::UserJoinGroup,
            &serde_json::json!({ "group_id": group.id }),
            now,
        ));

        debug!("User {} joined group {}", user.id, group.id);
        Ok(membership)
    }

    pub fn remove_user_from_group(
        &mut self,
        group: &Group,
        user: &User,
        target_user_id: Uuid,
    ) -> Result<(), ExpenseServiceError> {
        info!(
            "User {} attempting to remove user {} from group {}",
            user.id, target_user_id, group.id
        );
        let role = self
            .storage
            .get_group_user_role(group.id, user.id)
            .ok_or(ExpenseServiceError::NotGroupMember)?;
        if role != Role::Owner {
            warn!(
                "User {} attempted to remove user from group {} without owner role",
                user.id, group.id
            );
            return Err(ExpenseServiceError::NotAuthorized);
        }
        if group.owner_id == target_user_id {
            warn!(
                "Attempted to remove owner {} from group {}",
                target_user_id, group.id
            );
            return Err(ExpenseServiceError::NotAuthorized);
        }

        self.storage
            .remove_user_from_group(group.id, target_user_id)?;
        self.audit_logger.log(AuditLogEntry::new(
            user.id,
            AuditAction::RemoveUserFromGroup,
            &serde_json::json!({ "group_id": group.id, "target_user_id": target_user_id }),
            Utc::now(),
        ));

        debug!("User {} removed from group {}", target_user_id, group.id);
        Ok(())
    }

    // TRANSACTION MANAGEMENT

    pub fn create_transaction(
        &mut self,
        group: &Group,
        added_by: &User,
        payer_id: Uuid,
        amount: f64,
        description: String,
        split_type: SplitType,
        split_data: Vec<Uuid>,
        custom_splits: Vec<TransactionSplit>,
    ) -> Result<Transaction, ExpenseServiceError> {
        info!(
            "Creating transaction in group {} by user {} for amount {}",
            group.id, added_by.id, amount
        );
        if !self.storage.is_group_member(group.id, payer_id) {
            warn!("Payer {} not in group {}", payer_id, group.id);
            return Err(ExpenseServiceError::NotGroupMember);
        }

        let now = Utc::now();
        let splits: Vec<TransactionSplit> = match split_type {
            SplitType::Equal => {
                if split_data.is_empty() {
                    warn!(
                        "Empty user IDs provided for equal split in group {}",
                        group.id
                    );
                    return Err(ExpenseServiceError::InvalidSplit);
                }
                let share = amount / split_data.len() as f64;
                split_data
                    .iter()
                    .map(|&user_id| TransactionSplit { user_id, share })
                    .collect()
            }
            SplitType::Custom => {
                let total_splits: f64 = custom_splits.iter().map(|s| s.share).sum();
                if (total_splits - amount).abs() > SPLIT_TOLERANCE {
                    warn!(
                        "Custom splits sum {} does not match amount {}",
                        total_splits, amount
                    );
                    return Err(ExpenseServiceError::InvalidSplit);
                }
                custom_splits
            }
        };

        for split in &splits {
            if !self.storage.is_group_member(group.id, split.user_id) {
                warn!("User {} in splits not in group {}", split.user_id, group.id);
                return Err(ExpenseServiceError::NotGroupMember);
            }
        }

        let tx = Transaction {
            id: Uuid::new_v4(),
            group_id: group.id,
            payer_id,
            added_by: added_by.id,
            amount,
            description,
            splits,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let created = self.storage.create_transaction(tx.clone())?;
        debug!("Transaction created with ID: {}", created.id);

        self.audit_logger.log(AuditLogEntry::new(
            added_by.id,
            AuditAction::CreateTransaction,
            &serde_json::json!({ "transaction_id": created.id, "group_id": group.id, "amount": amount }),
            now,
        ));

        Ok(created)
    }

    pub fn update_transaction(
        &mut self,
        group: &Group,
        transaction: &Transaction,
        user: &User,
        new_amount: f64,
        new_description: String,
        new_splits: Vec<TransactionSplit>,
    ) -> Result<Transaction, ExpenseServiceError> {
        info!(
            "Updating transaction {} in group {} by user {}",
            transaction.id, group.id, user.id
        );
        if !self.can_edit_transaction(group, transaction, user.id) {
            warn!(
                "User {} not permitted to edit transaction {}",
                user.id, transaction.id
            );
            return Err(ExpenseServiceError::NotAuthorized);
        }

        let total_splits: f64 = new_splits.iter().map(|s| s.share).sum();
        if (total_splits - new_amount).abs() > SPLIT_TOLERANCE {
            warn!(
                "Sum of splits {} does not equal amount {}",
                total_splits, new_amount
            );
            return Err(ExpenseServiceError::InvalidSplit);
        }

        for split in &new_splits {
            if self
                .storage
                .get_group_user_role(group.id, split.user_id)
                .is_none()
            {
                warn!("User {} in splits not in group {}", split.user_id, group.id);
                return Err(ExpenseServiceError::NotGroupMember);
            }
        }

        let now = Utc::now();
        let updated_tx = Transaction {
            amount: new_amount,
            description: new_description,
            splits: new_splits,
            updated_at: now,
            ..transaction.clone()
        };
        let saved = self.storage.update_transaction(updated_tx.clone())?;
        debug!("Transaction updated: {:?}", saved);

        self.audit_logger.log(AuditLogEntry::new(
            user.id,
            AuditAction::UpdateTransaction,
            &serde_json::json!({ "transaction_id": saved.id, "group_id": group.id, "new_amount": new_amount }),
            now,
        ));

        Ok(saved)
    }

    pub fn soft_delete_transaction(
        &mut self,
        group: &Group,
        transaction: &Transaction,
        user: &User,
    ) -> Result<Transaction, ExpenseServiceError> {
        info!(
            "Soft deleting transaction {} in group {} by user {}",
            transaction.id, group.id, user.id
        );
        if !self.can_edit_transaction(group, transaction, user.id) {
            warn!(
                "User {} not permitted to delete transaction {}",
                user.id, transaction.id
            );
            return Err(ExpenseServiceError::NotAuthorized);
        }
        if transaction.deleted_at.is_some() {
            warn!("Transaction {} already deleted", transaction.id);
            return Err(ExpenseServiceError::AlreadyDeleted);
        }

        let now = Utc::now();
        let deleted_tx = Transaction {
            deleted_at: Some(now),
            updated_at: now,
            ..transaction.clone()
        };
        let saved = self.storage.update_transaction(deleted_tx.clone())?;
        debug!("Transaction soft deleted: {}", saved.id);

        self.audit_logger.log(AuditLogEntry::new(
            user.id,
            AuditAction::DeleteTransaction,
            &serde_json::json!({ "transaction_id": saved.id, "group_id": group.id }),
            now,
        ));

        Ok(saved)
    }

    // SUMMARY & DEBT SIMPLIFICATION

    pub fn calculate_balances(
        &self,
        group: &Group,
        transactions: &[Transaction],
    ) -> HashMap<Uuid, f64> {
        debug!("Calculating balances for group {}", group.id);
        let mut balances: HashMap<Uuid, f64> = HashMap::new();

        for tx in transactions
            .iter()
            .filter(|tx| tx.deleted_at.is_none() && tx.group_id == group.id)
        {
            *balances.entry(tx.payer_id).or_insert(0.0) += tx.amount;
            for split in &tx.splits {
                *balances.entry(split.user_id).or_insert(0.0) -= split.share;
            }
        }

        debug!("Balances calculated: {:?}", balances);
        balances
    }

    pub fn simplify_debts(
        &self,
        balances: &HashMap<Uuid, f64>,
    ) -> Vec<(
        Uuid, /* from_user */
        Uuid, /* to_user */
        f64,  /* amount */
    )> {
        debug!("Simplifying debts with balances: {:?}", balances);
        let mut creditors: Vec<(Uuid, f64)> = balances
            .iter()
            .filter_map(|(&user, &bal)| {
                if bal > SPLIT_TOLERANCE {
                    Some((user, bal))
                } else {
                    None
                }
            })
            .collect();

        let mut debtors: Vec<(Uuid, f64)> = balances
            .iter()
            .filter_map(|(&user, &bal)| {
                if bal < -SPLIT_TOLERANCE {
                    Some((user, -bal))
                } else {
                    None
                }
            })
            .collect();

        // Avoid sorting for small datasets (less than 10 users) to optimize performance
        if creditors.len() > 10 || debtors.len() > 10 {
            creditors.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
            debtors.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        }

        let mut simplified = Vec::new();
        let mut i = 0;
        let mut j = 0;

        while i < debtors.len() && j < creditors.len() {
            let (debtor_id, mut debt_amt) = debtors[i];
            let (creditor_id, mut credit_amt) = creditors[j];

            let settled_amt = debt_amt.min(credit_amt);

            if settled_amt > SPLIT_TOLERANCE {
                simplified.push((debtor_id, creditor_id, settled_amt));
            }

            debt_amt -= settled_amt;
            credit_amt -= settled_amt;

            debtors[i].1 = debt_amt;
            creditors[j].1 = credit_amt;

            if debt_amt < SPLIT_TOLERANCE {
                i += 1;
            }
            if credit_amt < SPLIT_TOLERANCE {
                j += 1;
            }
        }

        debug!("Simplified debts: {:?}", simplified);
        simplified
    }

    // PERMISSION HELPERS

    pub fn can_edit_group(&self, group: &Group, user_id: Uuid) -> bool {
        let can_edit = matches!(
            self.storage.get_group_user_role(group.id, user_id),
            Some(Role::Owner)
        );
        debug!("User {} can_edit_group {}: {}", user_id, group.id, can_edit);
        can_edit
    }

    pub fn can_edit_transaction(
        &self,
        group: &Group,
        transaction: &Transaction,
        user_id: Uuid,
    ) -> bool {
        let role = self.storage.get_group_user_role(group.id, user_id);
        let can_edit = if role.is_none() {
            false
        } else if group.strict_editing {
            transaction.added_by == user_id
        } else {
            true
        };
        debug!(
            "User {} can_edit_transaction {}: {}",
            user_id, transaction.id, can_edit
        );
        can_edit
    }

    pub fn can_delete_transaction(
        &self,
        group: &Group,
        transaction: &Transaction,
        user_id: Uuid,
    ) -> bool {
        let can_delete = self.can_edit_transaction(group, transaction, user_id);
        debug!(
            "User {} can_delete_transaction {}: {}",
            user_id, transaction.id, can_delete
        );
        can_delete
    }

    // UTILITIES

    fn generate_join_link() -> String {
        let link = Uuid::new_v4().to_string();
        debug!("Generated join link: {}", link);
        link
    }
}
