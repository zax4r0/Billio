// src/service.rs

use crate::constants::*;
use crate::error::SplitwiseError;
use crate::logger::LoggingService;
use crate::models::{
    audit::{AppLog, GroupAudit},
    group::{Group, GroupMember, Role},
    settlement::Settlement,
    transaction::Transaction,
    transaction_split::Balance,
    user::User,
};
use crate::storage::Storage;
use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

pub struct SplitwiseService<L: LoggingService, S: Storage> {
    storage: S,
    logging: L,
}

impl<L: LoggingService, S: Storage> SplitwiseService<L, S> {
    pub fn new(storage: S, logging: L) -> Self {
        SplitwiseService { storage, logging }
    }

    pub async fn get_user(&self, user_id: &str) -> Result<Option<User>, SplitwiseError> {
        self.storage.get_user(user_id).await
    }

    pub async fn add_user(
        &self,
        user: User,
        created_by: Option<&User>,
    ) -> Result<(), SplitwiseError> {
        if user.email.is_empty() {
            return Err(SplitwiseError::MissingEmail);
        }
        if self.storage.get_user_by_email(&user.email).await?.is_some() {
            return Err(SplitwiseError::EmailAlreadyRegistered(user.email));
        }
        self.storage.save_user(user.clone()).await?;
        self.logging
            .log_action(
                USER_ADDED,
                json!({ "user_id": user.id, "name": user.name, "email": user.email }),
                created_by.map(|u| u.id.as_str()),
            )
            .await?;
        Ok(())
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, SplitwiseError> {
        self.storage.get_user_by_email(email).await
    }

    fn is_group_member(group: &Group, user_id: &str) -> bool {
        group.members.iter().any(|m| m.user.id == user_id)
    }

    pub async fn create_group(
        &self,
        name: String,
        members: Vec<User>,
        created_by: &User,
    ) -> Result<Group, SplitwiseError> {
        if self.storage.get_user(&created_by.id).await?.is_none() {
            return Err(SplitwiseError::UserNotFound(created_by.id.clone()));
        }
        let group_id = Uuid::new_v4().to_string();
        let join_link = Uuid::new_v4().to_string();
        let group = Group {
            id: group_id.clone(),
            name,
            members: members
                .into_iter()
                .enumerate()
                .map(|(i, user)| GroupMember {
                    user,
                    role: if i == 0 { Role::Owner } else { Role::Member },
                })
                .collect(),
            join_link,
            strict_settlement_mode: true,
        };
        self.validate_group_roles(&group)?;
        self.storage.save_group(group.clone()).await?;
        self.logging
            .log_action(
                GROUP_CREATED,
                json!({ "group_id": group.id, "name": group.name, "join_link": group.join_link }),
                Some(created_by.id.as_str()),
            )
            .await?;
        self.audit_action(
            &group.id,
            GROUP_CREATED,
            json!({ "name": group.name, "member_ids": group.members.iter().map(|m| m.user.id.clone()).collect::<Vec<_>>(), "join_link": group.join_link }),
            Some(created_by.id.as_str()),
        ).await?;
        Ok(group)
    }

    pub async fn add_member_to_group(
        &self,
        group_id: &str,
        user: User,
        added_by: &User,
    ) -> Result<(), SplitwiseError> {
        let mut group = self.get_group(group_id).await?;
        self.validate_user(&user.id).await?;
        self.validate_user(&added_by.id).await?;
        self.validate_owner(&group, &added_by.id)?;
        if group.members.iter().any(|m| m.user.id == user.id) {
            return Err(SplitwiseError::AlreadyGroupMember(user.id));
        }
        group.members.push(GroupMember {
            user: user.clone(),
            role: Role::Member,
        });
        self.storage.save_group(group.clone()).await?;
        self.audit_action(
            group_id,
            MEMBER_ADDED,
            json!({ "user_id": user.id, "name": user.name, "email": user.email }),
            Some(added_by.id.as_str()),
        )
        .await?;
        self.logging
            .log_action(
                MEMBER_ADDED,
                json!({ "group_id": group_id, "user_id": user.id, "email": user.email }),
                Some(added_by.id.as_str()),
            )
            .await?;
        Ok(())
    }

    pub async fn add_member_by_email(
        &self,
        group_id: &str,
        email: &str,
        added_by: &User,
    ) -> Result<(), SplitwiseError> {
        let mut group = self.get_group(group_id).await?;
        self.validate_user(&added_by.id).await?;
        self.validate_owner(&group, &added_by.id)?;
        let user = self
            .storage
            .get_user_by_email(email)
            .await?
            .ok_or_else(|| SplitwiseError::UserNotFound(email.to_string()))?;
        if group.members.iter().any(|m| m.user.id == user.id) {
            return Err(SplitwiseError::AlreadyGroupMember(email.to_string()));
        }
        group.members.push(GroupMember {
            user: user.clone(),
            role: Role::Member,
        });
        self.storage.save_group(group.clone()).await?;
        self.audit_action(
            group_id,
            MEMBER_ADDED,
            json!({ "user_id": user.id, "name": user.name, "email": user.email }),
            Some(added_by.id.as_str()),
        )
        .await?;
        self.logging
            .log_action(
                MEMBER_ADDED,
                json!({ "group_id": group_id, "user_id": user.id, "email": user.email }),
                Some(added_by.id.as_str()),
            )
            .await?;
        Ok(())
    }

    pub async fn remove_member_from_group(
        &self,
        group_id: &str,
        user_id: &str,
        removed_by: &User,
    ) -> Result<(), SplitwiseError> {
        let mut group = self.get_group(group_id).await?;
        self.validate_user(&removed_by.id).await?;
        self.validate_owner(&group, &removed_by.id)?;
        self.validate_user(user_id).await?;
        if user_id == removed_by.id {
            return Err(SplitwiseError::OwnerCannotRemoveSelf);
        }
        if group.members.len() <= 1 {
            return Err(SplitwiseError::CannotRemoveLastMember);
        }
        let user_opt = group.members.iter().find(|m| m.user.id == user_id).cloned();
        let user = user_opt.ok_or_else(|| SplitwiseError::NotGroupMember(user_id.to_string()))?;
        group.members.retain(|m| m.user.id != user_id);
        self.storage.save_group(group.clone()).await?;
        self.audit_action(
            group_id,
            MEMBER_REMOVED,
            json!({ "user_id": user_id, "name": user.user.name, "email": user.user.email }),
            Some(removed_by.id.as_str()),
        )
        .await?;
        self.logging
            .log_action(
                MEMBER_REMOVED,
                json!({ "group_id": group_id, "user_id": user_id, "email": user.user.email }),
                Some(removed_by.id.as_str()),
            )
            .await?;
        Ok(())
    }

    pub async fn join_group_by_link(
        &self,
        join_link: &str,
        user: &User,
    ) -> Result<(), SplitwiseError> {
        if join_link.is_empty() {
            return Err(SplitwiseError::InvalidJoinLink);
        }
        let mut group = self
            .storage
            .get_group_by_join_link(join_link)
            .await?
            .ok_or(SplitwiseError::JoinLinkNotFound)?;
        self.validate_user(&user.id).await?;
        if group.members.iter().any(|m| m.user.id == user.id) {
            return Err(SplitwiseError::AlreadyGroupMember(user.id.clone()));
        }
        group.members.push(GroupMember {
            user: user.clone(),
            role: Role::Member,
        });
        self.storage.save_group(group.clone()).await?;
        self.audit_action(
            &group.id,
            MEMBER_JOINED,
            json!({ "user_id": user.id, "name": user.name, "email": user.email, "join_link": join_link }),
            Some(user.id.as_str()),
        ).await?;
        self.logging.log_action(
            MEMBER_JOINED,
            json!({ "group_id": group.id, "user_id": user.id, "email": user.email, "join_link": join_link }),
            Some(user.id.as_str()),
        ).await?;
        Ok(())
    }

    pub async fn revoke_join_link(
        &self,
        group_id: &str,
        revoked_by: &User,
    ) -> Result<(), SplitwiseError> {
        let mut group = self.get_group(group_id).await?;
        self.validate_user(&revoked_by.id).await?;
        self.validate_owner(&group, &revoked_by.id)?;
        let old_link = group.join_link.clone();
        group.join_link = String::new();
        self.storage.revoke_join_link(&old_link).await?;
        self.storage.save_group(group.clone()).await?;
        self.audit_action(
            group_id,
            JOIN_LINK_REVOKED,
            json!({ "join_link": old_link }),
            Some(revoked_by.id.as_str()),
        )
        .await?;
        self.logging
            .log_action(
                JOIN_LINK_REVOKED,
                json!({ "group_id": group_id, "join_link": old_link }),
                Some(revoked_by.id.as_str()),
            )
            .await?;
        Ok(())
    }

    pub async fn regenerate_join_link(
        &self,
        group_id: &str,
        regenerated_by: &User,
    ) -> Result<String, SplitwiseError> {
        let mut group = self.get_group(group_id).await?;
        self.validate_user(&regenerated_by.id).await?;
        self.validate_owner(&group, &regenerated_by.id)?;
        let old_link = group.join_link.clone();
        let new_link = Uuid::new_v4().to_string();
        group.join_link = new_link.clone();
        self.storage.revoke_join_link(&old_link).await?;
        self.storage.save_group(group.clone()).await?;
        self.audit_action(
            group_id,
            JOIN_LINK_REGENERATED,
            json!({ "old_link": old_link, "new_link": new_link }),
            Some(regenerated_by.id.as_str()),
        )
        .await?;
        self.logging
            .log_action(
                JOIN_LINK_REGENERATED,
                json!({ "group_id": group_id, "old_link": old_link, "new_link": new_link }),
                Some(regenerated_by.id.as_str()),
            )
            .await?;
        Ok(new_link)
    }

    pub async fn toggle_strict_settlement_mode(
        &self,
        group_id: &str,
        enabled: bool,
        toggled_by: &User,
    ) -> Result<(), SplitwiseError> {
        let mut group = self.get_group(group_id).await?;
        self.validate_user(&toggled_by.id).await?;
        self.validate_owner(&group, &toggled_by.id)?;
        group.strict_settlement_mode = enabled;
        self.storage.save_group(group.clone()).await?;
        self.audit_action(
            group_id,
            STRICT_SETTLEMENT_MODE_TOGGLED,
            json!({ "enabled": enabled }),
            Some(toggled_by.id.as_str()),
        )
        .await?;
        self.logging
            .log_action(
                STRICT_SETTLEMENT_MODE_TOGGLED,
                json!({ "group_id": group_id, "enabled": enabled }),
                Some(toggled_by.id.as_str()),
            )
            .await?;
        Ok(())
    }

    pub async fn transfer_ownership(
        &self,
        group_id: &str,
        new_owner: &User,
        transferred_by: &User,
    ) -> Result<(), SplitwiseError> {
        let mut group = self.get_group(group_id).await?;
        self.validate_user(&new_owner.id).await?;
        self.validate_user(&transferred_by.id).await?;
        self.validate_owner(&group, &transferred_by.id)?;
        if !Self::is_group_member(&group, &new_owner.id) {
            return Err(SplitwiseError::NotGroupMember(new_owner.id.clone()));
        }
        group.members = group
            .members
            .into_iter()
            .map(|m| {
                let user_id = m.user.id.clone();
                GroupMember {
                    user: m.user,
                    role: if user_id == new_owner.id {
                        Role::Owner
                    } else if user_id == transferred_by.id {
                        Role::Member
                    } else {
                        m.role
                    },
                }
            })
            .collect();
        self.validate_group_roles(&group)?;
        self.storage.save_group(group.clone()).await?;
        self.audit_action(
            group_id,
            OWNERSHIP_TRANSFERRED,
            json!({ "old_owner_id": transferred_by.id, "new_owner_id": new_owner.id }),
            Some(transferred_by.id.as_str()),
        )
        .await?;
        self.logging.log_action(
            OWNERSHIP_TRANSFERRED,
            json!({ "group_id": group_id, "old_owner_id": transferred_by.id, "new_owner_id": new_owner.id }),
            Some(transferred_by.id.as_str()),
        ).await?;
        Ok(())
    }

    pub async fn add_expense(
        &self,
        group_id: &str,
        description: String,
        amount: f64,
        paid_by: User,
        shares: HashMap<String, f64>,
        created_by: &User,
    ) -> Result<Transaction, SplitwiseError> {
        let group = self.get_group(group_id).await?;
        self.validate_user(&paid_by.id).await?;
        self.validate_user(&created_by.id).await?;
        if !group.members.iter().any(|m| m.user.id == created_by.id) {
            return Err(SplitwiseError::NotGroupMember(created_by.id.clone()));
        }
        if !self.is_valid_split(amount, &shares) {
            return Err(SplitwiseError::InvalidSplit);
        }
        for user_id in shares.keys() {
            if !group.members.iter().any(|m| &m.user.id == user_id) {
                return Err(SplitwiseError::InvalidSplitUser(user_id.clone()));
            }
        }
        let transaction = Transaction {
            id: Uuid::new_v4().to_string(),
            group_id: group_id.to_string(),
            description,
            amount,
            paid_by,
            shares,
            timestamp: Utc::now(),
            is_reversed: false,
            reverses: None,
            reversed_by: None,
        };
        self.storage.save_transaction(transaction.clone()).await?;
        self.update_balances(&transaction).await?;
        self.logging.log_action(
            EXPENSE_ADDED,
            json!({ "transaction_id": transaction.id, "group_id": group_id, "description": transaction.description, "amount": transaction.amount }),
            Some(created_by.id.as_str()),
        ).await?;
        self.audit_action(
            group_id,
            EXPENSE_ADDED,
            json!({ "transaction_id": transaction.id, "description": transaction.description, "amount": transaction.amount, "paid_by_id": transaction.paid_by.id }),
            Some(created_by.id.as_str()),
        ).await?;
        Ok(transaction)
    }

    pub async fn reverse_transaction(
        &self,
        transaction_id: &str,
        reversed_by: &User,
    ) -> Result<Transaction, SplitwiseError> {
        let original = self
            .storage
            .get_transaction(transaction_id)
            .await?
            .ok_or_else(|| SplitwiseError::TransactionNotFound(transaction_id.to_string()))?;
        self.validate_user(&reversed_by.id).await?;
        let group_id_clone = original.group_id.clone();
        let group = self.get_group(&group_id_clone).await?;
        if !group.members.iter().any(|m| m.user.id == reversed_by.id) {
            return Err(SplitwiseError::NotGroupMember(reversed_by.id.clone()));
        }
        if original.reversed_by.is_some() {
            return Err(SplitwiseError::TransactionAlreadyReversed(
                transaction_id.to_string(),
            ));
        }
        let mut reversal_splits = HashMap::new();
        for (user_id, amount) in &original.shares {
            reversal_splits.insert(user_id.clone(), -amount);
        }
        let reversal = Transaction {
            id: Uuid::new_v4().to_string(),
            group_id: group_id_clone.clone(),
            description: format!("Reversal of: {}", original.description),
            amount: -original.amount,
            paid_by: original.paid_by.clone(),
            shares: reversal_splits,
            timestamp: Utc::now(),
            is_reversed: false,
            reverses: Some(transaction_id.to_string()),
            reversed_by: None,
        };
        self.storage
            .save_transaction(Transaction {
                is_reversed: true,
                reversed_by: Some(reversal.id.clone()),
                ..original
            })
            .await?;
        self.storage.save_transaction(reversal.clone()).await?;
        self.update_balances(&reversal).await?;
        self.logging
            .log_action(
                TRANSACTION_REVERSED,
                json!({ "transaction_id": transaction_id, "reversal_id": reversal.id }),
                Some(reversed_by.id.as_str()),
            )
            .await?;
        self.audit_action(
            &group_id_clone,
            TRANSACTION_REVERSED,
            json!({ "transaction_id": transaction_id, "reversal_id": reversal.id }),
            Some(reversed_by.id.as_str()),
        )
        .await?;
        Ok(reversal)
    }

    pub async fn create_settlement(
        &self,
        group_id: &str,
        from_user: &User,
        to_user: &User,
        amount: f64,
        remarks: Option<String>,
        transaction_ids: Option<Vec<String>>,
        created_by: &User,
    ) -> Result<Settlement, SplitwiseError> {
        let group = self.get_group(group_id).await?;
        self.validate_user(&created_by.id).await?;
        if !group.members.iter().any(|m| m.user.id == created_by.id) {
            return Err(SplitwiseError::NotGroupMember(created_by.id.clone()));
        }
        if !group.members.iter().any(|m| m.user.id == from_user.id) {
            return Err(SplitwiseError::NotGroupMember(from_user.id.clone()));
        }
        if !group.members.iter().any(|m| m.user.id == to_user.id) {
            return Err(SplitwiseError::NotGroupMember(to_user.id.clone()));
        }
        if from_user.id == to_user.id {
            return Err(SplitwiseError::SelfSettlement);
        }
        if amount <= 0.0 {
            return Err(SplitwiseError::InvalidSettlementAmount);
        }
        if let Some(tx_ids) = &transaction_ids {
            for tx_id in tx_ids {
                let tx =
                    self.storage.get_transaction(tx_id).await?.ok_or_else(|| {
                        SplitwiseError::InvalidSettlementTransaction(tx_id.clone())
                    })?;
                if tx.group_id != group_id {
                    return Err(SplitwiseError::InvalidSettlementTransaction(tx_id.clone()));
                }
            }
        }
        let settlement = Settlement {
            id: Uuid::new_v4().to_string(),
            group_id: group_id.to_string(),
            from_user_id: from_user.id.clone(),
            to_user_id: to_user.id.clone(),
            amount,
            remarks,
            transaction_ids,
            timestamp: Utc::now(),
            is_confirmed: !group.strict_settlement_mode,
            confirmed_by: if group.strict_settlement_mode {
                None
            } else {
                Some(to_user.id.clone())
            },
        };
        self.storage.save_settlement(settlement.clone()).await?;
        if !group.strict_settlement_mode {
            self.storage
                .save_balance(
                    &settlement.from_user_id,
                    &settlement.to_user_id,
                    -settlement.amount,
                )
                .await?;
            self.storage
                .save_balance(
                    &settlement.to_user_id,
                    &settlement.from_user_id,
                    settlement.amount,
                )
                .await?;
        }
        self.logging
            .log_action(
                SETTLEMENT_CREATED,
                json!({
                    "settlement_id": settlement.id,
                    "group_id": group_id,
                    "from_user_id": from_user.id,
                    "to_user_id": to_user.id,
                    "amount": amount,
                    "remarks": settlement.remarks,
                    "transaction_ids": settlement.transaction_ids,
                    "is_strict": group.strict_settlement_mode
                }),
                Some(created_by.id.as_str()),
            )
            .await?;
        self.audit_action(
            group_id,
            SETTLEMENT_CREATED,
            json!({
                "settlement_id": settlement.id,
                "from_user_id": from_user.id,
                "to_user_id": to_user.id,
                "amount": amount,
                "remarks": settlement.remarks,
                "transaction_ids": settlement.transaction_ids,
                "is_strict": group.strict_settlement_mode
            }),
            Some(created_by.id.as_str()),
        )
        .await?;
        Ok(settlement)
    }

    pub async fn confirm_settlement(
        &self,
        settlement_id: &str,
        confirmed_by: &User,
    ) -> Result<(), SplitwiseError> {
        self.validate_user(&confirmed_by.id).await?;
        let mut settlement = self
            .storage
            .get_settlement(settlement_id)
            .await?
            .ok_or_else(|| SplitwiseError::SettlementNotFound(settlement_id.to_string()))?;
        if settlement.is_confirmed {
            return Err(SplitwiseError::SettlementAlreadyConfirmed(
                settlement_id.to_string(),
            ));
        }
        if settlement.to_user_id != confirmed_by.id {
            return Err(SplitwiseError::UnauthorizedSettlementConfirmation(
                confirmed_by.id.clone(),
            ));
        }
        settlement.is_confirmed = true;
        settlement.confirmed_by = Some(confirmed_by.id.clone());
        self.storage.save_settlement(settlement.clone()).await?;
        self.storage
            .save_balance(
                &settlement.from_user_id,
                &settlement.to_user_id,
                -settlement.amount,
            )
            .await?;
        self.storage
            .save_balance(
                &settlement.to_user_id,
                &settlement.from_user_id,
                settlement.amount,
            )
            .await?;
        self.logging
            .log_action(
                SETTLEMENT_CONFIRMED,
                json!({ "settlement_id": settlement_id, "group_id": settlement.group_id }),
                Some(confirmed_by.id.as_str()),
            )
            .await?;
        self.audit_action(
            &settlement.group_id,
            SETTLEMENT_CONFIRMED,
            json!({ "settlement_id": settlement_id, "from_user_id": settlement.from_user_id, "to_user_id": settlement.to_user_id }),
            Some(confirmed_by.id.as_str()),
        ).await?;
        Ok(())
    }

    pub async fn get_pending_settlements(
        &self,
        group_id: &str,
        user: &User,
    ) -> Result<Vec<Settlement>, SplitwiseError> {
        let group = self.get_group(group_id).await?;
        self.validate_user(&user.id).await?;
        if !group.members.iter().any(|m| m.user.id == user.id) {
            return Err(SplitwiseError::NotGroupMember(user.id.clone()));
        }
        let settlements = self
            .storage
            .get_pending_settlements(group_id, &user.id)
            .await?;
        self.logging
            .log_action(
                PENDING_SETTLEMENTS_QUERIED,
                json!({ "group_id": group_id, "user_id": user.id, "count": settlements.len() }),
                Some(user.id.as_str()),
            )
            .await?;
        Ok(settlements)
    }

    pub async fn get_user_balances(
        &self,
        user_id: &str,
        queried_by: &User,
    ) -> Result<Vec<Balance>, SplitwiseError> {
        self.validate_user(user_id).await?;
        self.validate_user(&queried_by.id).await?;
        let balances = self.storage.get_balances(user_id).await?;
        self.logging
            .log_action(
                BALANCE_QUERIED,
                json!({ "user_id": user_id, "balances_count": balances.len() }),
                Some(queried_by.id.as_str()),
            )
            .await?;
        Ok(balances)
    }

    pub async fn get_effective_transactions(
        &self,
        group_id: &str,
        queried_by: &User,
    ) -> Result<Vec<Transaction>, SplitwiseError> {
        let group = self.get_group(group_id).await?;
        self.validate_user(&queried_by.id).await?;
        if !group.members.iter().any(|m| m.user.id == queried_by.id) {
            return Err(SplitwiseError::NotGroupMember(queried_by.id.clone()));
        }
        let transactions: Vec<Transaction> = self
            .storage
            .get_transactions_by_group(group_id)
            .await?
            .into_iter()
            .filter(|tx| !tx.is_reversed)
            .collect();
        self.logging
            .log_action(
                TRANSACTIONS_QUERIED,
                json!({ "group_id": group_id, "transactions_count": transactions.len() }),
                Some(queried_by.id.as_str()),
            )
            .await?;
        Ok(transactions)
    }

    pub async fn get_app_logs(&self) -> Result<Vec<AppLog>, SplitwiseError> {
        self.logging.get_logs().await
    }

    pub async fn get_group_audits(
        &self,
        group_id: &str,
    ) -> Result<Vec<GroupAudit>, SplitwiseError> {
        self.storage.get_group_audits(group_id).await
    }

    async fn update_balances(&self, transaction: &Transaction) -> Result<(), SplitwiseError> {
        for (user_id, amount) in &transaction.shares {
            if user_id != &transaction.paid_by.id {
                self.storage
                    .save_balance(user_id, &transaction.paid_by.id, *amount)
                    .await?;
                self.storage
                    .save_balance(&transaction.paid_by.id, user_id, -amount)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn get_group_members(
        &self,
        group_id: &str,
    ) -> Result<Vec<GroupMember>, SplitwiseError> {
        let group = self.get_group(group_id).await?;
        Ok(group.members.clone())
    }

    async fn get_group(&self, group_id: &str) -> Result<Group, SplitwiseError> {
        self.storage
            .get_group(group_id)
            .await?
            .ok_or_else(|| SplitwiseError::GroupNotFound(group_id.to_string()))
    }

    async fn validate_user(&self, user_id: &str) -> Result<(), SplitwiseError> {
        if self.storage.get_user(user_id).await?.is_none() {
            return Err(SplitwiseError::UserNotFound(user_id.to_string()));
        }
        Ok(())
    }

    fn validate_owner(&self, group: &Group, user_id: &str) -> Result<(), SplitwiseError> {
        if !group
            .members
            .iter()
            .any(|m| m.user.id == user_id && m.role == Role::Owner)
        {
            return Err(SplitwiseError::NotGroupOwner(user_id.to_string()));
        }
        Ok(())
    }

    fn validate_group_roles(&self, group: &Group) -> Result<(), SplitwiseError> {
        let owner_count = group
            .members
            .iter()
            .filter(|m| m.role == Role::Member)
            .count();
        if owner_count != 1 {
            return Err(SplitwiseError::InvalidOwnerCount(owner_count));
        }
        Ok(())
    }

    async fn audit_action(
        &self,
        group_id: &str,
        action: &str,
        details: serde_json::Value,
        user_id: Option<&str>,
    ) -> Result<(), SplitwiseError> {
        self.storage
            .save_group_audit(GroupAudit {
                id: Uuid::new_v4().to_string(),
                group_id: group_id.to_string(),
                action: action.to_string(),
                user_id: user_id.map(String::from),
                details: serde_json::from_value(details).unwrap_or_default(),
                timestamp: Utc::now(),
            })
            .await
    }
}
