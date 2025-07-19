use crate::constants::*;
use crate::error::{FieldError, SplitwiseError};
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
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Serialize, Debug)]
pub struct UserBalancesResponse {
    circular_balances: Vec<Balance>,
    minimized_balances: Vec<Balance>,
}

impl UserBalancesResponse {
    pub fn circular_balances(&self) -> &Vec<Balance> {
        &self.circular_balances
    }

    pub fn minimized_balances(&self) -> &Vec<Balance> {
        &self.minimized_balances
    }
}

pub struct SplitwiseService<L: LoggingService, S: Storage> {
    storage: S,
    logging: L,
}

impl<L: LoggingService, S: Storage> SplitwiseService<L, S> {
    pub fn new(storage: S, logging: L) -> Self {
        SplitwiseService { storage, logging }
    }

    // Helper: Validate multiple users exist
    async fn validate_users(&self, user_ids: &[&str]) -> Result<(), SplitwiseError> {
        for &user_id in user_ids {
            if self.storage.get_user(user_id).await?.is_none() {
                return Err(SplitwiseError::UserNotFound(user_id.to_string()));
            }
        }
        Ok(())
    }

    // Helper: Validate group exists and user is owner
    async fn validate_group_and_owner(&self, group_id: &str, owner_id: &str) -> Result<Group, SplitwiseError> {
        let group = self
            .storage
            .get_group(group_id)
            .await?
            .ok_or_else(|| SplitwiseError::GroupNotFound(group_id.to_string()))?;
        if !group
            .members
            .iter()
            .any(|m| m.user.id == owner_id && m.role == Role::Owner)
        {
            return Err(SplitwiseError::NotGroupOwner(owner_id.to_string()));
        }
        Ok(group)
    }

    // Helper: Validate user is a group member
    async fn validate_group_membership(&self, group_id: &str, user_id: &str) -> Result<Group, SplitwiseError> {
        let group = self
            .storage
            .get_group(group_id)
            .await?
            .ok_or_else(|| SplitwiseError::GroupNotFound(group_id.to_string()))?;
        if !group.members.iter().any(|m| m.user.id == *user_id) {
            return Err(SplitwiseError::NotGroupMember(user_id.to_string()));
        }
        Ok(group)
    }

    // Helper: Combine logging and auditing
    async fn log_and_audit(
        &self,
        group_id: Option<&str>,
        action: &str,
        log_details: serde_json::Value,
        user_id: Option<&str>,
    ) -> Result<(), SplitwiseError> {
        self.logging.log_action(action, log_details.clone(), user_id).await?;
        if let Some(gid) = group_id {
            self.storage
                .save_group_audit(GroupAudit {
                    id: Uuid::new_v4().to_string(),
                    group_id: gid.to_string(),
                    action: action.to_string(),
                    user_id: user_id.map(String::from),
                    details: serde_json::from_value(log_details).unwrap_or_default(),
                    timestamp: Utc::now(),
                })
                .await?;
        }
        Ok(())
    }

    // Helper: Validate string input (e.g., name, description, remarks)
    fn validate_string_input(&self, field: &str, value: &str, max_length: usize) -> Result<(), SplitwiseError> {
        if value.trim().is_empty() {
            return Err(SplitwiseError::InvalidInput(
                field.to_string(),
                FieldError {
                    field: field.to_string(),
                    title: format!("Invalid {}", field),
                    description: format!("{} cannot be empty", field),
                },
            ));
        }
        if value.len() > max_length {
            return Err(SplitwiseError::InvalidInput(
                field.to_string(),
                FieldError {
                    field: field.to_string(),
                    title: format!("{} Too Long", field),
                    description: format!("{} cannot exceed {} characters", field, max_length),
                },
            ));
        }
        // Sanitize: reject control characters or potentially harmful characters
        if value.chars().any(|c| c.is_control() || "<>{}\\[\\]".contains(c)) {
            return Err(SplitwiseError::InvalidInput(
                field.to_string(),
                FieldError {
                    field: field.to_string(),
                    title: format!("Invalid {}", field),
                    description: format!("{} contains invalid characters", field),
                },
            ));
        }
        Ok(())
    }

    // Helper: Validate amount input (e.g., transaction or settlement amount)
    fn validate_amount_input(&self, field: &str, amount: f64) -> Result<(), SplitwiseError> {
        if amount <= 0.0 {
            return Err(SplitwiseError::InvalidInput(
                field.to_string(),
                FieldError {
                    field: field.to_string(),
                    title: "Invalid Amount".to_string(),
                    description: "Amount must be greater than 0".to_string(),
                },
            ));
        }
        if amount > 1_000_000.0 {
            return Err(SplitwiseError::InvalidInput(
                field.to_string(),
                FieldError {
                    field: field.to_string(),
                    title: "Amount Too Large".to_string(),
                    description: "Amount cannot exceed 1,000,000".to_string(),
                },
            ));
        }
        if !amount.is_finite() {
            return Err(SplitwiseError::InvalidInput(
                field.to_string(),
                FieldError {
                    field: field.to_string(),
                    title: "Invalid Amount".to_string(),
                    description: "Amount must be a finite number".to_string(),
                },
            ));
        }
        if (amount * 100.0).fract() != 0.0 {
            return Err(SplitwiseError::InvalidInput(
                field.to_string(),
                FieldError {
                    field: field.to_string(),
                    title: "Invalid Amount".to_string(),
                    description: "Amount cannot have more than 2 decimal places".to_string(),
                },
            ));
        }
        Ok(())
    }

    pub async fn get_user(&self, user_id: &str) -> Result<Option<User>, SplitwiseError> {
        self.storage.get_user(user_id).await
    }

    pub async fn add_user(&self, user: User, created_by: Option<&User>) -> Result<User, SplitwiseError> {
        // Enhanced email validation
        if user.email.is_empty() {
            return Err(SplitwiseError::MissingEmail);
        }
        if !user.email.contains('@') || !user.email.contains('.') || user.email.len() < 5 {
            return Err(SplitwiseError::InvalidEmail(user.email.clone()));
        }

        // Name validation
        self.validate_string_input("name", &user.name, 100)?;

        let new_user = self.storage.create_user_if_not_exists(user.clone()).await?;
        if !new_user.id.is_empty() {
            self.log_and_audit(
                None,
                USER_ADDED,
                json!({ "user_id": user.id, "name": user.name, "email": user.email }),
                created_by.map(|u| u.id.as_str()),
            )
            .await?;
            Ok(new_user)
        } else {
            Err(SplitwiseError::EmailAlreadyRegistered(user.email))
        }
    }

    pub async fn create_group(
        &self,
        name: String,
        members: Vec<User>,
        created_by: &User,
    ) -> Result<Group, SplitwiseError> {
        self.validate_users(&[&created_by.id]).await?;
        self.validate_string_input("name", &name, 100)?;

        // Ensure created_by is included in members list
        let mut all_members = members;
        if !all_members.iter().any(|m| m.id == created_by.id) {
            all_members.push(created_by.clone());
        }

        // Validate all members exist
        self.validate_users(&all_members.iter().map(|m| m.id.as_str()).collect::<Vec<_>>())
            .await?;

        let group_id = Uuid::new_v4().to_string();
        let join_link = Uuid::new_v4().to_string();
        let group_members = all_members
            .into_iter()
            .map(|user| GroupMember {
                role: if user.id == created_by.id {
                    Role::Owner
                } else {
                    Role::Member
                },
                user,
            })
            .collect();

        let group = Group {
            id: group_id.clone(),
            name,
            members: group_members,
            join_link,
            strict_settlement_mode: true,
        };

        self.validate_group_roles(&group)?;
        self.storage.save_group(group.clone()).await?;

        self.log_and_audit(
            Some(&group.id),
            GROUP_CREATED,
            json!({
                "group_id": group.id,
                "name": group.name,
                "join_link": group.join_link,
                "member_ids": group.members.iter().map(|m| m.user.id.clone()).collect::<Vec<_>>()
            }),
            Some(created_by.id.as_str()),
        )
        .await?;

        Ok(group)
    }

    pub async fn delete_group(&self, group_id: &str, deleted_by: &User) -> Result<(), SplitwiseError> {
        let group = self.validate_group_and_owner(group_id, &deleted_by.id).await?;
        self.storage.revoke_join_link(&group.join_link).await?;
        self.storage.delete_group(group_id).await?;

        self.log_and_audit(
            Some(group_id),
            GROUP_DELETED,
            json!({ "group_id": group_id, "name": group.name }),
            Some(deleted_by.id.as_str()),
        )
        .await?;
        Ok(())
    }

    pub async fn add_member_to_group(&self, group_id: &str, user: User, added_by: &User) -> Result<(), SplitwiseError> {
        let mut group = self.validate_group_and_owner(group_id, &added_by.id).await?;
        self.validate_users(&[&user.id]).await?;

        if group.members.iter().any(|m| m.user.id == user.id) {
            return Err(SplitwiseError::AlreadyGroupMember(user.id));
        }

        group.members.push(GroupMember {
            user: user.clone(),
            role: Role::Member,
        });
        self.storage.save_group(group.clone()).await?;

        self.log_and_audit(
            Some(group_id),
            MEMBER_ADDED,
            json!({ "group_id": group_id, "user_id": user.id, "name": user.name, "email": user.email }),
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
        let mut group = self.validate_group_and_owner(group_id, &added_by.id).await?;
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

        self.log_and_audit(
            Some(group_id),
            MEMBER_ADDED,
            json!({ "group_id": group_id, "user_id": user.id, "name": user.name, "email": user.email }),
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
        let mut group = self.validate_group_and_owner(group_id, &removed_by.id).await?;
        self.validate_users(&[user_id]).await?;

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

        self.log_and_audit(
            Some(group_id),
            MEMBER_REMOVED,
            json!({ "group_id": group_id, "user_id": user_id, "name": user.user.name, "email": user.user.email }),
            Some(removed_by.id.as_str()),
        )
        .await?;
        Ok(())
    }

    pub async fn join_group_by_link(&self, join_link: &str, user: &User) -> Result<(), SplitwiseError> {
        self.validate_string_input("join_link", join_link, 100)?;
        let mut group = self
            .storage
            .get_group_by_join_link(join_link)
            .await?
            .ok_or(SplitwiseError::JoinLinkNotFound)?;
        self.validate_users(&[&user.id]).await?;

        if group.members.iter().any(|m| m.user.id == user.id) {
            return Err(SplitwiseError::AlreadyGroupMember(user.id.clone()));
        }

        group.members.push(GroupMember {
            user: user.clone(),
            role: Role::Member,
        });
        self.storage.save_group(group.clone()).await?;

        self.log_and_audit(
            Some(&group.id),
            MEMBER_JOINED,
            json!({ "group_id": group.id, "user_id": user.id, "name": user.name, "email": user.email, "join_link": join_link }),
            Some(user.id.as_str()),
        )
        .await?;
        Ok(())
    }

    pub async fn revoke_join_link(&self, group_id: &str, revoked_by: &User) -> Result<(), SplitwiseError> {
        let mut group = self.validate_group_and_owner(group_id, &revoked_by.id).await?;
        let old_link = group.join_link.clone();
        group.join_link = String::from("REVOKED");
        self.storage.revoke_join_link(&old_link).await?;
        self.storage.save_group(group.clone()).await?;

        self.log_and_audit(
            Some(group_id),
            JOIN_LINK_REVOKED,
            json!({ "group_id": group_id, "join_link": old_link }),
            Some(revoked_by.id.as_str()),
        )
        .await?;
        Ok(())
    }

    pub async fn regenerate_join_link(&self, group_id: &str, regenerated_by: &User) -> Result<String, SplitwiseError> {
        let mut group = self.validate_group_and_owner(group_id, &regenerated_by.id).await?;
        let old_link = group.join_link.clone();
        let new_link = Uuid::new_v4().to_string();
        group.join_link = new_link.clone();
        self.storage.revoke_join_link(&old_link).await?;
        self.storage.save_group(group.clone()).await?;

        self.log_and_audit(
            Some(group_id),
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
        let mut group = self.validate_group_and_owner(group_id, &toggled_by.id).await?;
        group.strict_settlement_mode = enabled;
        self.storage.save_group(group.clone()).await?;

        self.log_and_audit(
            Some(group_id),
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
        let mut group = self.validate_group_and_owner(group_id, &transferred_by.id).await?;
        self.validate_users(&[&new_owner.id]).await?;

        if !self.storage.is_group_member(&group.id, &new_owner.id).await? {
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

        self.log_and_audit(
            Some(group_id),
            OWNERSHIP_TRANSFERRED,
            json!({ "group_id": group_id, "old_owner_id": transferred_by.id, "new_owner_id": new_owner.id }),
            Some(transferred_by.id.as_str()),
        )
        .await?;
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
        let group = self.validate_group_membership(group_id, &created_by.id).await?;
        self.validate_users(&[&paid_by.id]).await?;
        self.validate_string_input("description", &description, 500)?;
        self.validate_amount_input("amount", amount)?;

        if !group.members.iter().any(|m| m.user.id == paid_by.id) {
            return Err(SplitwiseError::NotGroupMember(paid_by.id.clone()));
        }

        if !self.is_valid_split(amount, &shares) {
            return Err(SplitwiseError::InvalidInput(
                "shares".to_string(),
                FieldError {
                    field: "shares".to_string(),
                    title: "Invalid Split".to_string(),
                    description: "Sum of shares must equal the total amount".to_string(),
                },
            ));
        }

        for user_id in shares.keys() {
            if !group.members.iter().any(|m| m.user.id == *user_id) {
                return Err(SplitwiseError::InvalidSplitUser(user_id.clone()));
            }
        }

        let transaction = Transaction {
            id: Uuid::new_v4().to_string(),
            group_id: group_id.to_string(),
            description: description.trim().to_string(),
            amount,
            paid_by,
            shares,
            timestamp: Utc::now(),
            is_reversed: false,
            reverses: None,
            reversed_by: None,
        };

        self.storage.save_transaction(transaction.clone()).await?;

        self.log_and_audit(
            Some(group_id),
            EXPENSE_ADDED,
            json!({
                "transaction_id": transaction.id,
                "group_id": group_id,
                "description": transaction.description,
                "amount": transaction.amount,
                "paid_by_id": transaction.paid_by.id
            }),
            Some(created_by.id.as_str()),
        )
        .await?;

        Ok(transaction)
    }

    pub async fn get_transaction(&self, transaction_id: &str) -> Result<Option<Transaction>, SplitwiseError> {
        self.storage.get_transaction(transaction_id).await
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

        self.validate_users(&[&reversed_by.id]).await?;
        let _group = self
            .validate_group_membership(&original.group_id, &reversed_by.id)
            .await?;

        if original.reversed_by.is_some() {
            return Err(SplitwiseError::TransactionAlreadyReversed(transaction_id.to_string()));
        }

        let mut reversal_shares = HashMap::new();
        for (user_id, amount) in &original.shares {
            reversal_shares.insert(user_id.clone(), -amount);
        }

        let original_group_id = original.group_id.clone();
        let reversal = Transaction {
            id: Uuid::new_v4().to_string(),
            group_id: original_group_id.clone(),
            description: format!("Reversal of: {}", original.description),
            amount: -original.amount,
            paid_by: original.paid_by.clone(),
            shares: reversal_shares,
            timestamp: Utc::now(),
            is_reversed: false,
            reverses: Some(transaction_id.to_string()),
            reversed_by: None,
        };

        let updated_original = Transaction {
            is_reversed: true,
            reversed_by: Some(reversal.id.clone()),
            ..original
        };

        self.storage.save_transaction(updated_original).await?;
        self.storage.save_transaction(reversal.clone()).await?;

        self.log_and_audit(
            Some(&original_group_id),
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
        let group = self.validate_group_membership(group_id, &created_by.id).await?;
        self.validate_users(&[&from_user.id, &to_user.id]).await?;

        if from_user.id == to_user.id {
            return Err(SplitwiseError::SelfSettlement);
        }

        self.validate_amount_input("amount", amount)?;

        if let Some(ref remarks_text) = remarks {
            self.validate_string_input("remarks", remarks_text, 500)?;
        }

        if let Some(tx_ids) = &transaction_ids {
            for tx_id in tx_ids {
                let tx = self
                    .storage
                    .get_transaction(tx_id)
                    .await?
                    .ok_or_else(|| SplitwiseError::InvalidSettlementTransaction(tx_id.clone()))?;
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
            remarks: remarks.map(|r| r.trim().to_string()),
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

        self.log_and_audit(
            Some(group_id),
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

        Ok(settlement)
    }

    pub async fn confirm_settlement(&self, settlement_id: &str, confirmed_by: &User) -> Result<(), SplitwiseError> {
        self.validate_users(&[&confirmed_by.id]).await?;
        let mut settlement = self
            .storage
            .get_settlement(settlement_id)
            .await?
            .ok_or_else(|| SplitwiseError::SettlementNotFound(settlement_id.to_string()))?;

        if settlement.is_confirmed {
            return Err(SplitwiseError::SettlementAlreadyConfirmed(settlement_id.to_string()));
        }
        if settlement.to_user_id != confirmed_by.id {
            return Err(SplitwiseError::UnauthorizedSettlementConfirmation(
                confirmed_by.id.clone(),
            ));
        }

        settlement.is_confirmed = true;
        settlement.confirmed_by = Some(confirmed_by.id.clone());
        self.storage.save_settlement(settlement.clone()).await?;

        self.log_and_audit(
            Some(&settlement.group_id),
            SETTLEMENT_CONFIRMED,
            json!({ "settlement_id": settlement_id, "from_user_id": settlement.from_user_id, "to_user_id": settlement.to_user_id }),
            Some(confirmed_by.id.as_str()),
        )
        .await?;
        Ok(())
    }

    pub async fn get_pending_settlements(
        &self,
        group_id: &str,
        user: &User,
    ) -> Result<Vec<Settlement>, SplitwiseError> {
        let _group = self.validate_group_membership(group_id, &user.id).await?;
        let settlements = self.storage.get_pending_settlements(group_id, &user.id).await?;

        self.log_and_audit(
            Some(group_id),
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
    ) -> Result<UserBalancesResponse, SplitwiseError> {
        // For production: Cache results
        /*
        let cache_key = format!("balances:{}", user_id);
        if let Some(cached) = self.redis.get(&cache_key).await? {
            return Ok(cached);
        }
        */

        self.validate_users(&[user_id, &queried_by.id]).await?;

        let transactions = self.storage.get_transactions_by_user(user_id).await?;
        let settlements = self.storage.get_settlements_by_user(user_id).await?;
        let mut balances: HashMap<String, f64> = HashMap::new();

        // Process transactions - only non-reversed ones
        for tx in transactions.iter().filter(|t| !t.is_reversed) {
            // If user is in the split, they owe money to the payer
            if let Some(amount) = tx.shares.get(user_id) {
                if tx.paid_by.id != user_id {
                    *balances.entry(tx.paid_by.id.clone()).or_insert(0.0) += amount;
                }
            }

            // If user paid, others owe them
            if tx.paid_by.id == user_id {
                for (uid, amount) in &tx.shares {
                    if uid != user_id {
                        *balances.entry(uid.clone()).or_insert(0.0) -= amount;
                    }
                }
            }
        }

        // Process confirmed settlements
        for settlement in settlements.iter().filter(|s| s.is_confirmed) {
            if settlement.from_user_id == user_id {
                // User paid someone - reduces what they owe them
                *balances.entry(settlement.to_user_id.clone()).or_insert(0.0) -= settlement.amount;
            } else if settlement.to_user_id == user_id {
                // User received payment - reduces what someone owes them
                *balances.entry(settlement.from_user_id.clone()).or_insert(0.0) += settlement.amount;
            }
        }

        // Convert to Balance objects, filtering negligible amounts
        let circular_balances = balances
            .iter()
            .filter(|(_, amount)| amount.abs() >= 0.01)
            .map(|(owes_to, amount)| Balance {
                user_id: user_id.to_string(),
                owes_to: owes_to.clone(),
                amount: *amount,
            })
            .collect::<Vec<Balance>>();

        // Minimize debts
        let minimized_balances = self.minimize_debts_for_user(user_id, &circular_balances);

        // Cache results for future queries
        /*
        self.redis.set(&cache_key, &UserBalancesResponse {
            circular_balances: circular_balances.clone(),
            minimized_balances: minimized_balances.clone(),
        }, 3600).await?;
        */

        self.log_and_audit(
            None,
            BALANCE_QUERIED,
            json!({
                "user_id": user_id,
                "circular_count": circular_balances.len(),
                "minimized_count": minimized_balances.len()
            }),
            Some(queried_by.id.as_str()),
        )
        .await?;

        Ok(UserBalancesResponse {
            circular_balances,
            minimized_balances,
        })
    }

    fn minimize_debts_for_user(&self, user_id: &str, balances: &[Balance]) -> Vec<Balance> {
        let mut result = balances.to_vec();
        let mut modified = true;

        // Perform pairwise debt reduction until no further reductions are possible
        while modified {
            modified = false;
            for i in 0..result.len() {
                for j in 0..result.len() {
                    if i == j {
                        continue;
                    }
                    // Check for circular debt: user_id owes A, and A owes user_id
                    if result[i].owes_to != user_id && result[j].user_id == user_id && result[j].owes_to == user_id {
                        let amount_i = result[i].amount;
                        let amount_j = result[j].amount;
                        if amount_i > 0.01 && amount_j < -0.01 {
                            let reduction = amount_i.min(amount_j.abs());
                            result[i].amount -= reduction;
                            result[j].amount += reduction;
                            modified = true;
                        }
                    }
                }
            }
        }

        // Filter out negligible amounts
        result.into_iter().filter(|b| b.amount.abs() >= 0.01).collect()
    }

    fn is_valid_split(&self, amount: f64, shares: &HashMap<String, f64>) -> bool {
        if shares.is_empty() {
            return false;
        }
        for share in shares.values() {
            if *share < 0.0 || !share.is_finite() {
                return false;
            }
        }
        let total: f64 = shares.values().sum();
        let rounded_amount = (amount * 100.0).round() / 100.0;
        let rounded_total = (total * 100.0).round() / 100.0;
        (rounded_total - rounded_amount).abs() < 0.005
    }

    pub async fn get_effective_transactions(
        &self,
        group_id: &str,
        queried_by: &User,
    ) -> Result<Vec<Transaction>, SplitwiseError> {
        let _group = self.validate_group_membership(group_id, &queried_by.id).await?;
        let transactions: Vec<Transaction> = self
            .storage
            .get_transactions_by_group(group_id)
            .await?
            .into_iter()
            .filter(|tx| !tx.is_reversed)
            .collect();

        self.log_and_audit(
            Some(group_id),
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

    pub async fn get_group_audits(&self, group_id: &str) -> Result<Vec<GroupAudit>, SplitwiseError> {
        self.storage.get_group_audits(group_id).await
    }

    pub async fn get_group_members(&self, group_id: &str) -> Result<Vec<GroupMember>, SplitwiseError> {
        let group = self
            .storage
            .get_group(group_id)
            .await?
            .ok_or_else(|| SplitwiseError::GroupNotFound(group_id.to_string()))?;
        Ok(group.members.clone())
    }

    pub async fn get_group(&self, group_id: &str) -> Result<Group, SplitwiseError> {
        self.storage
            .get_group(group_id)
            .await?
            .ok_or_else(|| SplitwiseError::GroupNotFound(group_id.to_string()))
    }

    fn validate_group_roles(&self, group: &Group) -> Result<(), SplitwiseError> {
        let owner_count = group.members.iter().filter(|m| m.role == Role::Owner).count();
        if owner_count != 1 {
            return Err(SplitwiseError::InvalidOwnerCount(owner_count));
        }
        Ok(())
    }
}
