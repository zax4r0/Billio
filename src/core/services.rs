use crate::auth::jwt::{Claims, JwtService};
use crate::constants::constants::{
    BALANCE_QUERIED, EXPENSE_ADDED, GROUP_CREATED, GROUP_DELETED, JOIN_LINK_REGENERATED, JOIN_LINK_REVOKED,
    MEMBER_ADDED, MEMBER_JOINED, MEMBER_REMOVED, OWNERSHIP_TRANSFERRED, PENDING_SETTLEMENTS_QUERIED,
    SETTLEMENT_CONFIRMED, SETTLEMENT_CREATED, STRICT_SETTLEMENT_MODE_TOGGLED, TRANSACTION_REVERSED,
    TRANSACTIONS_QUERIED, USER_ADDED,
};
use crate::core::errors::{BillioError, FieldError};
use crate::core::models::{
    audit::{AppLog, GroupAudit},
    group::{Group, GroupMember, Role},
    settlement::Settlement,
    transaction::Transaction,
    transaction_split::Balance,
    user::User,
};
use crate::infrastructure::cache::Cache;
use crate::infrastructure::logging::LoggingService;
use crate::infrastructure::storage::Storage;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, ToSchema, Clone)]
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

pub struct BillioService<L: LoggingService, S: Storage, C: Cache> {
    storage: S,
    logging: L,
    cache: C,
    jwt_service: JwtService, // Added for JWT
}

impl<L: LoggingService, S: Storage, C: Cache> BillioService<L, S, C> {
    pub fn new(storage: S, logging: L, cache: C, jwt_secret: String) -> Self {
        BillioService {
            storage,
            logging,
            cache,
            jwt_service: JwtService::new(jwt_secret),
        }
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, BillioError> {
        self.jwt_service.validate_token(token)
    }

    pub async fn validate_users(&self, user_ids: &[&str]) -> Result<(), BillioError> {
        for &user_id in user_ids {
            if self.storage.get_user(user_id).await?.is_none() {
                return Err(BillioError::UserNotFound(user_id.to_string()));
            }
        }
        Ok(())
    }

    async fn validate_group_and_owner(&self, group_id: &str, owner_id: &str) -> Result<Group, BillioError> {
        let group = self
            .storage
            .get_group(group_id)
            .await?
            .ok_or_else(|| BillioError::GroupNotFound(group_id.to_string()))?;
        if !group
            .members
            .iter()
            .any(|m| m.user.id == owner_id && m.role == Role::Owner)
        {
            return Err(BillioError::NotGroupOwner(owner_id.to_string()));
        }
        Ok(group)
    }

    async fn validate_group_membership(&self, group_id: &str, user_id: &str) -> Result<Group, BillioError> {
        let group = self
            .storage
            .get_group(group_id)
            .await?
            .ok_or_else(|| BillioError::GroupNotFound(group_id.to_string()))?;
        if !group.members.iter().any(|m| m.user.id == *user_id) {
            return Err(BillioError::NotGroupMember(user_id.to_string()));
        }
        Ok(group)
    }

    async fn log_and_audit(
        &self,
        group_id: Option<&str>,
        action: &str,
        log_details: serde_json::Value,
        user_id: Option<&str>,
    ) -> Result<(), BillioError> {
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

    fn validate_string_input(&self, field: &str, value: &str, max_length: usize) -> Result<(), BillioError> {
        if value.trim().is_empty() {
            return Err(BillioError::InvalidInput(
                field.to_string(),
                FieldError {
                    field: field.to_string(),
                    title: format!("Invalid {}", field),
                    description: format!("{} cannot be empty", field),
                },
            ));
        }
        if value.len() > max_length {
            return Err(BillioError::InvalidInput(
                field.to_string(),
                FieldError {
                    field: field.to_string(),
                    title: format!("{} Too Long", field),
                    description: format!("{} cannot exceed {} characters", field, max_length),
                },
            ));
        }
        if value.chars().any(|c| c.is_control() || "<>{}[]".contains(c)) {
            return Err(BillioError::InvalidInput(
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

    fn validate_amount_input(&self, field: &str, amount: f64) -> Result<(), BillioError> {
        if amount <= 0.0 {
            return Err(BillioError::InvalidInput(
                field.to_string(),
                FieldError {
                    field: field.to_string(),
                    title: "Invalid Amount".to_string(),
                    description: "Amount must be greater than 0".to_string(),
                },
            ));
        }
        if amount > 1_000_000.0 {
            return Err(BillioError::InvalidInput(
                field.to_string(),
                FieldError {
                    field: field.to_string(),
                    title: "Amount Too Large".to_string(),
                    description: "Amount cannot exceed 1,000,000".to_string(),
                },
            ));
        }
        if !amount.is_finite() {
            return Err(BillioError::InvalidInput(
                field.to_string(),
                FieldError {
                    field: field.to_string(),
                    title: "Invalid Amount".to_string(),
                    description: "Amount must be a finite number".to_string(),
                },
            ));
        }
        if (amount * 100.0).fract() != 0.0 {
            return Err(BillioError::InvalidInput(
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

    pub async fn authenticate(&self, email: &str, password: &str) -> Result<String, BillioError> {
        let user = self
            .storage
            .get_user_by_email(email)
            .await?
            .ok_or(BillioError::InvalidCredentials)?;

        if bcrypt::verify(password, &user.password)
            .map_err(|e| BillioError::InternalServerError(format!("Password verification error: {}", e)))?
        {
            // Assume all users have "USER" role for simplicity; extend with roles if needed
            self.jwt_service
                .generate_token(&user.id, "USER")
                .map_err(|e| BillioError::InternalServerError(format!("Token generation error: {}", e)))
        } else {
            Err(BillioError::InvalidCredentials)
        }
    }

    pub async fn get_user(&self, user_id: &str) -> Result<Option<User>, BillioError> {
        self.storage.get_user(user_id).await
    }

    pub async fn add_user(&self, user: User, created_by: Option<&User>) -> Result<User, BillioError> {
        if user.email.is_empty() {
            return Err(BillioError::MissingEmail);
        }
        if !user.email.contains('@') || !user.email.contains('.') || user.email.len() < 5 {
            return Err(BillioError::InvalidEmail(user.email.clone()));
        }
        if user.password.is_empty() {
            return Err(BillioError::InvalidInput(
                "password".to_string(),
                FieldError {
                    field: "password".to_string(),
                    title: "Invalid password".to_string(),
                    description: "Password cannot be empty".to_string(),
                },
            ));
        }

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
            Err(BillioError::EmailAlreadyRegistered(user.email))
        }
    }

    pub async fn create_group(
        &self,
        name: String,
        members: Vec<User>,
        created_by: &User,
    ) -> Result<Group, BillioError> {
        self.validate_users(&[&created_by.id]).await?;
        self.validate_string_input("name", &name, 100)?;

        let mut all_members = members;
        if !all_members.iter().any(|m| m.id == created_by.id) {
            all_members.push(created_by.clone());
        }

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

    pub async fn delete_group(&self, group_id: &str, deleted_by: &User) -> Result<(), BillioError> {
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

    pub async fn add_member_to_group(&self, group_id: &str, user: User, added_by: &User) -> Result<(), BillioError> {
        let mut group = self.validate_group_and_owner(group_id, &added_by.id).await?;
        self.validate_users(&[&user.id]).await?;

        if group.members.iter().any(|m| m.user.id == user.id) {
            return Err(BillioError::AlreadyGroupMember(user.id));
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

    pub async fn add_member_by_email(&self, group_id: &str, email: &str, added_by: &User) -> Result<(), BillioError> {
        let mut group = self.validate_group_and_owner(group_id, &added_by.id).await?;
        let user = self
            .storage
            .get_user_by_email(email)
            .await?
            .ok_or_else(|| BillioError::UserNotFound(email.to_string()))?;

        if group.members.iter().any(|m| m.user.id == user.id) {
            return Err(BillioError::AlreadyGroupMember(email.to_string()));
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
    ) -> Result<(), BillioError> {
        let mut group = self.validate_group_and_owner(group_id, &removed_by.id).await?;
        self.validate_users(&[user_id]).await?;

        if user_id == removed_by.id {
            return Err(BillioError::OwnerCannotRemoveSelf);
        }
        if group.members.len() <= 1 {
            return Err(BillioError::CannotRemoveLastMember);
        }

        let user_opt = group.members.iter().find(|m| m.user.id == user_id).cloned();
        let user = user_opt.ok_or_else(|| BillioError::NotGroupMember(user_id.to_string()))?;
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

    pub async fn join_group_by_link(&self, join_link: &str, user: &User) -> Result<(), BillioError> {
        self.validate_string_input("join_link", join_link, 100)?;
        let mut group = self
            .storage
            .get_group_by_join_link(join_link)
            .await?
            .ok_or(BillioError::JoinLinkNotFound)?;
        self.validate_users(&[&user.id]).await?;

        if group.members.iter().any(|m| m.user.id == user.id) {
            return Err(BillioError::AlreadyGroupMember(user.id.clone()));
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

    pub async fn revoke_join_link(&self, group_id: &str, revoked_by: &User) -> Result<(), BillioError> {
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

    pub async fn regenerate_join_link(&self, group_id: &str, regenerated_by: &User) -> Result<String, BillioError> {
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
    ) -> Result<(), BillioError> {
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
    ) -> Result<(), BillioError> {
        let mut group = self.validate_group_and_owner(group_id, &transferred_by.id).await?;
        self.validate_users(&[&new_owner.id]).await?;

        if !self.storage.is_group_member(&group.id, &new_owner.id).await? {
            return Err(BillioError::NotGroupMember(new_owner.id.clone()));
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
    ) -> Result<Transaction, BillioError> {
        let group = self.validate_group_membership(group_id, &created_by.id).await?;
        self.validate_users(&[&paid_by.id]).await?;
        if !group.members.iter().any(|m| m.user.id == paid_by.id) {
            return Err(BillioError::NotGroupMember(paid_by.id.clone()));
        }

        self.validate_string_input("description", &description, 255)?;
        self.validate_amount_input("amount", amount)?;

        let share_sum: f64 = shares.values().sum();
        if (share_sum - amount).abs() > 0.01 {
            return Err(BillioError::InvalidSplit);
        }

        for user_id in shares.keys() {
            if !group.members.iter().any(|m| m.user.id == *user_id) {
                return Err(BillioError::InvalidSplitUser(user_id.clone()));
            }
        }

        let transaction_id = Uuid::new_v4().to_string();
        let transaction = Transaction {
            id: transaction_id.clone(),
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
        self.cache.invalidate_user_balances(&transaction.group_id).await?;

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

    pub async fn reverse_transaction(
        &self,
        transaction_id: &str,
        reversed_by: &User,
    ) -> Result<Transaction, BillioError> {
        let _group = self
            .validate_group_membership(
                &self
                    .storage
                    .get_transaction(transaction_id)
                    .await?
                    .ok_or_else(|| BillioError::TransactionNotFound(transaction_id.to_string()))?
                    .group_id,
                &reversed_by.id,
            )
            .await?;

        let mut transaction = self
            .storage
            .get_transaction(transaction_id)
            .await?
            .ok_or_else(|| BillioError::TransactionNotFound(transaction_id.to_string()))?;

        if transaction.is_reversed {
            return Err(BillioError::TransactionAlreadyReversed(transaction_id.to_string()));
        }

        let reversal_id = Uuid::new_v4().to_string();
        let reversal = Transaction {
            id: reversal_id.clone(),
            group_id: transaction.group_id.clone(),
            description: format!("Reversal of {}", transaction.description),
            amount: -transaction.amount,
            paid_by: transaction.paid_by.clone(),
            shares: transaction.shares.iter().map(|(k, v)| (k.clone(), -v)).collect(),
            timestamp: Utc::now(),
            is_reversed: false,
            reverses: Some(transaction_id.to_string()),
            reversed_by: Some(reversed_by.id.clone()),
        };

        transaction.is_reversed = true;
        transaction.reversed_by = Some(reversed_by.id.clone());

        self.storage.save_transaction(reversal.clone()).await?;
        self.storage.save_transaction(transaction).await?;
        self.cache.invalidate_user_balances(&reversal.group_id).await?;

        self.log_and_audit(
            Some(&reversal.group_id),
            TRANSACTION_REVERSED,
            json!({
                "transaction_id": transaction_id,
                "reversal_id": reversal.id,
                "group_id": reversal.group_id
            }),
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
    ) -> Result<Settlement, BillioError> {
        let group = self.validate_group_membership(group_id, &created_by.id).await?;
        self.validate_users(&[&from_user.id, &to_user.id]).await?;

        if from_user.id == to_user.id {
            return Err(BillioError::SelfSettlement);
        }

        if !group.members.iter().any(|m| m.user.id == from_user.id)
            || !group.members.iter().any(|m| m.user.id == to_user.id)
        {
            return Err(BillioError::NotGroupMember(
                if !group.members.iter().any(|m| m.user.id == from_user.id) {
                    from_user.id.clone()
                } else {
                    to_user.id.clone()
                },
            ));
        }

        self.validate_amount_input("amount", amount)?;

        if let Some(ref tids) = transaction_ids {
            for tid in tids {
                let transaction = self
                    .storage
                    .get_transaction(tid)
                    .await?
                    .ok_or_else(|| BillioError::InvalidSettlementTransaction(tid.clone()))?;
                if transaction.group_id != group_id {
                    return Err(BillioError::InvalidSettlementTransaction(tid.clone()));
                }
            }
        }

        let settlement_id = Uuid::new_v4().to_string();
        let settlement = Settlement {
            id: settlement_id.clone(),
            group_id: group_id.to_string(),
            from_user_id: from_user.id.clone(),
            to_user_id: to_user.id.clone(),
            amount,
            remarks,
            transaction_ids,
            timestamp: Utc::now(),
            is_confirmed: !group.strict_settlement_mode,
            confirmed_by: if !group.strict_settlement_mode {
                Some(created_by.id.clone())
            } else {
                None
            },
        };

        self.storage.save_settlement(settlement.clone()).await?;
        self.cache.invalidate_user_balances(group_id).await?;

        self.log_and_audit(
            Some(group_id),
            SETTLEMENT_CREATED,
            json!({
                "settlement_id": settlement.id,
                "group_id": group_id,
                "from_user_id": from_user.id,
                "to_user_id": to_user.id,
                "amount": amount
            }),
            Some(created_by.id.as_str()),
        )
        .await?;

        Ok(settlement)
    }

    pub async fn confirm_settlement(&self, settlement_id: &str, confirmed_by: &User) -> Result<(), BillioError> {
        let mut settlement = self
            .storage
            .get_settlement(settlement_id)
            .await?
            .ok_or_else(|| BillioError::SettlementNotFound(settlement_id.to_string()))?;

        if settlement.is_confirmed {
            return Err(BillioError::SettlementAlreadyConfirmed(settlement_id.to_string()));
        }

        let group = self
            .storage
            .get_group(&settlement.group_id)
            .await?
            .ok_or_else(|| BillioError::GroupNotFound(settlement.group_id.clone()))?;

        if !group.strict_settlement_mode {
            return Err(BillioError::SettlementAlreadyConfirmed(settlement_id.to_string()));
        }

        if confirmed_by.id != settlement.to_user_id {
            return Err(BillioError::UnauthorizedSettlementConfirmation(confirmed_by.id.clone()));
        }

        settlement.is_confirmed = true;
        settlement.confirmed_by = Some(confirmed_by.id.clone());
        self.storage.save_settlement(settlement.clone()).await?;
        self.cache.invalidate_user_balances(&settlement.group_id).await?;

        self.log_and_audit(
            Some(&settlement.group_id),
            SETTLEMENT_CONFIRMED,
            json!({ "settlement_id": settlement.id, "group_id": settlement.group_id }),
            Some(confirmed_by.id.as_str()),
        )
        .await?;

        Ok(())
    }

    pub async fn get_pending_settlements(&self, group_id: &str, user: &User) -> Result<Vec<Settlement>, BillioError> {
        let _group = self.validate_group_membership(group_id, &user.id).await?;
        let settlements = self.storage.get_pending_settlements(group_id).await?;
        self.log_and_audit(
            Some(group_id),
            PENDING_SETTLEMENTS_QUERIED,
            json!({ "group_id": group_id, "user_id": user.id }),
            Some(user.id.as_str()),
        )
        .await?;
        Ok(settlements)
    }

    pub async fn get_effective_transactions(
        &self,
        group_id: &str,
        queried_by: &User,
    ) -> Result<Vec<Transaction>, BillioError> {
        let _group = self.validate_group_membership(group_id, &queried_by.id).await?;
        let transactions = self.storage.get_effective_transactions(group_id).await?;
        self.log_and_audit(
            Some(group_id),
            TRANSACTIONS_QUERIED,
            json!({ "group_id": group_id, "user_id": queried_by.id }),
            Some(queried_by.id.as_str()),
        )
        .await?;
        Ok(transactions)
    }

    pub async fn get_user_balances(
        &self,
        user_id: &str,
        queried_by: &User,
    ) -> Result<UserBalancesResponse, BillioError> {
        self.validate_users(&[user_id, &queried_by.id]).await?;

        let cached = self.cache.get_user_balances(user_id).await?;
        if let Some(balances) = cached {
            return Ok(balances);
        }

        let mut balances: HashMap<(String, String), f64> = HashMap::new();
        let groups = self.storage.get_user_groups(user_id).await?;

        for group in groups {
            let transactions = self.storage.get_effective_transactions(&group.id).await?;
            for transaction in transactions {
                let paid_by_id = transaction.paid_by.id.clone();
                for (owes_id, amount) in &transaction.shares {
                    if paid_by_id != *owes_id {
                        let key = if paid_by_id < *owes_id {
                            (paid_by_id.clone(), owes_id.clone())
                        } else {
                            (owes_id.clone(), paid_by_id.clone())
                        };
                        let entry = balances.entry(key).or_insert(0.0);
                        if paid_by_id == user_id {
                            *entry += amount;
                        } else if owes_id == user_id {
                            *entry -= amount;
                        }
                    }
                }
            }

            let settlements = self.storage.get_settlements(&group.id).await?;
            for settlement in settlements {
                if !settlement.is_confirmed {
                    continue;
                }
                let key = if settlement.from_user_id < settlement.to_user_id {
                    (settlement.from_user_id.clone(), settlement.to_user_id.clone())
                } else {
                    (settlement.to_user_id.clone(), settlement.from_user_id.clone())
                };
                let entry = balances.entry(key).or_insert(0.0);
                if settlement.from_user_id == user_id {
                    *entry -= settlement.amount;
                } else if settlement.to_user_id == user_id {
                    *entry += settlement.amount;
                }
            }
        }

        let circular_balances = balances
            .into_iter()
            .filter(|((from, to), amount)| *amount != 0.0 && (from == user_id || to == user_id))
            .map(|((from, to), amount)| {
                let from_clone = from.clone();
                let to_clone = to.clone();
                Balance {
                    user_id: if from_clone == user_id {
                        from_clone.clone()
                    } else {
                        to_clone.clone()
                    },
                    owes_to: if from_clone == user_id { to_clone } else { from_clone },
                    amount: amount.abs(),
                }
            })
            .collect::<Vec<_>>();

        let minimized_balances = self.minimize_balances(circular_balances.clone());

        let response = UserBalancesResponse {
            circular_balances,
            minimized_balances,
        };

        self.cache
            .save_user_balances(user_id, &response, std::time::Duration::from_secs(3600))
            .await?;

        self.log_and_audit(
            None,
            BALANCE_QUERIED,
            json!({ "user_id": user_id, "queried_by": queried_by.id }),
            Some(queried_by.id.as_str()),
        )
        .await?;

        Ok(response)
    }

    fn minimize_balances(&self, balances: Vec<Balance>) -> Vec<Balance> {
        let mut net_balances: HashMap<String, f64> = HashMap::new();
        for balance in balances {
            *net_balances.entry(balance.user_id.clone()).or_insert(0.0) -= balance.amount;
            *net_balances.entry(balance.owes_to.clone()).or_insert(0.0) += balance.amount;
        }

        let mut positive: Vec<(String, f64)> = net_balances
            .iter()
            .filter(|(_, amount)| **amount > 0.01)
            .map(|(id, amount)| (id.clone(), *amount))
            .collect();
        let mut negative: Vec<(String, f64)> = net_balances
            .iter()
            .filter(|(_, amount)| **amount < -0.01)
            .map(|(id, amount)| (id.clone(), *amount))
            .collect();

        positive.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        negative.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        let mut minimized = Vec::new();
        while !positive.is_empty() && !negative.is_empty() {
            let (creditor, credit) = positive[0].clone();
            let (debtor, debit) = negative[0].clone();
            let amount = credit.min(-debit);

            if amount > 0.01 {
                minimized.push(Balance {
                    user_id: debtor.clone(),
                    owes_to: creditor.clone(),
                    amount,
                });
            }

            positive[0].1 -= amount;
            negative[0].1 += amount;

            if positive[0].1 < 0.01 {
                positive.remove(0);
            }
            if negative[0].1 > -0.01 {
                negative.remove(0);
            }
            positive.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
            negative.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
        }

        minimized
    }

    fn validate_group_roles(&self, group: &Group) -> Result<(), BillioError> {
        let owner_count = group.members.iter().filter(|m| m.role == Role::Owner).count();
        if owner_count != 1 {
            return Err(BillioError::InvalidOwnerCount(owner_count));
        }
        Ok(())
    }

    pub async fn get_group_audits(&self, group_id: &str) -> Result<Vec<GroupAudit>, BillioError> {
        self.storage
            .get_group(group_id)
            .await?
            .ok_or_else(|| BillioError::GroupNotFound(group_id.to_string()))?;
        self.storage.get_group_audits(group_id).await
    }

    pub async fn get_app_logs(&self) -> Result<Vec<AppLog>, BillioError> {
        self.logging.get_logs().await
    }

    pub async fn get_group(&self, group_id: &str) -> Result<Option<Group>, BillioError> {
        self.storage.get_group(group_id).await
    }
}
