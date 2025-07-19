use uuid::Uuid;

use crate::error::ExpenseServiceError;
use crate::models::*;

pub trait Storage {
    fn create_user(&mut self, user: User) -> Result<User, ExpenseServiceError>;
    fn update_user(&mut self, user: User) -> Result<User, ExpenseServiceError>;
    fn get_user(&self, user_id: Uuid) -> Option<User>;

    fn list_groups(&self) -> Vec<Group>;
    fn create_group(&mut self, group: Group) -> Result<Group, ExpenseServiceError>;
    fn update_group(&mut self, group: Group) -> Result<Group, ExpenseServiceError>;
    fn get_group(&self, group_id: Uuid) -> Option<Group>;
    fn is_group_member(&self, group_id: Uuid, user_id: Uuid) -> bool;

    fn add_user_to_group(&mut self, group_user: GroupUser) -> Result<(), ExpenseServiceError>;
    fn update_group_user_role(
        &mut self,
        group_id: Uuid,
        user_id: Uuid,
        role: Role,
    ) -> Result<(), ExpenseServiceError>;
    fn remove_user_from_group(
        &mut self,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), ExpenseServiceError>;
    fn get_group_user_role(&self, group_id: Uuid, user_id: Uuid) -> Option<Role>;
    fn list_group_users(&self, group_id: Uuid) -> Vec<GroupUser>;

    fn create_transaction(&mut self, tx: Transaction) -> Result<Transaction, ExpenseServiceError>;
    fn update_transaction(&mut self, tx: Transaction) -> Result<Transaction, ExpenseServiceError>;
    fn get_transaction(&self, tx_id: Uuid) -> Option<Transaction>;
    fn list_transactions(&self, group_id: Uuid) -> Vec<Transaction>;

    fn list_audit_logs(&self) -> Vec<AuditLogEntry>;
}

pub mod in_memory;
