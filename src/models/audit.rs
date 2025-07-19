use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditAction {
    CreateUser,
    UpdateUser,
    CreateGroup,
    UpdateGroup,
    TransferOwnership,
    UserJoinGroup,
    RemoveUserFromGroup,
    CreateTransaction,
    UpdateTransaction,
    DeleteTransaction,
}

#[derive(Clone, Debug)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub user_id: Uuid,
    pub action: AuditAction,
    pub payload: String,
    pub created_at: DateTime<Utc>,
}

impl AuditLogEntry {
    // Create audit log entry with structured JSON payload
    pub fn new<T: Serialize>(
        user_id: Uuid,
        action: AuditAction,
        payload: &T,
        created_at: DateTime<Utc>,
    ) -> Self {
        AuditLogEntry {
            id: Uuid::new_v4(),
            user_id,
            action,
            payload: serde_json::to_string(payload).unwrap_or_default(),
            created_at,
        }
    }
}
