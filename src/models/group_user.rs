use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Role {
    Owner,
    Member,
}

#[derive(Clone, Debug)]
pub struct GroupUser {
    pub group_id: Uuid,
    pub user_id: Uuid,
    pub role: Role,
    pub joined_at: DateTime<Utc>,
}
