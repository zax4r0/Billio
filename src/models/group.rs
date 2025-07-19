use super::group_user::GroupUser;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    pub strict_editing: bool,
    pub join_link: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub users: Vec<GroupUser>, // List of user IDs in the group, or empty array if none
}
