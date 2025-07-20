use super::user::User;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Role {
    Owner,
    Member,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Role::Owner => "OWNER",
            Role::Member => "MEMBER",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct GroupMember {
    pub user: User,
    pub role: Role,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub members: Vec<GroupMember>,
    pub join_link: String,
    pub strict_settlement_mode: bool,
}

impl GroupMember {
    pub fn is_owner(&self) -> bool {
        self.role == Role::Owner
    }

    pub fn is_member(&self) -> bool {
        self.role == Role::Member
    }
}
