use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    pub password: String, // Added for storing hashed password
}
