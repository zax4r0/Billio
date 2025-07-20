use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

use crate::core::errors::BillioError;

// Request structs for JSON payloads
#[derive(Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub id: String,
    pub name: String,
    pub email: String,
    pub password: String,
    pub created_by_id: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateGroupRequest {
    pub name: String,
    pub member_ids: Vec<String>,
    pub created_by_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct AddMemberRequest {
    pub user_id: String,
    pub added_by_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct AddMemberByEmailRequest {
    pub email: String,
    pub added_by_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct RemoveMemberRequest {
    pub user_id: String,
    pub removed_by_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct JoinGroupRequest {
    pub join_link: String,
    pub user_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct RevokeJoinLinkRequest {
    pub revoked_by_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct RegenerateJoinLinkRequest {
    pub regenerated_by_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct ToggleStrictModeRequest {
    pub enabled: bool,
    pub toggled_by_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct TransferOwnershipRequest {
    pub new_owner_id: String,
    pub transferred_by_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct AddExpenseRequest {
    pub group_id: String,
    pub description: String,
    pub amount: f64,
    pub paid_by_id: String,
    pub shares: HashMap<String, f64>,
    pub created_by_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct ReverseTransactionRequest {
    pub transaction_id: String,
    pub reversed_by_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateSettlementRequest {
    pub group_id: String,
    pub from_user_id: String,
    pub to_user_id: String,
    pub amount: f64,
    pub remarks: Option<String>,
    pub transaction_ids: Option<Vec<String>>,
    pub created_by_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct ConfirmSettlementRequest {
    pub settlement_id: String,
    pub confirmed_by_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct GetPendingSettlementsRequest {
    pub group_id: String,
    pub user_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct DeleteGroupRequest {
    pub deleted_by_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct GetUserBalancesRequest {
    pub user_id: String,
    pub queried_by_id: String,
}

#[derive(Deserialize, ToSchema)]
pub struct GetEffectiveTransactionsRequest {
    pub group_id: String,
    pub queried_by_id: String,
}

// Error response struct
#[derive(Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
}

// Newtype wrapper for BillioError to implement IntoResponse
pub struct ApiError(pub BillioError);

impl From<BillioError> for ApiError {
    fn from(err: BillioError) -> Self {
        ApiError(err)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self.0 {
            BillioError::MissingEmail => (StatusCode::BAD_REQUEST, "Email is required".to_string()),
            BillioError::EmailAlreadyRegistered(email) => {
                (StatusCode::CONFLICT, format!("Email {} already registered", email))
            }
            BillioError::UserNotFound(id) => (StatusCode::NOT_FOUND, format!("User {} not found", id)),
            BillioError::GroupNotFound(id) => (StatusCode::NOT_FOUND, format!("Group {} not found", id)),
            BillioError::AlreadyGroupMember(id) => {
                (StatusCode::CONFLICT, format!("User {} is already a group member", id))
            }
            BillioError::NotGroupMember(id) => (StatusCode::FORBIDDEN, format!("User {} is not a group member", id)),
            BillioError::NotGroupOwner(id) => (StatusCode::FORBIDDEN, format!("User {} is not group owner", id)),
            BillioError::InvalidOwnerCount(count) => {
                (StatusCode::BAD_REQUEST, format!("Invalid owner count: {}", count))
            }
            BillioError::OwnerCannotRemoveSelf => (StatusCode::FORBIDDEN, "Owner cannot remove themselves".to_string()),
            BillioError::CannotRemoveLastMember => {
                (StatusCode::BAD_REQUEST, "Cannot remove last group member".to_string())
            }
            BillioError::InvalidJoinLink => (StatusCode::BAD_REQUEST, "Invalid join link".to_string()),
            BillioError::JoinLinkNotFound => (StatusCode::NOT_FOUND, "Join link not found".to_string()),
            BillioError::InvalidSplit => (StatusCode::BAD_REQUEST, "Invalid split amounts".to_string()),
            BillioError::InvalidSplitUser(id) => (
                StatusCode::BAD_REQUEST,
                format!("User {} is not a group member for split", id),
            ),
            BillioError::TransactionNotFound(id) => (StatusCode::NOT_FOUND, format!("Transaction {} not found", id)),
            BillioError::SelfSettlement => (StatusCode::BAD_REQUEST, "Cannot create settlement to self".to_string()),
            BillioError::InvalidSettlementAmount => (
                StatusCode::BAD_REQUEST,
                "Settlement amount must be positive".to_string(),
            ),
            BillioError::InvalidSettlementTransaction(id) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid transaction {} for settlement", id),
            ),
            BillioError::SettlementNotFound(id) => (StatusCode::NOT_FOUND, format!("Settlement {} not found", id)),
            BillioError::SettlementAlreadyConfirmed(id) => {
                (StatusCode::CONFLICT, format!("Settlement {} already confirmed", id))
            }
            BillioError::UnauthorizedSettlementConfirmation(id) => (
                StatusCode::FORBIDDEN,
                format!("User {} not authorized to confirm settlement", id),
            ),
            BillioError::TransactionAlreadyReversed(id) => (
                StatusCode::CONFLICT,
                format!("Transaction {} has already been reversed", id),
            ),
            BillioError::InvalidEmail(email) => (StatusCode::BAD_REQUEST, format!("Invalid email: {}", email)),
            BillioError::InvalidInput(field, msg) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid input for {}: {:?}", field, msg),
            ),
            BillioError::InternalServerError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal server error: {}", msg),
            ),
            BillioError::StorageError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Storage error: {}", msg)),
            BillioError::LoggingError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Logging error: {}", msg)),
            BillioError::DatabaseError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", msg)),
            BillioError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid email or password".to_string()),
            BillioError::UnexpectedError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Unexpected error: {}", msg))
            }
            BillioError::CacheError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Cache error: {}", msg)),
        };
        (status, Json(ErrorResponse { error: error_message })).into_response()
    }
}
