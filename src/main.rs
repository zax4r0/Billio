use axum::{
    Json, Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use billio::service::BillioService;
use billio::storage::in_memory::InMemoryStorage;
use billio::{
    cache::in_memory_cache::InMemoryCache,
    models::{
        audit::{AppLog, GroupAudit},
        group::Group,
        settlement::Settlement,
        transaction::Transaction,
        user::User,
    },
};
use billio::{config::CONFIG, error::BillioError};
use billio::{logger::in_memory::InMemoryLogging, service::UserBalancesResponse};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::info;
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

// Request structs for JSON payloads
#[derive(Deserialize, ToSchema)]
struct CreateUserRequest {
    id: String,
    name: String,
    email: String,
    created_by_id: Option<String>,
}

#[derive(Deserialize, ToSchema)]
struct CreateGroupRequest {
    name: String,
    member_ids: Vec<String>,
    created_by_id: String,
}

#[derive(Deserialize, ToSchema)]
struct AddMemberRequest {
    user_id: String,
    added_by_id: String,
}

#[derive(Deserialize, ToSchema)]
struct AddMemberByEmailRequest {
    email: String,
    added_by_id: String,
}

#[derive(Deserialize, ToSchema)]
struct RemoveMemberRequest {
    user_id: String,
    removed_by_id: String,
}

#[derive(Deserialize, ToSchema)]
struct JoinGroupRequest {
    join_link: String,
    user_id: String,
}

#[derive(Deserialize, ToSchema)]
struct RevokeJoinLinkRequest {
    revoked_by_id: String,
}

#[derive(Deserialize, ToSchema)]
struct RegenerateJoinLinkRequest {
    regenerated_by_id: String,
}

#[derive(Deserialize, ToSchema)]
struct ToggleStrictModeRequest {
    enabled: bool,
    toggled_by_id: String,
}

#[derive(Deserialize, ToSchema)]
struct TransferOwnershipRequest {
    new_owner_id: String,
    transferred_by_id: String,
}

#[derive(Deserialize, ToSchema)]
struct AddExpenseRequest {
    group_id: String,
    description: String,
    amount: f64,
    paid_by_id: String,
    shares: HashMap<String, f64>,
    created_by_id: String,
}

#[derive(Deserialize, ToSchema)]
struct ReverseTransactionRequest {
    transaction_id: String,
    reversed_by_id: String,
}

#[derive(Deserialize, ToSchema)]
struct CreateSettlementRequest {
    group_id: String,
    from_user_id: String,
    to_user_id: String,
    amount: f64,
    remarks: Option<String>,
    transaction_ids: Option<Vec<String>>,
    created_by_id: String,
}

#[derive(Deserialize, ToSchema)]
struct ConfirmSettlementRequest {
    settlement_id: String,
    confirmed_by_id: String,
}

#[derive(Deserialize, ToSchema)]
struct GetPendingSettlementsRequest {
    group_id: String,
    user_id: String,
}

#[derive(Deserialize, ToSchema)]
struct DeleteGroupRequest {
    deleted_by_id: String,
}

#[derive(Deserialize, ToSchema)]
struct GetUserBalancesRequest {
    user_id: String,
    queried_by_id: String,
}

#[derive(Deserialize, ToSchema)]
struct GetEffectiveTransactionsRequest {
    group_id: String,
    queried_by_id: String,
}

// Error response struct
#[derive(Serialize, ToSchema)]
struct ErrorResponse {
    error: String,
}

// Newtype wrapper for BillioError to implement IntoResponse
struct ApiError(BillioError);

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
            BillioError::UnexpectedError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Unexpected error: {}", msg))
            }
            BillioError::CacheError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Cache error: {}", msg)),
        };
        (status, Json(ErrorResponse { error: error_message })).into_response()
    }
}

#[utoipa::path(
    post,
    path = "/users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created successfully"),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 409, description = "Email already registered", body = ErrorResponse),
        (status = 404, description = "Created by user not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn create_user(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<CreateUserRequest>,
) -> Result<StatusCode, ApiError> {
    let user = User {
        id: req.id,
        name: req.name,
        email: req.email,
    };
    let created_by_user = if let Some(ref id) = req.created_by_id {
        Some(
            service
                .get_user(id)
                .await?
                .ok_or_else(|| BillioError::UserNotFound(id.clone()))?,
        )
    } else {
        None
    };
    service.add_user(user, created_by_user.as_ref()).await?;
    Ok(StatusCode::CREATED)
}

#[utoipa::path(
    get,
    path = "/users/{user_id}",
    params(
        ("user_id" = String, Path, description = "ID of the user to retrieve")
    ),
    responses(
        (status = 200, description = "User retrieved successfully", body = User),
        (status = 404, description = "User not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn get_user(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(user_id): Path<String>,
) -> Result<Json<User>, ApiError> {
    let user = service
        .get_user(&user_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(user_id))?;
    Ok(Json(user))
}

#[utoipa::path(
    post,
    path = "/groups",
    request_body = CreateGroupRequest,
    responses(
        (status = 200, description = "Group created successfully", body = Group),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn create_group(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<Group>, ApiError> {
    let created_by = service
        .get_user(&req.created_by_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.created_by_id))?;
    let members = req
        .member_ids
        .into_iter()
        .map(|id| async {
            service
                .get_user(&id)
                .await?
                .ok_or_else(|| BillioError::UserNotFound(id))
        })
        .collect::<Vec<_>>();
    let members = futures::future::try_join_all(members).await?;
    let group = service.create_group(req.name, members, &created_by).await?;
    Ok(Json(group))
}

#[utoipa::path(
    delete,
    path = "/groups/{group_id}",
    request_body = DeleteGroupRequest,
    params(
        ("group_id" = String, Path, description = "ID of the group to delete")
    ),
    responses(
        (status = 200, description = "Group deleted successfully",),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 403, description = "Not group owner", body = ErrorResponse),
        (status = 404, description = "Group or user not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn delete_group(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
    Json(req): Json<DeleteGroupRequest>,
) -> Result<StatusCode, ApiError> {
    let deleted_by = service
        .get_user(&req.deleted_by_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.deleted_by_id))?;
    service.delete_group(&group_id, &deleted_by).await?;
    Ok(StatusCode::OK)
}

#[utoipa::path(
    post,
    path = "/groups/join",
    request_body = JoinGroupRequest,
    responses(
        (status = 200, description = "Joined group successfully",),
        (status = 400, description = "Invalid join link", body = ErrorResponse),
        (status = 404, description = "User or join link not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn join_group_by_link(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<JoinGroupRequest>,
) -> Result<StatusCode, ApiError> {
    let user = service
        .get_user(&req.user_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.user_id))?;
    service.join_group_by_link(&req.join_link, &user).await?;
    Ok(StatusCode::OK)
}

#[utoipa::path(
    post,
    path = "/groups/{group_id}/members",
    request_body = AddMemberRequest,
    params(
        ("group_id" = String, Path, description = "ID of the group")
    ),
    responses(
        (status = 200, description = "Member added successfully"),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 403, description = "Not authorized", body = ErrorResponse),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 409, description = "User already a member", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn add_member_to_group(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> Result<StatusCode, ApiError> {
    let user = service
        .get_user(&req.user_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.user_id))?;
    let added_by = service
        .get_user(&req.added_by_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.added_by_id))?;
    service.add_member_to_group(&group_id, user, &added_by).await?;
    Ok(StatusCode::OK)
}

#[utoipa::path(
    post,
    path = "/groups/{group_id}/members/email",
    request_body = AddMemberByEmailRequest,
    params(
        ("group_id" = String, Path, description = "ID of the group")
    ),
    responses(
        (status = 200, description = "Member added successfully"),
        (status = 400, description = "Invalid email", body = ErrorResponse),
        (status = 403, description = "Not authorized", body = ErrorResponse),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]

async fn add_member_by_email(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
    Json(req): Json<AddMemberByEmailRequest>,
) -> Result<StatusCode, ApiError> {
    let added_by = service
        .get_user(&req.added_by_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.added_by_id))?;
    service.add_member_by_email(&group_id, &req.email, &added_by).await?;
    Ok(StatusCode::OK)
}

#[utoipa::path(
    post,
    path = "/groups/{group_id}/members/remove",
    request_body = RemoveMemberRequest,
    params(
        ("group_id" = String, Path, description = "ID of the group")
    ),
    responses(
        (status = 200, description = "Member removed successfully"),
        (status = 400, description = "Cannot remove last member or owner", body = ErrorResponse),
        (status = 403, description = "Not authorized", body = ErrorResponse),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn remove_member_from_group(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
    Json(req): Json<RemoveMemberRequest>,
) -> Result<StatusCode, ApiError> {
    let removed_by = service
        .get_user(&req.removed_by_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.removed_by_id))?;
    service
        .remove_member_from_group(&group_id, &req.user_id, &removed_by)
        .await?;
    Ok(StatusCode::OK)
}

#[utoipa::path(
    post,
    path = "/groups/{group_id}/join_link/revoke",
    request_body = RevokeJoinLinkRequest,
    params(
        ("group_id" = String, Path, description = "ID of the group")
    ),
    responses(
        (status = 200, description = "Join link revoked successfully"),
        (status = 403, description = "Not authorized", body = ErrorResponse),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn revoke_join_link(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
    Json(req): Json<RevokeJoinLinkRequest>,
) -> Result<StatusCode, ApiError> {
    let revoked_by = service
        .get_user(&req.revoked_by_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.revoked_by_id))?;
    service.revoke_join_link(&group_id, &revoked_by).await?;
    Ok(StatusCode::OK)
}

#[utoipa::path(
    post,
    path = "/groups/{group_id}/join_link/regenerate",
    request_body = RegenerateJoinLinkRequest,
    params(
        ("group_id" = String, Path, description = "ID of the group")
    ),
    responses(
        (status = 200, description = "Join link regenerated successfully", body = String),
        (status = 403, description = "Not authorized", body = ErrorResponse),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn regenerate_join_link(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
    Json(req): Json<RegenerateJoinLinkRequest>,
) -> Result<Json<String>, ApiError> {
    let regenerated_by = service
        .get_user(&req.regenerated_by_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.regenerated_by_id))?;
    let new_link = service.regenerate_join_link(&group_id, &regenerated_by).await?;
    Ok(Json(new_link))
}

#[utoipa::path(
    post,
    path = "/groups/{group_id}/strict_mode",
    request_body = ToggleStrictModeRequest,
    params(
        ("group_id" = String, Path, description = "ID of the group")
    ),
    responses(
        (status = 200, description = "Strict mode toggled successfully"),
        (status = 403, description = "Not authorized", body = ErrorResponse),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn toggle_strict_settlement_mode(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
    Json(req): Json<ToggleStrictModeRequest>,
) -> Result<StatusCode, ApiError> {
    let toggled_by = service
        .get_user(&req.toggled_by_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.toggled_by_id))?;
    service
        .toggle_strict_settlement_mode(&group_id, req.enabled, &toggled_by)
        .await?;
    Ok(StatusCode::OK)
}

#[utoipa::path(
    post,
    path = "/groups/{group_id}/ownership",
    request_body = TransferOwnershipRequest,
    params(
        ("group_id" = String, Path, description = "ID of the group")
    ),
    responses(
        (status = 200, description = "Ownership transferred successfully"),
        (status = 403, description = "Not authorized", body = ErrorResponse),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn transfer_ownership(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
    Json(req): Json<TransferOwnershipRequest>,
) -> Result<StatusCode, ApiError> {
    let new_owner = service
        .get_user(&req.new_owner_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.new_owner_id))?;
    let transferred_by = service
        .get_user(&req.transferred_by_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.transferred_by_id))?;
    service
        .transfer_ownership(&group_id, &new_owner, &transferred_by)
        .await?;
    Ok(StatusCode::OK)
}

#[utoipa::path(
    post,
    path = "/expenses",
    request_body = AddExpenseRequest,
    responses(
        (status = 200, description = "Expense added successfully", body = Transaction),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn add_expense(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<AddExpenseRequest>,
) -> Result<Json<Transaction>, ApiError> {
    let paid_by = service
        .get_user(&req.paid_by_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.paid_by_id))?;
    let created_by = service
        .get_user(&req.created_by_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.created_by_id))?;
    let transaction = service
        .add_expense(
            &req.group_id,
            req.description,
            req.amount,
            paid_by,
            req.shares,
            &created_by,
        )
        .await?;
    Ok(Json(transaction))
}

#[utoipa::path(
    post,
    path = "/transactions/reverse",
    request_body = ReverseTransactionRequest,
    responses(
        (status = 200, description = "Transaction reversed successfully", body = Transaction),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 404, description = "Transaction or user not found", body = ErrorResponse),
        (status = 409, description = "Transaction already reversed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn reverse_transaction(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<ReverseTransactionRequest>,
) -> Result<Json<Transaction>, ApiError> {
    let reversed_by = service
        .get_user(&req.reversed_by_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.reversed_by_id))?;
    let reversal = service.reverse_transaction(&req.transaction_id, &reversed_by).await?;
    Ok(Json(reversal))
}

#[utoipa::path(
    post,
    path = "/settlements",
    request_body = CreateSettlementRequest,
    responses(
        (status = 200, description = "Settlement created successfully", body = Settlement),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 409, description = "Self settlement or invalid transaction", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn create_settlement(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<CreateSettlementRequest>,
) -> Result<Json<Settlement>, ApiError> {
    let from_user = service
        .get_user(&req.from_user_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.from_user_id))?;
    let to_user = service
        .get_user(&req.to_user_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.to_user_id))?;
    let created_by = service
        .get_user(&req.created_by_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.created_by_id))?;
    let settlement = service
        .create_settlement(
            &req.group_id,
            &from_user,
            &to_user,
            req.amount,
            req.remarks,
            req.transaction_ids,
            &created_by,
        )
        .await?;
    Ok(Json(settlement))
}

#[utoipa::path(
    post,
    path = "/settlements/confirm",
    request_body = ConfirmSettlementRequest,
    responses(
        (status = 200, description = "Settlement confirmed successfully"),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 403, description = "Not authorized", body = ErrorResponse),
        (status = 404, description = "Settlement or user not found", body = ErrorResponse),
        (status = 409, description = "Settlement already confirmed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn confirm_settlement(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<ConfirmSettlementRequest>,
) -> Result<StatusCode, ApiError> {
    let confirmed_by = service
        .get_user(&req.confirmed_by_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.confirmed_by_id))?;
    service.confirm_settlement(&req.settlement_id, &confirmed_by).await?;
    Ok(StatusCode::OK)
}

#[utoipa::path(
    post,
    path = "/settlements/pending",
    request_body = GetPendingSettlementsRequest,
    responses(
        (status = 200, description = "Pending settlements retrieved successfully", body = Vec<Settlement>),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn get_pending_settlements(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<GetPendingSettlementsRequest>,
) -> Result<Json<Vec<Settlement>>, ApiError> {
    let user = service
        .get_user(&req.user_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.user_id))?;
    let settlements = service.get_pending_settlements(&req.group_id, &user).await?;
    Ok(Json(settlements))
}

#[utoipa::path(
    post,
    path = "/balances",
    request_body = GetUserBalancesRequest,
    responses(
        (status = 200, description = "User balances retrieved successfully", body = UserBalancesResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn get_user_balances(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<GetUserBalancesRequest>,
) -> Result<Json<UserBalancesResponse>, ApiError> {
    let queried_by = service
        .get_user(&req.queried_by_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.queried_by_id))?;
    let balances = service.get_user_balances(&req.user_id, &queried_by).await?;
    Ok(Json(balances))
}

#[utoipa::path(
    post,
    path = "/transactions/effective",
    request_body = GetEffectiveTransactionsRequest,
    responses(
        (status = 200, description = "Effective transactions retrieved successfully", body = Vec<Transaction>),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn get_effective_transactions(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<GetEffectiveTransactionsRequest>,
) -> Result<Json<Vec<Transaction>>, ApiError> {
    let queried_by = service
        .get_user(&req.queried_by_id)
        .await?
        .ok_or_else(|| BillioError::UserNotFound(req.queried_by_id))?;
    let transactions = service.get_effective_transactions(&req.group_id, &queried_by).await?;
    Ok(Json(transactions))
}

#[utoipa::path(
    get,
    path = "/logs",
    responses(
        (status = 200, description = "Application logs retrieved successfully", body = Vec<AppLog>),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn get_app_logs(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
) -> Result<Json<Vec<AppLog>>, ApiError> {
    let logs = service.get_app_logs().await?;
    Ok(Json(logs))
}

#[utoipa::path(
    get,
    path = "/groups/{group_id}/audits",
    params(
        ("group_id" = String, Path, description = "ID of the group")
    ),
    responses(
        (status = 200, description = "Group audits retrieved successfully", body = Vec<GroupAudit>),
        (status = 404, description = "Group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn get_group_audits(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
) -> Result<Json<Vec<GroupAudit>>, ApiError> {
    let audits = service.get_group_audits(&group_id).await?;
    Ok(Json(audits))
}

// Define OpenAPI schema
#[derive(OpenApi)]
#[openapi(
    paths(
        create_user,
        get_user,
        create_group,
        delete_group,
        join_group_by_link,
        add_member_to_group,
        add_member_by_email,
        remove_member_from_group,
        revoke_join_link,
        regenerate_join_link,
        toggle_strict_settlement_mode,
        transfer_ownership,
        add_expense,
        reverse_transaction,
        create_settlement,
        confirm_settlement,
        get_pending_settlements,
        get_user_balances,
        get_effective_transactions,
        get_app_logs,
        get_group_audits
    ),
    components(schemas(
        CreateUserRequest,
        CreateGroupRequest,
        AddMemberRequest,
        AddMemberByEmailRequest,
        RemoveMemberRequest,
        JoinGroupRequest,
        RevokeJoinLinkRequest,
        RegenerateJoinLinkRequest,
        ToggleStrictModeRequest,
        TransferOwnershipRequest,
        AddExpenseRequest,
        ReverseTransactionRequest,
        CreateSettlementRequest,
        ConfirmSettlementRequest,
        GetPendingSettlementsRequest,
        DeleteGroupRequest,
        GetUserBalancesRequest,
        GetEffectiveTransactionsRequest,
        ErrorResponse,
        User,
        Group,
        Settlement,
        Transaction,
        AppLog,
        GroupAudit,
        UserBalancesResponse
    )),
    info(
        title = "Billio API",
        description = "API for managing group expenses and settlements",
        version = "0.1.0"
    )
)]
struct ApiDoc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt().with_env_filter("info").init();

    // Initialize storage and logging
    let cache = InMemoryCache::new();
    let storage = InMemoryStorage::new();
    let logging = InMemoryLogging::new();
    let billio = Arc::new(BillioService::new(storage, logging, cache));

    // Define API routes
    let app = Router::new()
        // Health check endpoint
        .route("/", get(|| async { "OK" }))
        .route("/users", post(create_user))
        .route("/users/{user_id}", get(get_user))
        .route("/groups", post(create_group))
        .route("/groups/{group_id}", axum::routing::delete(delete_group))
        .route("/groups/join", post(join_group_by_link))
        .route("/groups/{group_id}/members", post(add_member_to_group))
        .route("/groups/{group_id}/members/email", post(add_member_by_email))
        .route("/groups/{group_id}/members/remove", post(remove_member_from_group))
        .route("/groups/{group_id}/join_link/revoke", post(revoke_join_link))
        .route("/groups/{group_id}/join_link/regenerate", post(regenerate_join_link))
        .route("/groups/{group_id}/strict_mode", post(toggle_strict_settlement_mode))
        .route("/groups/{group_id}/ownership", post(transfer_ownership))
        .route("/expenses", post(add_expense))
        .route("/transactions/reverse", post(reverse_transaction))
        .route("/settlements", post(create_settlement))
        .route("/settlements/confirm", post(confirm_settlement))
        .route("/settlements/pending", post(get_pending_settlements))
        .route("/balances", post(get_user_balances))
        .route("/transactions/effective", post(get_effective_transactions))
        .route("/logs", get(get_app_logs))
        .route("/groups/{group_id}/audits", get(get_group_audits))
        // Add Swagger UI route
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(CompressionLayer::new()) // Gzip compression
        .layer(TimeoutLayer::new(Duration::from_secs(30))) // 30-second timeout
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([http::Method::GET, http::Method::POST])
                .allow_headers([header::CONTENT_TYPE]),
        )
        .layer(TraceLayer::new_for_http()) // Request tracing
        .with_state(billio);

    // Start server
    let addr = SocketAddr::from(([127, 0, 0, 1], CONFIG.port));
    info!("Server running at http://{}", addr);
    // swagger UI will be available at http://<host>:<port>/swagger-ui
    info!("Swagger UI available at http://{}/swagger-ui", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
