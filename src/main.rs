use axum::{
    Json, Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use splitwise::service::SplitwiseService;
use splitwise::storage::in_memory::InMemoryStorage;
use splitwise::{
    cache::in_memory_cache::InMemoryCache,
    models::{
        audit::{AppLog, GroupAudit},
        group::Group,
        settlement::Settlement,
        transaction::Transaction,
        user::User,
    },
};
use splitwise::{config::CONFIG, error::SplitwiseError};
use splitwise::{logger::in_memory::InMemoryLogging, service::UserBalancesResponse};
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

// Request structs for JSON payloads
#[derive(Deserialize)]
struct CreateUserRequest {
    id: String,
    name: String,
    email: String,
    created_by_id: Option<String>,
}

#[derive(Deserialize)]
struct CreateGroupRequest {
    name: String,
    member_ids: Vec<String>,
    created_by_id: String,
}

#[derive(Deserialize)]
struct AddMemberRequest {
    user_id: String,
    added_by_id: String,
}

#[derive(Deserialize)]
struct AddMemberByEmailRequest {
    email: String,
    added_by_id: String,
}

#[derive(Deserialize)]
struct RemoveMemberRequest {
    user_id: String,
    removed_by_id: String,
}

#[derive(Deserialize)]
struct JoinGroupRequest {
    join_link: String,
    user_id: String,
}

#[derive(Deserialize)]
struct RevokeJoinLinkRequest {
    revoked_by_id: String,
}

#[derive(Deserialize)]
struct RegenerateJoinLinkRequest {
    regenerated_by_id: String,
}

#[derive(Deserialize)]
struct ToggleStrictModeRequest {
    enabled: bool,
    toggled_by_id: String,
}

#[derive(Deserialize)]
struct TransferOwnershipRequest {
    new_owner_id: String,
    transferred_by_id: String,
}

#[derive(Deserialize)]
struct AddExpenseRequest {
    group_id: String,
    description: String,
    amount: f64,
    paid_by_id: String,
    shares: HashMap<String, f64>,
    created_by_id: String,
}

#[derive(Deserialize)]
struct ReverseTransactionRequest {
    transaction_id: String,
    reversed_by_id: String,
}

#[derive(Deserialize)]
struct CreateSettlementRequest {
    group_id: String,
    from_user_id: String,
    to_user_id: String,
    amount: f64,
    remarks: Option<String>,
    transaction_ids: Option<Vec<String>>,
    created_by_id: String,
}

#[derive(Deserialize)]
struct ConfirmSettlementRequest {
    settlement_id: String,
    confirmed_by_id: String,
}

#[derive(Deserialize)]
struct GetPendingSettlementsRequest {
    group_id: String,
    user_id: String,
}

#[derive(Deserialize)]
struct DeleteGroupRequest {
    deleted_by_id: String,
}

#[derive(Deserialize)]
struct GetUserBalancesRequest {
    user_id: String,
    queried_by_id: String,
}

#[derive(Deserialize)]
struct GetEffectiveTransactionsRequest {
    group_id: String,
    queried_by_id: String,
}

// Error response struct
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// Newtype wrapper for SplitwiseError to implement IntoResponse
struct ApiError(SplitwiseError);

impl From<SplitwiseError> for ApiError {
    fn from(err: SplitwiseError) -> Self {
        ApiError(err)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self.0 {
            SplitwiseError::MissingEmail => (StatusCode::BAD_REQUEST, "Email is required".to_string()),
            SplitwiseError::EmailAlreadyRegistered(email) => {
                (StatusCode::CONFLICT, format!("Email {} already registered", email))
            }
            SplitwiseError::UserNotFound(id) => (StatusCode::NOT_FOUND, format!("User {} not found", id)),
            SplitwiseError::GroupNotFound(id) => (StatusCode::NOT_FOUND, format!("Group {} not found", id)),
            SplitwiseError::AlreadyGroupMember(id) => {
                (StatusCode::CONFLICT, format!("User {} is already a group member", id))
            }
            SplitwiseError::NotGroupMember(id) => (StatusCode::FORBIDDEN, format!("User {} is not a group member", id)),
            SplitwiseError::NotGroupOwner(id) => (StatusCode::FORBIDDEN, format!("User {} is not group owner", id)),
            SplitwiseError::InvalidOwnerCount(count) => {
                (StatusCode::BAD_REQUEST, format!("Invalid owner count: {}", count))
            }
            SplitwiseError::OwnerCannotRemoveSelf => {
                (StatusCode::FORBIDDEN, "Owner cannot remove themselves".to_string())
            }
            SplitwiseError::CannotRemoveLastMember => {
                (StatusCode::BAD_REQUEST, "Cannot remove last group member".to_string())
            }
            SplitwiseError::InvalidJoinLink => (StatusCode::BAD_REQUEST, "Invalid join link".to_string()),
            SplitwiseError::JoinLinkNotFound => (StatusCode::NOT_FOUND, "Join link not found".to_string()),
            SplitwiseError::InvalidSplit => (StatusCode::BAD_REQUEST, "Invalid split amounts".to_string()),
            SplitwiseError::InvalidSplitUser(id) => (
                StatusCode::BAD_REQUEST,
                format!("User {} is not a group member for split", id),
            ),
            SplitwiseError::TransactionNotFound(id) => (StatusCode::NOT_FOUND, format!("Transaction {} not found", id)),
            SplitwiseError::SelfSettlement => (StatusCode::BAD_REQUEST, "Cannot create settlement to self".to_string()),
            SplitwiseError::InvalidSettlementAmount => (
                StatusCode::BAD_REQUEST,
                "Settlement amount must be positive".to_string(),
            ),
            SplitwiseError::InvalidSettlementTransaction(id) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid transaction {} for settlement", id),
            ),
            SplitwiseError::SettlementNotFound(id) => (StatusCode::NOT_FOUND, format!("Settlement {} not found", id)),
            SplitwiseError::SettlementAlreadyConfirmed(id) => {
                (StatusCode::CONFLICT, format!("Settlement {} already confirmed", id))
            }
            SplitwiseError::UnauthorizedSettlementConfirmation(id) => (
                StatusCode::FORBIDDEN,
                format!("User {} not authorized to confirm settlement", id),
            ),
            SplitwiseError::TransactionAlreadyReversed(id) => (
                StatusCode::CONFLICT,
                format!("Transaction {} has already been reversed", id),
            ),
            SplitwiseError::InvalidEmail(email) => (StatusCode::BAD_REQUEST, format!("Invalid email: {}", email)),
            SplitwiseError::InvalidInput(field, msg) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid input for {}: {:?}", field, msg),
            ),
            SplitwiseError::InternalServerError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Internal server error: {}", msg),
            ),
            SplitwiseError::StorageError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Storage error: {}", msg)),
            SplitwiseError::LoggingError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Logging error: {}", msg)),
            SplitwiseError::DatabaseError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Database error: {}", msg))
            }
            SplitwiseError::UnexpectedError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Unexpected error: {}", msg))
            }
            SplitwiseError::CacheError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Cache error: {}", msg)),
        };
        (status, Json(ErrorResponse { error: error_message })).into_response()
    }
}

async fn create_user(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
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
                .ok_or_else(|| SplitwiseError::UserNotFound(id.clone()))?,
        )
    } else {
        None
    };
    service.add_user(user, created_by_user.as_ref()).await?;
    Ok(StatusCode::CREATED)
}

async fn get_user(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(user_id): Path<String>,
) -> Result<Json<User>, ApiError> {
    let user = service
        .get_user(&user_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(user_id))?;
    Ok(Json(user))
}

async fn create_group(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<Group>, ApiError> {
    let created_by = service
        .get_user(&req.created_by_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.created_by_id))?;
    let members = req
        .member_ids
        .into_iter()
        .map(|id| async {
            service
                .get_user(&id)
                .await?
                .ok_or_else(|| SplitwiseError::UserNotFound(id))
        })
        .collect::<Vec<_>>();
    let members = futures::future::try_join_all(members).await?;
    let group = service.create_group(req.name, members, &created_by).await?;
    Ok(Json(group))
}

async fn delete_group(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
    Json(req): Json<DeleteGroupRequest>,
) -> Result<StatusCode, ApiError> {
    let deleted_by = service
        .get_user(&req.deleted_by_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.deleted_by_id))?;
    service.delete_group(&group_id, &deleted_by).await?;
    Ok(StatusCode::OK)
}

async fn join_group_by_link(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<JoinGroupRequest>,
) -> Result<StatusCode, ApiError> {
    let user = service
        .get_user(&req.user_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.user_id))?;
    service.join_group_by_link(&req.join_link, &user).await?;
    Ok(StatusCode::OK)
}

async fn add_member_to_group(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> Result<StatusCode, ApiError> {
    let user = service
        .get_user(&req.user_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.user_id))?;
    let added_by = service
        .get_user(&req.added_by_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.added_by_id))?;
    service.add_member_to_group(&group_id, user, &added_by).await?;
    Ok(StatusCode::OK)
}

async fn add_member_by_email(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
    Json(req): Json<AddMemberByEmailRequest>,
) -> Result<StatusCode, ApiError> {
    let added_by = service
        .get_user(&req.added_by_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.added_by_id))?;
    service.add_member_by_email(&group_id, &req.email, &added_by).await?;
    Ok(StatusCode::OK)
}

async fn remove_member_from_group(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
    Json(req): Json<RemoveMemberRequest>,
) -> Result<StatusCode, ApiError> {
    let removed_by = service
        .get_user(&req.removed_by_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.removed_by_id))?;
    service
        .remove_member_from_group(&group_id, &req.user_id, &removed_by)
        .await?;
    Ok(StatusCode::OK)
}

async fn revoke_join_link(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
    Json(req): Json<RevokeJoinLinkRequest>,
) -> Result<StatusCode, ApiError> {
    let revoked_by = service
        .get_user(&req.revoked_by_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.revoked_by_id))?;
    service.revoke_join_link(&group_id, &revoked_by).await?;
    Ok(StatusCode::OK)
}

async fn regenerate_join_link(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
    Json(req): Json<RegenerateJoinLinkRequest>,
) -> Result<Json<String>, ApiError> {
    let regenerated_by = service
        .get_user(&req.regenerated_by_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.regenerated_by_id))?;
    let new_link = service.regenerate_join_link(&group_id, &regenerated_by).await?;
    Ok(Json(new_link))
}

async fn toggle_strict_settlement_mode(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
    Json(req): Json<ToggleStrictModeRequest>,
) -> Result<StatusCode, ApiError> {
    let toggled_by = service
        .get_user(&req.toggled_by_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.toggled_by_id))?;
    service
        .toggle_strict_settlement_mode(&group_id, req.enabled, &toggled_by)
        .await?;
    Ok(StatusCode::OK)
}

async fn transfer_ownership(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
    Json(req): Json<TransferOwnershipRequest>,
) -> Result<StatusCode, ApiError> {
    let new_owner = service
        .get_user(&req.new_owner_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.new_owner_id))?;
    let transferred_by = service
        .get_user(&req.transferred_by_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.transferred_by_id))?;
    service
        .transfer_ownership(&group_id, &new_owner, &transferred_by)
        .await?;
    Ok(StatusCode::OK)
}

async fn add_expense(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<AddExpenseRequest>,
) -> Result<Json<Transaction>, ApiError> {
    let paid_by = service
        .get_user(&req.paid_by_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.paid_by_id))?;
    let created_by = service
        .get_user(&req.created_by_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.created_by_id))?;
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

async fn reverse_transaction(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<ReverseTransactionRequest>,
) -> Result<Json<Transaction>, ApiError> {
    let reversed_by = service
        .get_user(&req.reversed_by_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.reversed_by_id))?;
    let reversal = service.reverse_transaction(&req.transaction_id, &reversed_by).await?;
    Ok(Json(reversal))
}

async fn create_settlement(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<CreateSettlementRequest>,
) -> Result<Json<Settlement>, ApiError> {
    let from_user = service
        .get_user(&req.from_user_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.from_user_id))?;
    let to_user = service
        .get_user(&req.to_user_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.to_user_id))?;
    let created_by = service
        .get_user(&req.created_by_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.created_by_id))?;
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

async fn confirm_settlement(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<ConfirmSettlementRequest>,
) -> Result<StatusCode, ApiError> {
    let confirmed_by = service
        .get_user(&req.confirmed_by_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.confirmed_by_id))?;
    service.confirm_settlement(&req.settlement_id, &confirmed_by).await?;
    Ok(StatusCode::OK)
}

async fn get_pending_settlements(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<GetPendingSettlementsRequest>,
) -> Result<Json<Vec<Settlement>>, ApiError> {
    let user = service
        .get_user(&req.user_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.user_id))?;
    let settlements = service.get_pending_settlements(&req.group_id, &user).await?;
    Ok(Json(settlements))
}

async fn get_user_balances(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<GetUserBalancesRequest>,
) -> Result<Json<UserBalancesResponse>, ApiError> {
    let queried_by = service
        .get_user(&req.queried_by_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.queried_by_id))?;
    let balances = service.get_user_balances(&req.user_id, &queried_by).await?;
    Ok(Json(balances))
}

async fn get_effective_transactions(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<GetEffectiveTransactionsRequest>,
) -> Result<Json<Vec<Transaction>>, ApiError> {
    let queried_by = service
        .get_user(&req.queried_by_id)
        .await?
        .ok_or_else(|| SplitwiseError::UserNotFound(req.queried_by_id))?;
    let transactions = service.get_effective_transactions(&req.group_id, &queried_by).await?;
    Ok(Json(transactions))
}

async fn get_app_logs(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
) -> Result<Json<Vec<AppLog>>, ApiError> {
    let logs = service.get_app_logs().await?;
    Ok(Json(logs))
}

async fn get_group_audits(
    State(service): State<Arc<SplitwiseService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
) -> Result<Json<Vec<GroupAudit>>, ApiError> {
    let audits = service.get_group_audits(&group_id).await?;
    Ok(Json(audits))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt().with_env_filter("info").init();

    // Initialize storage and logging
    let cache = InMemoryCache::new();
    let storage = InMemoryStorage::new();
    let logging = InMemoryLogging::new();
    let splitwise = Arc::new(SplitwiseService::new(storage, logging, cache));

    // Define API routes
    let app = Router::new()
        // add / route with a simple health check
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
        .layer(CompressionLayer::new()) // Gzip compression
        .layer(TimeoutLayer::new(Duration::from_secs(30))) // 30-second timeout
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([http::Method::GET, http::Method::POST])
                .allow_headers([header::CONTENT_TYPE]),
        )
        .layer(TraceLayer::new_for_http()) // Request tracing
        .with_state(splitwise);

    // Start server
    let addr = SocketAddr::from(([127, 0, 0, 1], CONFIG.port));
    info!("Server running at http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
