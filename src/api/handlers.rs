use crate::{
    api::models::*,
    core::{
        errors::BillioError,
        models::{
            audit::{AppLog, GroupAudit},
            group::Group,
            settlement::Settlement,
            transaction::Transaction,
            user::User,
        },
        services::{BillioService, UserBalancesResponse},
    },
    infrastructure::{
        cache::in_memory::InMemoryCache, logging::in_memory::InMemoryLogging, storage::in_memory::InMemoryStorage,
    },
};
use axum::{
    Json, Router,
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::IntoResponse,
};
use http::header;

use std::sync::Arc;

// / Middleware to validate JWT
async fn auth_middleware(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<impl IntoResponse, ApiError> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| BillioError::UnauthorizedSettlementConfirmation("Missing Authorization header".to_string()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| BillioError::UnauthorizedSettlementConfirmation("Invalid Authorization header".to_string()))?;

    let claims = service.validate_token(token)?;
    req.extensions_mut().insert(claims);
    Ok(next.run(req).await)
}

// Define API routes
pub fn api_routes(service: Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>) -> Router {
    let protected_routes = Router::new()
        .route("/users/{user_id}", axum::routing::get(get_user))
        .route("/groups", axum::routing::post(create_group))
        .route("/groups/{group_id}", axum::routing::delete(delete_group))
        .route("/groups/join", axum::routing::post(join_group_by_link))
        .route("/groups/{group_id}/members", axum::routing::post(add_member_to_group))
        .route(
            "/groups/{group_id}/members/email",
            axum::routing::post(add_member_by_email),
        )
        .route(
            "/groups/{group_id}/members/remove",
            axum::routing::post(remove_member_from_group),
        )
        .route(
            "/groups/{group_id}/join_link/revoke",
            axum::routing::post(revoke_join_link),
        )
        .route(
            "/groups/{group_id}/join_link/regenerate",
            axum::routing::post(regenerate_join_link),
        )
        .route(
            "/groups/{group_id}/strict_mode",
            axum::routing::post(toggle_strict_settlement_mode),
        )
        .route("/groups/{group_id}/ownership", axum::routing::post(transfer_ownership))
        .route("/expenses", axum::routing::post(add_expense))
        .route("/transactions/reverse", axum::routing::post(reverse_transaction))
        .route("/settlements", axum::routing::post(create_settlement))
        .route("/settlements/confirm", axum::routing::post(confirm_settlement))
        .route("/settlements/pending", axum::routing::post(get_pending_settlements))
        .route("/balances", axum::routing::post(get_user_balances))
        .route(
            "/transactions/effective",
            axum::routing::post(get_effective_transactions),
        )
        .route("/logs", axum::routing::get(get_app_logs))
        .route("/groups/{group_id}/audits", axum::routing::get(get_group_audits))
        .route_layer(middleware::from_fn_with_state(service.clone(), auth_middleware));

    Router::new()
        .route("/login", axum::routing::post(login))
        .route("/users", axum::routing::post(create_user)) // Unprotected
        .merge(protected_routes)
        .with_state(service)
}

#[utoipa::path(
    post,
    path = "/api/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 401, description = "Invalid credentials", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
async fn login(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let token = service.authenticate(&req.email, &req.password).await?;
    Ok(Json(LoginResponse { token }))
}

#[utoipa::path(
    post,
    path = "/api/users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created successfully"),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 409, description = "Email already registered", body = ErrorResponse),
        (status = 404, description = "Created by user not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("Bearer" = []))
)]
async fn create_user(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Json(req): Json<CreateUserRequest>,
) -> Result<StatusCode, ApiError> {
    let user = User {
        id: req.id,
        name: req.name,
        email: req.email,
        password: req.password,
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
    path = "/api/users/{user_id}",
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
    path = "/api/groups",
    request_body = CreateGroupRequest,
    responses(
        (status = 200, description = "Group created successfully", body = Group),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("Bearer" = []))
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
    path = "/api/groups/{group_id}",
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
    ),
    security(("Bearer" = []))
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
    path = "/api/groups/join",
    request_body = JoinGroupRequest,
    responses(
        (status = 200, description = "Joined group successfully",),
        (status = 400, description = "Invalid join link", body = ErrorResponse),
        (status = 404, description = "User or join link not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("Bearer" = []))
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
    path = "/api/groups/{group_id}/members",
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
    ),
    security(("Bearer" = []))
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
    path = "/api/groups/{group_id}/members/email",
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
    ),
    security(("Bearer" = []))
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
    path = "/api/groups/{group_id}/members/remove",
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
    ),
    security(("Bearer" = []))
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
    path = "/api/groups/{group_id}/join_link/revoke",
    request_body = RevokeJoinLinkRequest,
    params(
        ("group_id" = String, Path, description = "ID of the group")
    ),
    responses(
        (status = 200, description = "Join link revoked successfully"),
        (status = 403, description = "Not authorized", body = ErrorResponse),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("Bearer" = []))
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
    path = "/api/groups/{group_id}/join_link/regenerate",
    request_body = RegenerateJoinLinkRequest,
    params(
        ("group_id" = String, Path, description = "ID of the group")
    ),
    responses(
        (status = 200, description = "Join link regenerated successfully", body = String),
        (status = 403, description = "Not authorized", body = ErrorResponse),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("Bearer" = []))
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
    path = "/api/groups/{group_id}/strict_mode",
    request_body = ToggleStrictModeRequest,
    params(
        ("group_id" = String, Path, description = "ID of the group")
    ),
    responses(
        (status = 200, description = "Strict mode toggled successfully"),
        (status = 403, description = "Not authorized", body = ErrorResponse),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("Bearer" = []))
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
    path = "/api/groups/{group_id}/ownership",
    request_body = TransferOwnershipRequest,
    params(
        ("group_id" = String, Path, description = "ID of the group")
    ),
    responses(
        (status = 200, description = "Ownership transferred successfully"),
        (status = 403, description = "Not authorized", body = ErrorResponse),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("Bearer" = []))
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
    path = "/api/expenses",
    request_body = AddExpenseRequest,
    responses(
        (status = 200, description = "Expense added successfully", body = Transaction),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("Bearer" = []))
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
    path = "/api/transactions/reverse",
    request_body = ReverseTransactionRequest,
    responses(
        (status = 200, description = "Transaction reversed successfully", body = Transaction),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 404, description = "Transaction or user not found", body = ErrorResponse),
        (status = 409, description = "Transaction already reversed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("Bearer" = []))
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
    path = "/api/settlements",
    request_body = CreateSettlementRequest,
    responses(
        (status = 200, description = "Settlement created successfully", body = Settlement),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 409, description = "Self settlement or invalid transaction", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("Bearer" = []))
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
    path = "/api/settlements/confirm",
    request_body = ConfirmSettlementRequest,
    responses(
        (status = 200, description = "Settlement confirmed successfully"),
        (status = 400, description = "Bad request", body = ErrorResponse),
        (status = 403, description = "Not authorized", body = ErrorResponse),
        (status = 404, description = "Settlement or user not found", body = ErrorResponse),
        (status = 409, description = "Settlement already confirmed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("Bearer" = []))
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
    path = "/api/settlements/pending",
    request_body = GetPendingSettlementsRequest,
    responses(
        (status = 200, description = "Pending settlements retrieved successfully", body = Vec<Settlement>),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("Bearer" = []))
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
    path = "/api/balances",
    request_body = GetUserBalancesRequest,
    responses(
        (status = 200, description = "User balances retrieved successfully", body = UserBalancesResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("Bearer" = []))
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
    path = "/api/transactions/effective",
    request_body = GetEffectiveTransactionsRequest,
    responses(
        (status = 200, description = "Effective transactions retrieved successfully", body = Vec<Transaction>),
        (status = 404, description = "User or group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("Bearer" = []))
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
    path = "/api/logs",
    responses(
        (status = 200, description = "Application logs retrieved successfully", body = Vec<AppLog>),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("Bearer" = []))
)]
async fn get_app_logs(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
) -> Result<Json<Vec<AppLog>>, ApiError> {
    let logs = service.get_app_logs().await?;
    Ok(Json(logs))
}

#[utoipa::path(
    get,
    path = "/api/groups/{group_id}/audits",
    params(
        ("group_id" = String, Path, description = "ID of the group")
    ),
    responses(
        (status = 200, description = "Group audits retrieved successfully", body = Vec<GroupAudit>),
        (status = 404, description = "Group not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    ),
    security(("Bearer" = []))
)]
async fn get_group_audits(
    State(service): State<Arc<BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache>>>,
    Path(group_id): Path<String>,
) -> Result<Json<Vec<GroupAudit>>, ApiError> {
    let audits = service.get_group_audits(&group_id).await?;
    Ok(Json(audits))
}
