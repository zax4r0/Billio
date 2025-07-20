use utoipa::OpenApi;

use crate::{
    api::models::{
        AddExpenseRequest, AddMemberByEmailRequest, AddMemberRequest, ConfirmSettlementRequest, CreateGroupRequest,
        CreateSettlementRequest, CreateUserRequest, DeleteGroupRequest, ErrorResponse, GetEffectiveTransactionsRequest,
        GetPendingSettlementsRequest, GetUserBalancesRequest, JoinGroupRequest, RegenerateJoinLinkRequest,
        RemoveMemberRequest, ReverseTransactionRequest, RevokeJoinLinkRequest, ToggleStrictModeRequest,
        TransferOwnershipRequest,
    },
    core::{
        models::{
            audit::{AppLog, GroupAudit},
            group::Group,
            settlement::Settlement,
            transaction::Transaction,
            user::User,
        },
        services::UserBalancesResponse,
    },
};

#[derive(OpenApi)]
#[openapi(
    paths(
        super::handlers::login,
        super::handlers::create_user,
        super::handlers::get_user,
        super::handlers::create_group,
        super::handlers::delete_group,
        super::handlers::join_group_by_link,
        super::handlers::add_member_to_group,
        super::handlers::add_member_by_email,
        super::handlers::remove_member_from_group,
        super::handlers::revoke_join_link,
        super::handlers::regenerate_join_link,
        super::handlers::toggle_strict_settlement_mode,
        super::handlers::transfer_ownership,
        super::handlers::add_expense,
        super::handlers::reverse_transaction,
        super::handlers::create_settlement,
        super::handlers::confirm_settlement,
        super::handlers::get_pending_settlements,
        super::handlers::get_user_balances,
        super::handlers::get_effective_transactions,
        super::handlers::get_app_logs,
        super::handlers::get_group_audits
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
pub struct ApiDoc;
