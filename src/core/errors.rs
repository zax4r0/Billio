use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Serialize)]
pub struct FieldError {
    pub field: String,
    pub title: String,
    pub description: String,
}

#[derive(Error, Debug, Serialize)]
pub enum BillioError {
    #[error("Email is required")]
    MissingEmail,
    #[error("Email {0} already registered")]
    EmailAlreadyRegistered(String),
    #[error("User {0} not found")]
    UserNotFound(String),
    #[error("Group {0} not found")]
    GroupNotFound(String),
    #[error("User {0} is already a group member")]
    AlreadyGroupMember(String),
    #[error("User {0} is not a group member")]
    NotGroupMember(String),
    #[error("User {0} is not group owner")]
    NotGroupOwner(String),
    #[error("Invalid owner count: {0}")]
    InvalidOwnerCount(usize),
    #[error("Owner cannot remove themselves")]
    OwnerCannotRemoveSelf,
    #[error("Cannot remove last group member")]
    CannotRemoveLastMember,
    #[error("Join link not found")]
    JoinLinkNotFound,
    #[error("Cannot create settlement to self")]
    SelfSettlement,
    #[error("Transaction {0} not found")]
    TransactionNotFound(String),
    #[error("Invalid transaction {0} for settlement")]
    InvalidSettlementTransaction(String),
    #[error("Settlement {0} not found")]
    SettlementNotFound(String),
    #[error("Settlement {0} already confirmed")]
    SettlementAlreadyConfirmed(String),
    #[error("User {0} not authorized to confirm settlement")]
    UnauthorizedSettlementConfirmation(String),
    #[error("Transaction {0} already reversed")]
    TransactionAlreadyReversed(String),
    #[error("Invalid email format: {0}")]
    InvalidEmail(String),
    #[error("Invalid input for field `{0}`: {1:?}")]
    InvalidInput(String, FieldError),
    #[error("Internal server error: {0}")]
    InternalServerError(String),
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
    #[error("Invalid split user: {0}")]
    InvalidSplitUser(String),
    #[error("Invalid join link")]
    InvalidJoinLink,
    #[error("Invalid settlement amount")]
    InvalidSettlementAmount,
    #[error("Invalid split amounts")]
    InvalidSplit,
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Logging error: {0}")]
    LoggingError(String),
    #[error("Cache error: {0}")]
    CacheError(String),
    #[error("Invalid credentials")]
    InvalidCredentials,
}
