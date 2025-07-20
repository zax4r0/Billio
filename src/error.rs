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
    /// Email field is empty
    #[error("Email is required")]
    MissingEmail,

    /// Email is already registered
    #[error("Email {0} already registered")]
    EmailAlreadyRegistered(String),

    /// User with given ID not found
    #[error("User {0} not found")]
    UserNotFound(String),

    /// Group with given ID not found
    #[error("Group {0} not found")]
    GroupNotFound(String),

    /// User is already a member of the group
    #[error("User {0} is already a group member")]
    AlreadyGroupMember(String),

    /// User is not a member of the group
    #[error("User {0} is not a group member")]
    NotGroupMember(String),

    /// User is not the group owner
    #[error("User {0} is not group owner")]
    NotGroupOwner(String),

    /// Group has an invalid number of owners (must be exactly 1)
    #[error("Invalid owner count: {0}")]
    InvalidOwnerCount(usize),

    /// Group owner cannot remove themselves
    #[error("Owner cannot remove themselves")]
    OwnerCannotRemoveSelf,

    /// Cannot remove the last member of a group
    #[error("Cannot remove last group member")]
    CannotRemoveLastMember,

    /// Join link is not valid or not found
    #[error("Join link not found")]
    JoinLinkNotFound,

    /// Cannot create a settlement from a user to themselves
    #[error("Cannot create settlement to self")]
    SelfSettlement,

    /// Transaction with given ID not found
    #[error("Transaction {0} not found")]
    TransactionNotFound(String),

    /// Transaction is invalid for the settlement
    #[error("Invalid transaction {0} for settlement")]
    InvalidSettlementTransaction(String),

    /// Settlement with given ID not found
    #[error("Settlement {0} not found")]
    SettlementNotFound(String),

    /// Settlement has already been confirmed
    #[error("Settlement {0} already confirmed")]
    SettlementAlreadyConfirmed(String),

    /// User is not authorized to confirm the settlement
    #[error("User {0} not authorized to confirm settlement")]
    UnauthorizedSettlementConfirmation(String),

    /// Transaction has already been reversed
    #[error("Transaction {0} already reversed")]
    TransactionAlreadyReversed(String),

    /// Email format is invalid
    #[error("Invalid email format: {0}")]
    InvalidEmail(String),

    /// Generic input validation error with detailed field information
    #[error("Invalid input for field `{0}`: {1:?}")]
    InvalidInput(String, FieldError),

    /// Internal server error (e.g., unexpected failure)
    #[error("Internal server error: {0}")]
    InternalServerError(String),

    /// Database operation failed
    #[error("Database error: {0}")]
    DatabaseError(String),

    /// Catch-all for unexpected errors
    #[error("Unexpected error: {0}")]
    UnexpectedError(String),

    /// User specified in split is invalid
    #[error("Invalid split user: {0}")]
    InvalidSplitUser(String),

    /// Join link is invalid or malformed
    #[error("Invalid join link")]
    InvalidJoinLink,

    /// Settlement amount is invalid or doesn't match transaction
    #[error("Invalid settlement amount")]
    InvalidSettlementAmount,

    /// Split amounts don't add up correctly
    #[error("Invalid split amounts")]
    InvalidSplit,
    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Logging error: {0}")]
    LoggingError(String),

    #[error("Cache error: {0}")]
    CacheError(String),
}
