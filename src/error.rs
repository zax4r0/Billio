use thiserror::Error;

#[derive(Error, Debug)]
pub enum SplitwiseError {
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
    #[error("Invalid join link")]
    InvalidJoinLink,
    #[error("Join link not found")]
    JoinLinkNotFound,
    #[error("Invalid split amounts")]
    InvalidSplit,
    #[error("User {0} is not a group member for split")]
    InvalidSplitUser(String),
    #[error("Transaction {0} not found")]
    TransactionNotFound(String),
    #[error("Cannot create settlement to self")]
    SelfSettlement,
    #[error("Settlement amount must be positive")]
    InvalidSettlementAmount,
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
}
