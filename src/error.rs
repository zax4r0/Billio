use std::fmt;

#[derive(Debug)]
pub enum ExpenseServiceError {
    UserNotFound,
    GroupNotFound,
    TransactionNotFound,
    EmailInUse,
    NotGroupMember,
    NotAuthorized,
    InvalidSplit,
    AlreadyDeleted,
    InvalidJoinLink,
    UserAlreadyInGroup,
    GroupAlreadyExists,
    TransactionAlreadyExists,
    UserAlreadyExists,
    NoBalancesAvailable,
}

impl fmt::Display for ExpenseServiceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::UserNotFound => write!(f, "User not found"),
            Self::GroupNotFound => write!(f, "Group not found"),
            Self::TransactionNotFound => write!(f, "Transaction not found"),
            Self::EmailInUse => write!(f, "Email already in use"),
            Self::NotGroupMember => write!(f, "User not in group"),
            Self::NotAuthorized => write!(f, "User not authorized"),
            Self::InvalidSplit => write!(f, "Invalid split configuration"),
            Self::AlreadyDeleted => write!(f, "Transaction already deleted"),
            Self::InvalidJoinLink => write!(f, "Invalid join link"),
            Self::UserAlreadyInGroup => write!(f, "User already in group"),
            Self::GroupAlreadyExists => write!(f, "Group already exists"),
            Self::TransactionAlreadyExists => write!(f, "Transaction already exists"),
            Self::UserAlreadyExists => write!(f, "User already exists"),
            Self::NoBalancesAvailable => write!(f, "No balances available"),
        }
    }
}

impl std::error::Error for ExpenseServiceError {}
