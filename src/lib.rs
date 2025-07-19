pub mod constants;
pub mod error;
pub mod logger;
pub mod models;
pub mod service;
pub mod storage;
pub mod visualization;

pub use error::ExpenseServiceError;
pub use logger::in_memory::InMemoryAuditLogger;
pub use service::ExpenseService;
pub use storage::in_memory::InMemoryStorage;
pub use visualization::Visualization;

#[cfg(test)]
mod tests; // Include integration tests
