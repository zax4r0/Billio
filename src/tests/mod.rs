mod group_tests;
mod transaction_tests;
mod user_tests;

use crate::core::services::BillioService;
use crate::infrastructure::cache::in_memory::InMemoryCache;
use crate::infrastructure::logging::in_memory::InMemoryLogging;
use crate::infrastructure::storage::in_memory::InMemoryStorage;

pub fn create_test_service() -> BillioService<InMemoryLogging, InMemoryStorage, InMemoryCache> {
    let storage = InMemoryStorage::new();
    let logging = InMemoryLogging::new();
    let cache = InMemoryCache::new();
    BillioService::new(storage, logging, cache)
}
