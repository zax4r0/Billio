pub mod cache_keys;
pub mod in_memory;

use crate::core::errors::BillioError;
use crate::core::services::UserBalancesResponse;
use async_trait::async_trait;

#[async_trait]
pub trait Cache: Send + Sync {
    async fn get_user_balances(&self, user_id: &str) -> Result<Option<UserBalancesResponse>, BillioError>;
    async fn save_user_balances(
        &self,
        user_id: &str,
        balances: &UserBalancesResponse,
        ttl: std::time::Duration,
    ) -> Result<(), BillioError>;
    async fn invalidate_user_balances(&self, group_id: &str) -> Result<(), BillioError>;
}
