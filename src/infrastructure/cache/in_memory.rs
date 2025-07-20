use crate::core::errors::BillioError;
use crate::core::services::UserBalancesResponse;
use crate::infrastructure::cache::Cache;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct InMemoryCache {
    cache: Arc<RwLock<HashMap<String, (UserBalancesResponse, chrono::DateTime<chrono::Utc>)>>>,
}

impl InMemoryCache {
    pub fn new() -> Self {
        InMemoryCache {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl Cache for InMemoryCache {
    async fn get_user_balances(&self, user_id: &str) -> Result<Option<UserBalancesResponse>, BillioError> {
        let cache = self.cache.read().await;
        let key = crate::infrastructure::cache::cache_keys::user_balances_key(user_id);
        Ok(cache.get(&key).map(|(balances, _)| (*balances).clone()))
    }

    async fn save_user_balances(
        &self,
        user_id: &str,
        balances: &UserBalancesResponse,
        ttl: std::time::Duration,
    ) -> Result<(), BillioError> {
        let mut cache = self.cache.write().await;
        let key = crate::infrastructure::cache::cache_keys::user_balances_key(user_id);
        cache.insert(
            key,
            (
                balances.clone(),
                chrono::Utc::now()
                    + chrono::Duration::from_std(ttl)
                        .map_err(|e| BillioError::CacheError(format!("Failed to convert TTL: {}", e)))?,
            ),
        );
        Ok(())
    }

    async fn invalidate_user_balances(&self, _group_id: &str) -> Result<(), BillioError> {
        let mut cache = self.cache.write().await;
        cache.retain(|_, (_, expiry)| *expiry > chrono::Utc::now());
        Ok(())
    }
}
