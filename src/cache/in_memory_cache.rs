use crate::error::SplitwiseError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

#[async_trait]
pub trait Cache: Send + Sync {
    /// Get a value from the cache by key
    async fn get<T: for<'a> Deserialize<'a> + Send + Sync>(&self, key: &str) -> Result<Option<T>, SplitwiseError>;

    /// Set a value in the cache with an optional TTL (in seconds)
    async fn set<T: Serialize + Send + Sync>(
        &self,
        key: &str,
        value: &T,
        ttl: Option<u64>,
    ) -> Result<(), SplitwiseError>;

    /// Delete a key from the cache
    async fn del(&self, key: &str) -> Result<(), SplitwiseError>;
}

/// In-memory cache implementation for testing
pub struct InMemoryCache {
    store: RwLock<HashMap<String, (String, Option<std::time::Instant>)>>,
}

impl InMemoryCache {
    pub fn new() -> Self {
        InMemoryCache {
            store: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Cache for InMemoryCache {
    async fn get<T: for<'a> Deserialize<'a> + Send + Sync>(&self, key: &str) -> Result<Option<T>, SplitwiseError> {
        let store = self.store.read().await;
        if let Some((value, expiry)) = store.get(key) {
            if expiry.map_or(true, |e| e > std::time::Instant::now()) {
                let deserialized = serde_json::from_str(value)
                    .map_err(|e| SplitwiseError::InternalServerError(format!("Cache deserialization failed: {}", e)))?;
                Ok(Some(deserialized))
            } else {
                drop(store); // Release read lock before acquiring write lock
                let mut store = self.store.write().await;
                store.remove(key);
                Ok(None) // Expired and removed
            }
        } else {
            Ok(None)
        }
    }

    async fn set<T: Serialize + Send + Sync>(
        &self,
        key: &str,
        value: &T,
        ttl: Option<u64>,
    ) -> Result<(), SplitwiseError> {
        let serialized = serde_json::to_string(value)
            .map_err(|e| SplitwiseError::InternalServerError(format!("Cache serialization failed: {}", e)))?;
        let expiry = ttl.map(|t| std::time::Instant::now() + std::time::Duration::from_secs(t));
        let mut store = self.store.write().await;
        store.insert(key.to_string(), (serialized, expiry));
        Ok(())
    }

    async fn del(&self, key: &str) -> Result<(), SplitwiseError> {
        let mut store = self.store.write().await;
        store.remove(key);
        Ok(())
    }
}
