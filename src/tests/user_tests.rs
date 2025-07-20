use crate::cache::in_memory_cache::InMemoryCache;
use crate::error::BillioError;
use crate::logger::in_memory::InMemoryLogging;
use crate::models::user::User;
use crate::service::BillioService;
use crate::storage::in_memory::InMemoryStorage;

#[tokio::test]
async fn test_add_user() {
    let cache = InMemoryCache::new();
    let storage = InMemoryStorage::new();
    let logging = InMemoryLogging::new();
    let billio = BillioService::new(storage, logging, cache);

    let user = User {
        id: "u1".to_string(),
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
    };
    billio.add_user(user.clone(), None).await.unwrap();
    assert_eq!(billio.get_user("u1").await.unwrap().unwrap().email, "alice@example.com");
}

#[tokio::test]
async fn test_duplicate_email() {
    let cache = InMemoryCache::new();
    let storage = InMemoryStorage::new();
    let logging = InMemoryLogging::new();
    let billio = BillioService::new(storage, logging, cache);

    let user1 = User {
        id: "u1".to_string(),
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
    };
    let user2 = User {
        id: "u2".to_string(),
        name: "Bob".to_string(),
        email: "alice@example.com".to_string(),
    };
    billio.add_user(user1, None).await.unwrap();
    let result = billio.add_user(user2, None).await;
    assert!(matches!(result, Err(BillioError::EmailAlreadyRegistered(_))));
}
