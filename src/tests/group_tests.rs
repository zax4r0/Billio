use crate::cache::in_memory_cache::InMemoryCache;
use crate::logger::in_memory::InMemoryLogging;
use crate::models::group::Role;
use crate::models::user::User;
use crate::service::BillioService;
use crate::storage::in_memory::InMemoryStorage;
#[tokio::test]
async fn test_create_group() {
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
    let group = billio
        .create_group("Test".to_string(), vec![user.clone()], &user)
        .await
        .unwrap();
    assert_eq!(group.name, "Test");
    assert_eq!(group.members[0].role, Role::Owner);
}
