use crate::logger::in_memory::InMemoryLogging;
use crate::models::group::Role;
use crate::models::user::User;
use crate::service::SplitwiseService;
use crate::storage::in_memory::InMemoryStorage;
#[tokio::test]
async fn test_create_group() {
    let storage = InMemoryStorage::new();
    let logging = InMemoryLogging::new();
    let splitwise = SplitwiseService::new(storage, logging);
    let user = User {
        id: "u1".to_string(),
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
    };
    splitwise.add_user(user.clone(), None).await.unwrap();
    let group = splitwise
        .create_group("Test".to_string(), vec![user.clone()], &user)
        .await
        .unwrap();
    assert_eq!(group.name, "Test");
    assert_eq!(group.members[0].role, Role::Owner);
}
