use acme::{ExpenseService, InMemoryAuditLogger, InMemoryStorage};
use env_logger;

fn main() {
    env_logger::init();
    let mut storage = InMemoryStorage::new();
    let mut audit_logger = InMemoryAuditLogger::new();
    let mut service = ExpenseService::new(&mut storage, &mut audit_logger);

    let user = service
        .create_user(
            "user@example.com".to_string(),
            "hashed_password".to_string(),
            "User".to_string(),
        )
        .unwrap();

    let group = service
        .create_group(&user, "Test Group".to_string(), true)
        .unwrap();

    let user2 = service
        .create_user(
            "user2@example.com".to_string(),
            "hashed_password".to_string(),
            "User 2".to_string(),
        )
        .unwrap();

    service
        .join_group_by_link(&user2, &group.join_link)
        .unwrap();
}
