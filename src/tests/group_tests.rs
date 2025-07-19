use crate::{ExpenseService, ExpenseServiceError, InMemoryAuditLogger, InMemoryStorage};
use env_logger;

#[test]
fn test_create_group_with_correct_group_user() {
    let _ = env_logger::try_init();
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

    assert_eq!(group.name, "Test Group");
    assert_eq!(group.owner_id, user.id);
    assert_eq!(group.users.len(), 1);
    assert_eq!(group.users[0].group_id, group.id);
    assert_eq!(group.users[0].user_id, user.id);
    assert_eq!(group.users[0].role, crate::models::Role::Owner);
    let logs = audit_logger.get_logs();
    assert_eq!(logs.len(), 2);
    assert_eq!(logs[1].action, crate::models::AuditAction::CreateGroup);
}

#[test]
fn test_remove_user_from_group() {
    let _ = env_logger::try_init();
    let mut storage = InMemoryStorage::new();
    let mut audit_logger = InMemoryAuditLogger::new();
    let mut service = ExpenseService::new(&mut storage, &mut audit_logger);

    let user1 = service
        .create_user(
            "user1@example.com".to_string(),
            "hashed_password".to_string(),
            "User 1".to_string(),
        )
        .unwrap();

    let user2 = service
        .create_user(
            "user2@example.com".to_string(),
            "hashed_password".to_string(),
            "User 2".to_string(),
        )
        .unwrap();

    let group = service
        .create_group(&user1, "Test Group".to_string(), false)
        .unwrap();

    service
        .join_group_by_link(&user2, &group.join_link)
        .unwrap();

    service
        .remove_user_from_group(&group, &user1, user2.id)
        .unwrap();

    assert!(!service.storage.is_group_member(group.id, user2.id));

    // 🚨 End mutable borrow of service
    drop(service);

    // ✅ Now it’s safe to immutably borrow audit_logger
    let logs = audit_logger.get_logs();
    assert_eq!(logs.len(), 5);
    assert_eq!(
        logs[4].action,
        crate::models::AuditAction::RemoveUserFromGroup
    );

    // Now re-borrow `storage` and `audit_logger` if needed
    let mut service = ExpenseService::new(&mut storage, &mut audit_logger);

    let result = service.remove_user_from_group(&group, &user1, user1.id);
    assert!(matches!(result, Err(ExpenseServiceError::NotAuthorized)));
}
