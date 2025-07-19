use crate::{ExpenseService, ExpenseServiceError, InMemoryAuditLogger, InMemoryStorage};
use env_logger;

#[test]
fn test_create_user_with_unique_email() {
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

    assert_eq!(user1.email, "user1@example.com");

    // Drop service before accessing audit_logger
    drop(service);

    let logs = audit_logger.get_logs();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].action, crate::models::AuditAction::CreateUser);

    // Recreate service after dropping previous one
    let mut service = ExpenseService::new(&mut storage, &mut audit_logger);

    let result = service.create_user(
        "user1@example.com".to_string(),
        "hashed_password".to_string(),
        "User 2".to_string(),
    );

    assert!(matches!(result, Err(ExpenseServiceError::EmailInUse)));
}

#[test]
fn test_update_user_email_validation() {
    let _ = env_logger::try_init();
    let mut storage = InMemoryStorage::new();
    let mut audit_logger = InMemoryAuditLogger::new();
    let mut service = ExpenseService::new(&mut storage, &mut audit_logger);

    let _user1 = service
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

    let mut updated_user2 = user2.clone();

    // Attempt to update email to one already taken
    updated_user2.email = "user1@example.com".to_string();
    let result = service.update_user(updated_user2.clone());
    assert!(matches!(result, Err(ExpenseServiceError::EmailInUse)));

    // Update to a new unique email
    updated_user2.email = "new_user2@example.com".to_string();
    let updated = service.update_user(updated_user2).unwrap();
    assert_eq!(updated.email, "new_user2@example.com");

    // Drop service to access audit logs
    drop(service);

    let logs = audit_logger.get_logs();
    assert_eq!(logs.len(), 3);
    assert_eq!(logs[2].action, crate::models::AuditAction::UpdateUser);
}
