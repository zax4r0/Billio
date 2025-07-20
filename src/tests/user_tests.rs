use crate::core::errors::BillioError;
use crate::core::models::user::User;
use crate::tests::create_test_service;
use uuid::Uuid;

#[tokio::test]
async fn test_add_user() {
    let service = create_test_service();
    let user = User {
        id: Uuid::new_v4().to_string(),
        name: "Test User".to_string(),
        email: "test@example.com".to_string(),
    };
    let added_user = service.add_user(user.clone(), None).await.unwrap();
    assert_eq!(added_user.id, user.id);
    assert_eq!(added_user.email, user.email);

    let result = service.add_user(user.clone(), None).await.unwrap();
    assert_eq!(result.id, "");
}

#[tokio::test]
async fn test_add_user_invalid_email() {
    let service = create_test_service();
    let user = User {
        id: Uuid::new_v4().to_string(),
        name: "Test User".to_string(),
        email: "invalid".to_string(),
    };
    let result = service.add_user(user, None).await;
    assert!(matches!(result, Err(BillioError::InvalidEmail(_))));
}
