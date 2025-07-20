use crate::core::errors::BillioError;
use crate::core::models::user::User;
use crate::tests::create_test_service;
use std::collections::HashMap;
use uuid::Uuid;

#[tokio::test]
async fn test_add_expense_and_reverse() {
    let service = create_test_service();
    let user1 = User {
        id: Uuid::new_v4().to_string(),
        name: "User 1".to_string(),
        email: "user1@example.com".to_string(),
    };
    let user2 = User {
        id: Uuid::new_v4().to_string(),
        name: "User 2".to_string(),
        email: "user2@example.com".to_string(),
    };
    service.add_user(user1.clone(), None).await.unwrap();
    service.add_user(user2.clone(), None).await.unwrap();

    let group = service
        .create_group("Test Group".to_string(), vec![user2.clone()], &user1)
        .await
        .unwrap();

    let shares = HashMap::from([(user1.id.clone(), 50.0), (user2.id.clone(), 50.0)]);
    let transaction = service
        .add_expense(&group.id, "Dinner".to_string(), 100.0, user1.clone(), shares, &user1)
        .await
        .unwrap();

    assert_eq!(transaction.amount, 100.0);
    assert_eq!(transaction.shares[&user2.id], 50.0);

    let reversal = service.reverse_transaction(&transaction.id, &user1).await.unwrap();
    assert_eq!(reversal.amount, -100.0);
    assert_eq!(reversal.shares[&user2.id], -50.0);
}
