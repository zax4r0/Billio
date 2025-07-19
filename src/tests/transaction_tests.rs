// src/tests/transaction_tests.rs

use crate::logger::in_memory::InMemoryLogging;
use crate::models::user::User;
use crate::service::SplitwiseService;
use crate::storage::in_memory::InMemoryStorage;
use std::collections::HashMap;

#[tokio::test]
async fn test_add_expense_and_settlement() {
    let storage = InMemoryStorage::new();
    let logging = InMemoryLogging::new();
    let splitwise = SplitwiseService::new(storage, logging);
    let user1 = User {
        id: "u1".to_string(),
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
    };
    let user2 = User {
        id: "u2".to_string(),
        name: "Bob".to_string(),
        email: "bob@example.com".to_string(),
    };
    splitwise.add_user(user1.clone(), None).await.unwrap();
    splitwise.add_user(user2.clone(), None).await.unwrap();
    let group = splitwise
        .create_group(
            "Test".to_string(),
            vec![user1.clone(), user2.clone()],
            &user1,
        )
        .await
        .unwrap();
    let shares = HashMap::from([("u2".to_string(), 100.0)]);
    let tx = splitwise
        .add_expense(
            &group.id,
            "Dinner".to_string(),
            100.0,
            user1.clone(),
            shares,
            &user1,
        )
        .await
        .unwrap();
    let balances = splitwise.get_user_balances("u2", &user2).await.unwrap();
    assert_eq!(balances[0].amount, 100.0);
    splitwise
        .toggle_strict_settlement_mode(&group.id, false, &user1)
        .await
        .unwrap();
    let _settlement = splitwise
        .create_settlement(
            &group.id,
            &user2,
            &user1,
            100.0,
            None,
            Some(vec![tx.id]),
            &user2,
        )
        .await
        .unwrap();
    let balance = splitwise.get_user_balances("u2", &user2).await.unwrap();
    println!("Balances after settlement: {:?}", balance);
    assert!(balance.is_empty());
}
