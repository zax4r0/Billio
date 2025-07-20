// src/tests/transaction_tests.rs

use crate::cache::in_memory_cache::InMemoryCache;
use crate::logger::in_memory::InMemoryLogging;
use crate::models::user::User;
use crate::service::BillioService;
use crate::storage::in_memory::InMemoryStorage;
use std::collections::HashMap;

#[tokio::test]
async fn test_add_expense_and_settlement() {
    // Initialize storage and logging
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
        email: "bob@example.com".to_string(),
    };

    billio.add_user(user1.clone(), None).await.unwrap();
    billio.add_user(user2.clone(), None).await.unwrap();

    let group = billio
        .create_group("Test".to_string(), vec![user1.clone(), user2.clone()], &user1)
        .await
        .unwrap();

    let shares = HashMap::from([("u2".to_string(), 100.0)]);

    let tx = billio
        .add_expense(&group.id, "Dinner".to_string(), 100.0, user1.clone(), shares, &user1)
        .await
        .unwrap();

    let balances_response = billio.get_user_balances("u2", &user2).await.unwrap();
    assert_eq!(balances_response.minimized_balances()[0].amount, 100.0);

    billio
        .toggle_strict_settlement_mode(&group.id, false, &user1)
        .await
        .unwrap();

    let _settlement = billio
        .create_settlement(&group.id, &user2, &user1, 100.0, None, Some(vec![tx.id]), &user2)
        .await
        .unwrap();

    let balance = billio.get_user_balances("u2", &user2).await.unwrap();
    println!("Balances after settlement: {:?}", balance);

    assert!(balance.minimized_balances().is_empty());
}
