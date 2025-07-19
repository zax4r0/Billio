use crate::{
    ExpenseService, ExpenseServiceError, InMemoryAuditLogger, InMemoryStorage, Visualization,
};
use env_logger;
use serde_json::json; // Add this import

#[test]
fn test_create_transaction_and_simplify_debts() {
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

    let tx = service
        .create_transaction(
            &group,
            &user1,
            user1.id,
            100.0,
            "Dinner".to_string(),
            crate::models::SplitType::Equal,
            vec![user1.id, user2.id],
            vec![],
        )
        .unwrap();

    assert_eq!(tx.amount, 100.0);
    assert_eq!(tx.splits.len(), 2);
    assert_eq!(tx.splits[0].share, 50.0);
    assert_eq!(tx.splits[1].share, 50.0);

    let transactions = service.storage.list_transactions(group.id);
    let balances = service.calculate_balances(&group, &transactions);
    let simplified = service.simplify_debts(&balances);

    assert_eq!(balances.get(&user1.id), Some(&50.0));
    assert_eq!(balances.get(&user2.id), Some(&-50.0));
    assert_eq!(simplified, vec![(user2.id, user1.id, 50.0)]);
    assert_eq!(audit_logger.get_logs().len(), 5);
    assert_eq!(
        audit_logger.get_logs()[4].action,
        crate::models::AuditAction::CreateTransaction
    );
}

#[test]
fn test_generate_balance_chart() {
    let _ = env_logger::try_init();
    let mut storage = InMemoryStorage::new();
    let mut audit_logger = InMemoryAuditLogger::new();
    let mut service = ExpenseService::new(&mut storage, &mut audit_logger);

    let user1 = service
        .create_user(
            "user1@example.com".to_string(),
            "hashed_password".to_string(),
            "Alice".to_string(),
        )
        .unwrap();

    let user2 = service
        .create_user(
            "user2@example.com".to_string(),
            "hashed_password".to_string(),
            "Bob".to_string(),
        )
        .unwrap();

    let group = service
        .create_group(&user1, "Test Group".to_string(), false)
        .unwrap();

    service
        .join_group_by_link(&user2, &group.join_link)
        .unwrap();

    let _tx = service
        .create_transaction(
            &group,
            &user1,
            user1.id,
            100.0,
            "Dinner".to_string(),
            crate::models::SplitType::Equal,
            vec![user1.id, user2.id],
            vec![],
        )
        .unwrap();

    let transactions = service.storage.list_transactions(group.id);
    let chart_config =
        Visualization::generate_balance_chart(&service, &group, &transactions).unwrap();

    assert_eq!(chart_config["type"], "bar");

    // Extract and sort labels and data for comparison
    let mut labels_and_data: Vec<(String, f64)> = chart_config["data"]["labels"]
        .as_array()
        .unwrap()
        .iter()
        .zip(
            chart_config["data"]["datasets"][0]["data"]
                .as_array()
                .unwrap(),
        )
        .map(|(label, val)| (label.as_str().unwrap().to_string(), val.as_f64().unwrap()))
        .collect();
    labels_and_data.sort_by(|a, b| a.0.cmp(&b.0));

    let expected = vec![("Alice".to_string(), 50.0), ("Bob".to_string(), -50.0)];
    assert_eq!(labels_and_data, expected);

    assert_eq!(
        chart_config["data"]["datasets"][0]["label"],
        "User Balances"
    );
    assert_eq!(
        chart_config["data"]["datasets"][0]["backgroundColor"],
        json!(["rgba(75, 192, 192, 0.6)", "rgba(255, 99, 132, 0.6)"])
    );
    assert_eq!(
        chart_config["options"]["plugins"]["title"]["text"],
        "Balances for Group: Test Group"
    );

    // Test with empty transactions
    let empty_transactions: Vec<crate::models::Transaction> = vec![];
    let result = Visualization::generate_balance_chart(&service, &group, &empty_transactions);
    assert!(matches!(
        result,
        Err(ExpenseServiceError::NoBalancesAvailable)
    ));

    // Test with single user
    let single_user_group = service
        .create_group(&user1, "Single User Group".to_string(), false)
        .unwrap();
    let _tx = service
        .create_transaction(
            &single_user_group,
            &user1,
            user1.id,
            50.0,
            "Self Transaction".to_string(),
            crate::models::SplitType::Equal,
            vec![user1.id],
            vec![],
        )
        .unwrap();
    let transactions = service.storage.list_transactions(single_user_group.id);
    let chart_config =
        Visualization::generate_balance_chart(&service, &single_user_group, &transactions).unwrap();

    assert_eq!(chart_config["data"]["labels"], json!(["Alice"]));
    assert_eq!(chart_config["data"]["datasets"][0]["data"], json!([0.0])); // Single user, net balance is 0
}
