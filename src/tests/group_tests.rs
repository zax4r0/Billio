use crate::core::models::{group::Role, user::User};
use crate::tests::create_test_service;
use uuid::Uuid;

#[tokio::test]
async fn test_create_group() {
    let service = create_test_service();
    let user = User {
        id: Uuid::new_v4().to_string(),
        name: "Test User".to_string(),
        email: "test@example.com".to_string(),
    };
    let added_user = service.add_user(user.clone(), None).await.unwrap();

    let group = service
        .create_group("Test Group".to_string(), vec![], &added_user)
        .await
        .unwrap();

    assert_eq!(group.name, "Test Group");
    assert_eq!(group.members.len(), 1);
    assert_eq!(group.members[0].user.id, user.id);
    assert_eq!(group.members[0].role, Role::Owner);
}

#[tokio::test]
async fn test_add_member_to_group() {
    let service = create_test_service();
    let owner = User {
        id: Uuid::new_v4().to_string(),
        name: "Owner".to_string(),
        email: "owner@example.com".to_string(),
    };
    let member = User {
        id: Uuid::new_v4().to_string(),
        name: "Member".to_string(),
        email: "member@example.com".to_string(),
    };
    service.add_user(owner.clone(), None).await.unwrap();
    service.add_user(member.clone(), None).await.unwrap();

    let group = service
        .create_group("Test Group".to_string(), vec![], &owner)
        .await
        .unwrap();
    service
        .add_member_to_group(&group.id, member.clone(), &owner)
        .await
        .unwrap();

    let updated_group = service.get_group(&group.id).await.unwrap().unwrap();
    assert_eq!(updated_group.members.len(), 2);
    assert!(
        updated_group
            .members
            .iter()
            .any(|m| m.user.id == member.id && m.role == Role::Member)
    );
}

#[tokio::test]
async fn test_remove_member_from_group() {
    let service = create_test_service();
    let owner = User {
        id: Uuid::new_v4().to_string(),
        name: "Owner".to_string(),
        email: "owner@example.com".to_string(),
    };
    let member = User {
        id: Uuid::new_v4().to_string(),
        name: "Member".to_string(),
        email: "member@example.com".to_string(),
    };
    service.add_user(owner.clone(), None).await.unwrap();
    service.add_user(member.clone(), None).await.unwrap();

    let group = service
        .create_group("Test Group".to_string(), vec![member.clone()], &owner)
        .await
        .unwrap();
    service
        .remove_member_from_group(&group.id, &member.id, &owner)
        .await
        .unwrap();

    let updated_group = service.get_group(&group.id).await.unwrap().unwrap();
    assert_eq!(updated_group.members.len(), 1);
    assert_eq!(updated_group.members[0].user.id, owner.id);
}
