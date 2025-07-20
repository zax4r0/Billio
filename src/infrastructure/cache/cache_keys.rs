pub fn user_balances_key(user_id: &str) -> String {
    format!("user_balances:{}", user_id)
}

pub fn group_members_key(group_id: &str) -> String {
    format!("group_members:{}", group_id)
}
