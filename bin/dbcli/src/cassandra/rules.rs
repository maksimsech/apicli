use crate::shared::{Allow, glob};

const TABLE_WRITES: [&str; 4] = ["INSERT", "UPDATE", "DELETE", "TRUNCATE"];

pub fn rule(action: &str, target: Option<&str>) -> Result<Allow, String> {
    let action = action.to_ascii_uppercase();
    if action.is_empty() || !action.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err(format!(
            "{action} is not a CQL statement keyword, use one like INSERT, UPDATE or CREATE"
        ));
    }
    if target.is_none() && TABLE_WRITES.contains(&action.as_str()) {
        return Err(format!(
            "{action} rules need a table, like 'shop.orders', 'shop.*' or '*'"
        ));
    }
    Ok(Allow {
        action,
        target: target.map(String::from),
    })
}

pub fn find<'a>(allow: &'a [Allow], action: &str, target: Option<&str>) -> Option<&'a Allow> {
    allow.iter().find(|rule| {
        rule.action.eq_ignore_ascii_case(action)
            && match (&rule.target, target) {
                (None, None) => true,
                (Some(pattern), Some(target)) => glob(pattern.as_bytes(), target.as_bytes()),
                _ => false,
            }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_match_keyword_and_table() {
        let allow = [
            rule("INSERT", Some("shop.*")).unwrap(),
            rule("GRANT", None).unwrap(),
        ];

        assert!(find(&allow, "insert", Some("shop.orders")).is_some());
        assert!(find(&allow, "INSERT", Some("other.orders")).is_none());
        assert!(find(&allow, "UPDATE", Some("shop.orders")).is_none());
        assert!(find(&allow, "GRANT", None).is_some());
        assert!(find(&allow, "GRANT", Some("shop.orders")).is_none());
        assert!(find(&allow, "INSERT", None).is_none());
    }

    #[test]
    fn data_writes_need_a_table() {
        assert!(rule("INSERT", None).is_err());
        assert!(rule("DROP; GRANT", None).is_err());
        assert_eq!(rule("create", Some("shop.*")).unwrap().action, "CREATE");
    }
}
