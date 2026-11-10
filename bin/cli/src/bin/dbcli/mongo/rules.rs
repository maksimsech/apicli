use apicli_policy::Allow;

use crate::shared::glob;

pub fn rule(action: &str, target: Option<&str>) -> Result<Allow, String> {
    if action.is_empty() || !action.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(format!(
            "{action} is not a MongoDB command name, use one like insert, update or delete"
        ));
    }
    let Some(target) = target else {
        return Err("MongoDB rules need a namespace, like 'shop.orders', 'shop.*' or '*'".into());
    };
    Ok(Allow {
        action: action.to_string(),
        target: Some(target.to_string()),
    })
}

pub fn find<'a>(allow: &'a [Allow], action: &str, namespace: &str) -> Option<&'a Allow> {
    allow.iter().find(|rule| {
        rule.action.eq_ignore_ascii_case(action)
            && rule
                .target
                .as_ref()
                .is_some_and(|pattern| glob(pattern.as_bytes(), namespace.as_bytes()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_match_command_and_namespace() {
        let allow = [
            rule("update", Some("shop.orders")).unwrap(),
            rule("insert", Some("shop.*")).unwrap(),
        ];

        assert!(find(&allow, "update", "shop.orders").is_some());
        assert!(find(&allow, "update", "shop.users").is_none());
        assert!(find(&allow, "delete", "shop.orders").is_none());
        assert!(find(&allow, "insert", "shop.anything").is_some());
        assert!(find(&allow, "insert", "admin.users").is_none());
    }

    #[test]
    fn rules_need_a_command_and_namespace() {
        assert!(rule("update", None).is_err());
        assert!(rule("update", Some("shop.orders")).is_ok());
        assert!(rule("$where", Some("*")).is_err());
    }
}
