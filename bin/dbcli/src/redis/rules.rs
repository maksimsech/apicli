use fieldkit_policy::Allow;

use crate::shared::glob;

pub fn rule(action: &str, target: Option<&str>) -> Result<Allow, String> {
    let valid = action.split('|').count() <= 2
        && action.split('|').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))
        });
    if !valid {
        return Err(format!(
            "{action} is not a Redis command, use one like SET or 'CONFIG|SET'"
        ));
    }
    Ok(Allow {
        action: action.to_ascii_uppercase(),
        target: target.map(String::from),
    })
}

pub fn find<'a>(allow: &'a [Allow], action: &str, keys: &[&[u8]]) -> Option<&'a Allow> {
    allow.iter().find(|rule| {
        let named = rule.action.eq_ignore_ascii_case(action)
            || action
                .split_once('|')
                .is_some_and(|(container, _)| rule.action.eq_ignore_ascii_case(container));
        named
            && match &rule.target {
                None => keys.is_empty(),
                Some(pattern) => {
                    !keys.is_empty() && keys.iter().all(|key| glob(pattern.as_bytes(), key))
                }
            }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(list: &[(&str, Option<&str>)]) -> Vec<Allow> {
        list.iter()
            .map(|(action, target)| rule(action, *target).unwrap())
            .collect()
    }

    #[test]
    fn every_key_must_match() {
        let allow = rules(&[("SET", Some("cache:*"))]);

        assert!(find(&allow, "SET", &[b"cache:1"]).is_some());
        assert!(find(&allow, "set", &[b"cache:1"]).is_some());
        assert!(find(&allow, "SET", &[b"session:1"]).is_none());
        assert!(find(&allow, "MSET", &[b"cache:1"]).is_none());
        assert!(find(&allow, "SET", &[]).is_none());

        let allow = rules(&[("MSET", Some("cache:*"))]);

        assert!(find(&allow, "MSET", &[&b"cache:1"[..], &b"cache:2"[..]]).is_some());
        assert!(find(&allow, "MSET", &[&b"cache:1"[..], &b"session:2"[..]]).is_none());
    }

    #[test]
    fn rules_without_a_glob_cover_only_keyless_commands() {
        let allow = rules(&[("FLUSHDB", None), ("CONFIG", None)]);

        assert!(find(&allow, "FLUSHDB", &[]).is_some());
        assert!(find(&allow, "CONFIG|SET", &[]).is_some());
        assert!(find(&allow, "DEL", &[b"any"]).is_none());

        let allow = rules(&[("CONFIG|GET", None)]);

        assert!(find(&allow, "CONFIG|GET", &[]).is_some());
        assert!(find(&allow, "CONFIG|SET", &[]).is_none());
    }

    #[test]
    fn rules_name_one_command() {
        assert_eq!(rule("config|set", None).unwrap().action, "CONFIG|SET");
        assert!(rule("SET; FLUSHALL", None).is_err());
        assert!(rule("A|B|C", None).is_err());
    }
}
