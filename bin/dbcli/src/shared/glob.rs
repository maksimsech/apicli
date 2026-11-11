pub fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star = None;
    while t < text.len() {
        if pattern.get(p) == Some(&b'*') {
            star = Some((p, t));
            p += 1;
        } else if let Some(width) = single(&pattern[p..], text[t]) {
            p += width;
            t += 1;
        } else if let Some((star_p, star_t)) = star {
            p = star_p + 1;
            t = star_t + 1;
            star = Some((star_p, t));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|byte| *byte == b'*')
}

fn single(pattern: &[u8], byte: u8) -> Option<usize> {
    let (first, rest) = pattern.split_first()?;
    match first {
        b'?' => Some(1),
        b'[' => match class(rest, Some(byte)) {
            Some((true, after)) => Some(pattern.len() - after.len()),
            Some((false, _)) => None,
            None => (byte == b'[').then_some(1),
        },
        b'\\' if !rest.is_empty() => (rest[0] == byte).then_some(2),
        _ => (*first == byte).then_some(1),
    }
}

fn class(pattern: &[u8], byte: Option<u8>) -> Option<(bool, &[u8])> {
    let (negate, mut rest) = match pattern.split_first() {
        Some((b'^', rest)) => (true, rest),
        _ => (false, pattern),
    };
    let mut found = false;
    let mut first = true;
    loop {
        match rest {
            [] => return None,
            [b']', after @ ..] if !first => {
                return Some((byte.is_some() && found != negate, after));
            }
            [b'\\', escaped, after @ ..] => {
                found |= byte == Some(*escaped);
                rest = after;
            }
            [low, b'-', high, after @ ..] if *high != b']' => {
                found |= byte.is_some_and(|byte| (*low.min(high)..=*low.max(high)).contains(&byte));
                rest = after;
            }
            [single, after @ ..] => {
                found |= byte == Some(*single);
                rest = after;
            }
        }
        first = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches_like_redis() {
        assert!(glob(b"cache:*", b"cache:"));
        assert!(glob(b"cache:*", b"cache:user:1"));
        assert!(!glob(b"cache:*", b"session:1"));
        assert!(glob(b"user:?", b"user:7"));
        assert!(!glob(b"user:?", b"user:17"));
        assert!(glob(b"user:[0-9]", b"user:5"));
        assert!(!glob(b"user:[0-9]", b"user:x"));
        assert!(glob(b"user:[^0-9]", b"user:x"));
        assert!(glob(b"a\\*b", b"a*b"));
        assert!(!glob(b"a\\*b", b"axb"));
        assert!(glob(b"shop.*", b"shop.orders"));
        assert!(!glob(b"shop.*", b"shopping.orders"));
        assert!(!glob(b"shop.orders", b"shop.orders2"));
    }
}
