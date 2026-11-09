use base64::{Engine, engine::general_purpose::STANDARD};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode};

pub const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

pub struct Redactor {
    mask: Vec<u8>,
    patterns: Vec<Vec<u8>>,
    pending: Vec<u8>,
}

impl Redactor {
    pub fn new<'a>(mask: &str, secrets: impl IntoIterator<Item = &'a str>) -> Redactor {
        let mut patterns = Vec::new();
        for secret in secrets {
            patterns.push(secret.as_bytes().to_vec());
            patterns.push(STANDARD.encode(secret).into_bytes());
            patterns.push(
                percent_encode(secret.as_bytes(), UNRESERVED)
                    .to_string()
                    .into_bytes(),
            );
        }
        patterns.retain(|pattern| !pattern.is_empty());
        patterns.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
        patterns.dedup();
        Redactor {
            mask: mask.as_bytes().to_vec(),
            patterns,
            pending: Vec::new(),
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        self.drain(false)
    }

    pub fn finish(&mut self) -> Vec<u8> {
        self.drain(true)
    }

    pub fn redact(&self, text: &[u8]) -> Vec<u8> {
        Redactor {
            mask: self.mask.clone(),
            patterns: self.patterns.clone(),
            pending: text.to_vec(),
        }
        .drain(true)
    }

    fn drain(&mut self, last: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut index = 0;
        while index < self.pending.len() {
            let rest = &self.pending[index..];
            if let Some(pattern) = self
                .patterns
                .iter()
                .find(|pattern| rest.starts_with(pattern))
            {
                out.extend_from_slice(&self.mask);
                index += pattern.len();
            } else if !last
                && self
                    .patterns
                    .iter()
                    .any(|pattern| pattern.starts_with(rest))
            {
                break;
            } else {
                out.push(rest[0]);
                index += 1;
            }
        }
        self.pending.drain(..index);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASK: &str = "[apicli:redacted]";
    const SECRET: &str = "sk_live/abc+123";

    fn redacted(text: &str) -> String {
        String::from_utf8(Redactor::new(MASK, [SECRET]).redact(text.as_bytes())).unwrap()
    }

    #[test]
    fn masks_raw_secret() {
        assert_eq!(
            redacted("{\"key\":\"sk_live/abc+123\"}"),
            "{\"key\":\"[apicli:redacted]\"}"
        );
    }

    #[test]
    fn masks_base64_secret() {
        let encoded = STANDARD.encode(SECRET);

        assert_eq!(
            redacted(&format!("Basic {encoded}")),
            "Basic [apicli:redacted]"
        );
    }

    #[test]
    fn masks_percent_encoded_secret() {
        assert_eq!(
            redacted("?key=sk_live%2Fabc%2B123&x=1"),
            "?key=[apicli:redacted]&x=1"
        );
    }

    #[test]
    fn masks_secret_split_across_chunks() {
        let mut redactor = Redactor::new(MASK, [SECRET]);
        let mut out = redactor.push(b"before sk_li");
        out.extend(redactor.push(b"ve/abc+"));
        out.extend(redactor.push(b"123 after"));
        out.extend(redactor.finish());

        assert_eq!(
            String::from_utf8(out).unwrap(),
            "before [apicli:redacted] after"
        );
    }

    #[test]
    fn flushes_partial_match_at_the_end() {
        let mut redactor = Redactor::new(MASK, [SECRET]);
        let mut out = redactor.push(b"ends with sk_li");
        out.extend(redactor.finish());

        assert_eq!(String::from_utf8(out).unwrap(), "ends with sk_li");
    }
}
