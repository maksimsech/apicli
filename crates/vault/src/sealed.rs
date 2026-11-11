use aws_lc_rs::{
    aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    hkdf::{HKDF_SHA256, Salt},
    rand,
};
use zeroize::Zeroizing;

const AAD: &[u8] = b"fieldkit vault v1";

fn key(master: &[u8], purpose: &[u8]) -> Option<LessSafeKey> {
    let prk = Salt::new(HKDF_SHA256, &[]).extract(master);
    let info = [purpose];
    let okm = prk.expand(&info, &CHACHA20_POLY1305).ok()?;
    Some(LessSafeKey::new(UnboundKey::from(okm)))
}

pub fn seal(master: &[u8], plain: &[u8]) -> Option<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::fill(&mut nonce).ok()?;
    let mut data = plain.to_vec();
    key(master, b"vault")?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(AAD),
            &mut data,
        )
        .ok()?;
    Some([nonce.as_slice(), &data].concat())
}

pub fn open(master: &[u8], sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE_LEN {
        return None;
    }
    let (nonce, data) = sealed.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
    let mut data = Zeroizing::new(data.to_vec());
    let plain = key(master, b"vault")?
        .open_in_place(nonce, Aad::from(AAD), &mut data)
        .ok()?;
    Some(Zeroizing::new(plain.to_vec()))
}

pub fn random_key() -> Option<Zeroizing<Vec<u8>>> {
    let mut key = Zeroizing::new(vec![0u8; 32]);
    rand::fill(&mut key).ok()?;
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let master = random_key().unwrap();
        let sealed = seal(&master, b"secret data").unwrap();

        assert_eq!(open(&master, &sealed).unwrap().as_slice(), b"secret data");
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(&random_key().unwrap(), b"secret data").unwrap();

        assert!(open(&random_key().unwrap(), &sealed).is_none());
    }

    #[test]
    fn tampering_fails() {
        let master = random_key().unwrap();
        let mut sealed = seal(&master, b"secret data").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;

        assert!(open(&master, &sealed).is_none());
    }
}
