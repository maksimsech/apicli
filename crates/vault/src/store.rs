use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, OpenOptions},
    io::{self, ErrorKind, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use apicli_core::{Bucket, Vault};
use aws_lc_rs::digest::{SHA256, digest};
use directories::ProjectDirs;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{keystore, sealed};

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("no home directory to keep apicli's files in")]
    NoHome,
    #[error("the keystore failed: {0}")]
    Keystore(String),
    #[error("{0} can't be decrypted. Remove it to start over, which deletes every stored secret")]
    Corrupt(PathBuf),
    #[error("{0} was changed outside apicli. Run apicli policy edit to review and accept it")]
    PolicyChanged(PathBuf),
    #[error("{0} is missing. Run apicli policy edit to write a new one")]
    PolicyMissing(PathBuf),
    #[error("{0} was not written by apicli. Run apicli policy edit to review and accept it")]
    PolicyUnexpected(PathBuf),
    #[error("{0}")]
    Io(#[from] io::Error),
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open() -> Result<Store, VaultError> {
        let dirs = ProjectDirs::from("dev", "", "apicli").ok_or(VaultError::NoHome)?;
        Ok(Store {
            dir: dirs.data_dir().to_path_buf(),
        })
    }

    pub fn at(dir: PathBuf) -> Store {
        Store { dir }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn policy_path(&self) -> PathBuf {
        self.dir.join("policy.toml")
    }

    pub fn read_policy(&self, vault: &Vault) -> Result<Option<String>, VaultError> {
        let path = self.policy_path();
        match (&vault.policy_hash, self.read_policy_unchecked()?) {
            (None, None) => Ok(None),
            (None, Some(_)) => Err(VaultError::PolicyUnexpected(path)),
            (Some(_), None) => Err(VaultError::PolicyMissing(path)),
            (Some(expected), Some(text)) if *expected == hash(&text) => Ok(Some(text)),
            (Some(_), Some(_)) => Err(VaultError::PolicyChanged(path)),
        }
    }

    pub fn read_policy_unchecked(&self) -> Result<Option<String>, VaultError> {
        match fs::read_to_string(self.policy_path()) {
            Ok(text) => Ok(Some(text)),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn update_buckets<T>(
        &self,
        change: impl FnOnce(&mut BTreeMap<String, Bucket>) -> T,
    ) -> Result<T, VaultError> {
        self.create_dir()?;
        let mut file = private_options()
            .read(true)
            .open(self.dir.join("ratelimit.state"))?;
        file.lock()?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        let mut buckets = serde_json::from_str(&text).unwrap_or_default();
        let result = change(&mut buckets);
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&serde_json::to_vec(&buckets).map_err(io::Error::other)?)?;
        Ok(result)
    }

    pub fn read_buckets(&self) -> BTreeMap<String, Bucket> {
        fs::read_to_string(self.dir.join("ratelimit.state"))
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn append_log(&self, line: &str) -> io::Result<()> {
        self.create_dir()?;
        let mut file = private_options().append(true).open(self.log_path())?;
        writeln!(file, "{line}")
    }

    pub fn read_log(&self) -> io::Result<String> {
        match fs::read_to_string(self.log_path()) {
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(String::new()),
            result => result,
        }
    }

    pub fn log_path(&self) -> PathBuf {
        self.dir.join("audit.log")
    }

    pub fn write_policy(&self, vault: &mut Vault, text: &str) -> Result<(), VaultError> {
        self.create_dir()?;
        write_private(&self.policy_path(), text.as_bytes())?;
        vault.policy_hash = Some(hash(text));
        Ok(())
    }

    pub fn master_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        keystore::read(&self.dir)
    }

    pub fn load(&self) -> Result<Vault, VaultError> {
        let path = self.vault_path();
        if !path.exists() {
            return Ok(Vault::default());
        }
        let corrupt = || VaultError::Corrupt(path.clone());
        let key = self.master_key()?.ok_or_else(corrupt)?;
        let plain = sealed::open(&key, &fs::read(&path)?).ok_or_else(corrupt)?;
        serde_json::from_slice(&plain).map_err(|_| corrupt())
    }

    pub fn save(&self, vault: &Vault) -> Result<(), VaultError> {
        self.create_dir()?;
        let key = match self.master_key()? {
            Some(key) => key,
            None => {
                let key = sealed::random_key()
                    .ok_or_else(|| VaultError::Keystore("no system randomness".into()))?;
                keystore::write(&self.dir, &key)?;
                key
            }
        };
        let plain = Zeroizing::new(serde_json::to_vec(vault).map_err(io::Error::other)?);
        let sealed =
            sealed::seal(&key, &plain).ok_or_else(|| VaultError::Corrupt(self.vault_path()))?;
        write_private(&self.vault_path(), &sealed)?;
        Ok(())
    }

    fn vault_path(&self) -> PathBuf {
        self.dir.join("vault.bin")
    }

    fn create_dir(&self) -> io::Result<()> {
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(&self.dir)
    }
}

pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temp = path.with_extension("tmp");
    private_options()
        .truncate(true)
        .open(&temp)?
        .write_all(bytes)?;
    fs::rename(temp, path)
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
}

fn hash(text: &str) -> String {
    digest(&SHA256, text.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{env, process};

    use super::*;

    fn store(name: &str) -> Store {
        let dir = env::temp_dir().join(format!("apicli-test-{}-{name}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        Store::at(dir)
    }

    #[test]
    fn accepts_policy_it_wrote() {
        let store = store("accepts");
        let mut vault = Vault::default();
        store.write_policy(&mut vault, "[hosts]\n").unwrap();

        assert_eq!(
            store.read_policy(&vault).unwrap().as_deref(),
            Some("[hosts]\n")
        );
    }

    #[test]
    fn rejects_edited_policy() {
        let store = store("edited");
        let mut vault = Vault::default();
        store.write_policy(&mut vault, "[hosts]\n").unwrap();
        fs::write(
            store.policy_path(),
            "[hosts.\"https://attacker.example\"]\n",
        )
        .unwrap();

        assert!(matches!(
            store.read_policy(&vault),
            Err(VaultError::PolicyChanged(_))
        ));
    }

    #[test]
    fn rejects_deleted_policy() {
        let store = store("deleted");
        let mut vault = Vault::default();
        store.write_policy(&mut vault, "[hosts]\n").unwrap();
        fs::remove_file(store.policy_path()).unwrap();

        assert!(matches!(
            store.read_policy(&vault),
            Err(VaultError::PolicyMissing(_))
        ));
    }

    #[test]
    fn rejects_planted_policy() {
        let store = store("planted");
        store.create_dir().unwrap();
        fs::write(store.policy_path(), "[hosts]\n").unwrap();

        assert!(matches!(
            store.read_policy(&Vault::default()),
            Err(VaultError::PolicyUnexpected(_))
        ));
    }
}
