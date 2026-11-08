use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, OpenOptions},
    io::{self, ErrorKind, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use apicli_core::{Bucket, Vault};
use directories::ProjectDirs;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::sealed;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("no home directory to keep apicli's files in")]
    NoHome,
    #[error("{0}")]
    Crypto(String),
    #[error("{0} can't be decrypted. Remove it to start over, which deletes every stored secret")]
    Corrupt(PathBuf),
    #[error("{0}")]
    Io(#[from] io::Error),
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open() -> Result<Store, VaultError> {
        let dirs = ProjectDirs::from("dev", "mngapp", "apicli").ok_or(VaultError::NoHome)?;
        Ok(Store {
            dir: dirs.data_local_dir().to_path_buf(),
        })
    }

    pub fn at(dir: PathBuf) -> Store {
        Store { dir }
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

    pub fn append_log(&self, line: &str, limit: u64) -> io::Result<()> {
        self.create_dir()?;
        let mut file = private_options().read(true).open(self.log_path())?;
        file.lock()?;
        file.seek(SeekFrom::End(0))?;
        writeln!(file, "{line}")?;
        if file.metadata()?.len() <= limit {
            return Ok(());
        }
        let mut text = Vec::new();
        file.seek(SeekFrom::Start(0))?;
        file.read_to_end(&mut text)?;
        let keep = usize::try_from(limit / 4 * 3).unwrap_or(usize::MAX);
        let start = text.len().saturating_sub(keep);
        let start = text[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(text.len(), |index| start + index + 1);
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&text[start..])
    }

    pub fn read_log(&self) -> io::Result<String> {
        match fs::read_to_string(self.log_path()) {
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(String::new()),
            result => result,
        }
    }

    pub fn load(&self) -> Result<Vault, VaultError> {
        let path = self.vault_path();
        if !path.exists() {
            return Ok(Vault::default());
        }
        let corrupt = || VaultError::Corrupt(path.clone());
        let key = self.read_key()?.ok_or_else(corrupt)?;
        let plain = sealed::open(&key, &fs::read(&path)?).ok_or_else(corrupt)?;
        serde_json::from_slice(&plain).map_err(|_| corrupt())
    }

    pub fn save(&self, vault: &Vault) -> Result<(), VaultError> {
        self.create_dir()?;
        let key = match self.read_key()? {
            Some(key) => key,
            None => {
                let key = sealed::random_key()
                    .ok_or_else(|| VaultError::Crypto("no system randomness".into()))?;
                write_private(&self.key_path(), &key)?;
                key
            }
        };
        let plain = Zeroizing::new(serde_json::to_vec(vault).map_err(io::Error::other)?);
        let sealed =
            sealed::seal(&key, &plain).ok_or_else(|| VaultError::Corrupt(self.vault_path()))?;
        write_private(&self.vault_path(), &sealed)?;
        Ok(())
    }

    fn read_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        match fs::read(self.key_path()) {
            Ok(key) => Ok(Some(Zeroizing::new(key))),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join("master.key")
    }

    fn vault_path(&self) -> PathBuf {
        self.dir.join("vault.bin")
    }

    fn log_path(&self) -> PathBuf {
        self.dir.join("audit.log")
    }

    fn create_dir(&self) -> io::Result<()> {
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(&self.dir)
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
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
