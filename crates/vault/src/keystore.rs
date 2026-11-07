#[cfg(target_os = "macos")]
mod platform {
    use std::path::Path;

    use security_framework::passwords::{get_generic_password, set_generic_password};
    use zeroize::Zeroizing;

    use crate::VaultError;

    const SERVICE: &str = "dev.apicli";
    const ACCOUNT: &str = "master-key";
    const NOT_FOUND: i32 = -25300;

    pub fn read(_dir: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        match get_generic_password(SERVICE, ACCOUNT) {
            Ok(key) => Ok(Some(Zeroizing::new(key))),
            Err(error) if error.code() == NOT_FOUND => Ok(None),
            Err(error) => Err(VaultError::Keystore(error.to_string())),
        }
    }

    pub fn write(_dir: &Path, key: &[u8]) -> Result<(), VaultError> {
        set_generic_password(SERVICE, ACCOUNT, key)
            .map_err(|error| VaultError::Keystore(error.to_string()))
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use std::{fs, io::ErrorKind, path::Path};

    use zeroize::Zeroizing;

    use crate::{VaultError, store::write_private};

    pub fn read(dir: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        match fs::read(dir.join("master.key")) {
            Ok(key) => Ok(Some(Zeroizing::new(key))),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(VaultError::Keystore(error.to_string())),
        }
    }

    pub fn write(dir: &Path, key: &[u8]) -> Result<(), VaultError> {
        write_private(&dir.join("master.key"), key)
            .map_err(|error| VaultError::Keystore(error.to_string()))
    }
}

pub use platform::{read, write};
