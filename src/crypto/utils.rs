use std::{
    fs::{self, File},
    io,
    path::PathBuf,
};

use argon2::Argon2;
use rand::{TryRng, rngs::SysRng};

pub fn generate_random_bytes<const N: usize>() -> Result<[u8; N], anyhow::Error> {
    let mut bytes = [0u8; N];
    SysRng.try_fill_bytes(&mut bytes)?;
    Ok(bytes)
}

pub fn hash_password(password: &str, salt: [u8; 16]) -> Result<[u8; 32], anyhow::Error> {
    let argon2 = Argon2::default();

    let mut key = [0u8; 32];

    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|err| anyhow::anyhow!("Encrypting large file: {}", err))?;

    Ok(key)
}

pub struct TempFile {
    file_path: PathBuf,
    temp_file_path: PathBuf,
    persisted: bool,
}

impl TempFile {
    pub fn create(path: PathBuf) -> io::Result<(Self, File)> {
        let random_bytes: [u8; 4] = generate_random_bytes()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error generating random bytes"))?;
        let random_num = u32::from_ne_bytes(random_bytes);

        let temp_file_path = path
            .with_added_extension(format!("{:x}", random_num))
            .with_added_extension("temp");

        let file = File::create(temp_file_path.clone())?;

        let temp_file = Self {
            file_path: path,
            temp_file_path,
            persisted: false,
        };

        Ok((temp_file, file))
    }

    pub fn commit(mut self) -> io::Result<()> {
        fs::rename(&self.temp_file_path, &self.file_path)?;
        self.persisted = true;

        Ok(())
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.persisted {
            let _ = fs::remove_file(&self.temp_file_path);
        }
    }
}

pub struct TempDir {
    dir_path: PathBuf,
    pub temp_dir_path: PathBuf,
    persisted: bool,
}

impl TempDir {
    pub fn create(path: PathBuf) -> io::Result<Self> {
        let random_bytes: [u8; 4] = generate_random_bytes()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error generating random bytes"))?;
        let random_num = u32::from_ne_bytes(random_bytes);

        let temp_dir_path = path
            .with_added_extension(format!("{:x}", random_num))
            .with_added_extension("temp");

        fs::create_dir_all(&temp_dir_path)?;

        let temp_dir = Self {
            dir_path: path,
            temp_dir_path,
            persisted: false,
        };

        Ok(temp_dir)
    }

    pub fn commit(mut self) -> io::Result<()> {
        if self.dir_path.exists() {
            fs::remove_dir_all(&self.dir_path)?;
        }

        fs::rename(&self.temp_dir_path, &self.dir_path)?;
        self.persisted = true;

        Ok(())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if !self.persisted {
            let _ = fs::remove_dir_all(&self.temp_dir_path);
        }
    }
}
