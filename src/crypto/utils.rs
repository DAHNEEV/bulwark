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
