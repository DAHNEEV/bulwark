
use anyhow::Context;
use std::{
    fs::File,
    io::{Read, Write},
};
use argon2::{
    Argon2,
    password_hash::rand_core::{OsRng, RngCore},
};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::stream};

fn generate_salt() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn hash_password(password: &str, salt: [u8; 16]) -> Result<[u8; 32], anyhow::Error> {
    let argon2 = Argon2::default();

    let mut key = [0u8; 32];

    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|err| anyhow::anyhow!("Encrypting large file: {}", err))?;

    Ok(key)
}

fn generate_nonce() -> [u8; 19] {
    let mut bytes = [0u8; 19];
    OsRng.fill_bytes(&mut bytes);
    bytes
}


fn stream_encrypt_to_file(
    mut source_file: File,
    mut dist_file: File,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500;
    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let read_count = source_file
            .read(&mut buffer)
            .context("Failed to read source file")?;

        if read_count == BUFFER_LEN {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow::anyhow!("Encrypting large file: {}", err))?;
            dist_file
                .write_all(&ciphertext)
                .context("Failed to write encrypted chunk to dist file")?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow::anyhow!("Encrypting large file: {}", err))?;
            dist_file
                .write_all(&ciphertext)
                .context("Failed to write FINAL encrypted chunk to dist file")?;
            break;
        }
    }

    Ok(())
}

pub fn encrypt_file(
    source_file_path: String,
    dist_file_path: String,
    password: String,
) -> Result<(), anyhow::Error> {
    let source_file = File::open(source_file_path).context("Failed to open source file")?;
    let mut dist_file = File::create(dist_file_path).context("Failed to create dist file")?;

    let salt = generate_salt();
    dist_file
        .write_all(&salt)
        .context("Failed to write salt to dist file")?;
    let key = hash_password(&password, salt)?;

    let nonce = generate_nonce();
    dist_file
        .write_all(&nonce)
        .context("Failed to write nonce to dist file")?;

    stream_encrypt_to_file(source_file, dist_file, &key, &nonce)?;

    Ok(())
}

fn stream_decrypt_to_file(
    mut encrypted_file: File,
    mut dist_file: File,
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> Result<(), anyhow::Error> {
    let aead = XChaCha20Poly1305::new(key.as_ref().into());
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

    const BUFFER_LEN: usize = 500 + 16;
    let mut buffer = [0u8; BUFFER_LEN];

    loop {
        let read_count = encrypted_file
            .read(&mut buffer)
            .context("Failed to read encrypted file content")?;

        if read_count == BUFFER_LEN {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow::anyhow!("Decrypting large file: {}", err))?;
            dist_file
                .write_all(&plaintext)
                .context("Failed to write plain chunk to dist file")?;
        } else if read_count == 0 {
            break;
        } else {
            let plaintext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow::anyhow!("Decrypting large file: {}", err))?;
            dist_file
                .write_all(&plaintext)
                .context("Failed to write FINAL plain chunk to dist file")?;
            break;
        }
    }

    Ok(())
}

pub fn decrypt_file(
    encrypted_file_path: String,
    dist_file_path: String,
    password: String,
) -> Result<(), anyhow::Error> {
    let mut encrypted_file =
        File::open(encrypted_file_path).context("Failed to open encrypted file")?;
    let dist_file = File::create(dist_file_path).context("Failed to create dist file")?;

    let mut salt = [0u8; 16];
    encrypted_file
        .read_exact(&mut salt)
        .context("Failed to read salt")?;
    let key = hash_password(&password, salt)?;

    let mut nonce = [0u8; 19];
    encrypted_file
        .read_exact(&mut nonce)
        .context("Failed to read nonce")?;

    stream_decrypt_to_file(encrypted_file, dist_file, &key, &nonce)?;

    Ok(())
}