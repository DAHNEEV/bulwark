use std::{
    fs::File,
    io::{Read, Write},
};

use argon2::{
    Argon2,
    password_hash::{
        SaltString,
        rand_core::{OsRng, RngCore},
    },
};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::stream};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Encrypt {
        password: String,
        source_file_path: String,
        dist_file_path: String,
    },
    Decrypt {
        #[arg(short, long)]
        password: String,
    },
}

fn generate_salt() -> SaltString {
    SaltString::generate(&mut OsRng)
}

fn hash_password(password: &str, salt: SaltString) -> Result<[u8; 32], anyhow::Error> {
    let argon2 = Argon2::default();

    let mut key = [0u8; 32];

    argon2
        .hash_password_into(password.as_bytes(), &salt.as_str().as_bytes(), &mut key)
        .map_err(|err| anyhow::anyhow!("Encrypting large file: {}", err))?;

    Ok(key)
}

fn generate_nonce() -> [u8; 19] {
    let mut bytes = [0u8; 19];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

// maybe make it generics? todo!
fn write_key_to_file(mut dist_file: &File, key: &[u8; 32]) -> Result<(), anyhow::Error> {
    dist_file.write(key)?;
    Ok(())
}

fn write_nonce_to_file(mut dist_file: &File, nonce: &[u8; 19]) -> Result<(), anyhow::Error> {
    dist_file.write(nonce)?;
    Ok(())
}

// thinking in progress
// fn write_to_file<T: AsRef<[u8]>>(mut dist_file: &File, text: T) -> Result<(), anyhow::Error> {
//     dist_file.write(text.as_ref())?;
//     Ok(())
// }

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
        let read_count = source_file.read(&mut buffer)?;

        if read_count == BUFFER_LEN {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow::anyhow!("Encrypting large file: {}", err))?;
            dist_file.write(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow::anyhow!("Encrypting large file: {}", err))?;
            dist_file.write(&ciphertext)?;
            break;
        }
    }

    Ok(())
}

fn encrypt_file(
    source_file_path: String,
    dist_file_path: String,
    password: String,
) -> Result<(), anyhow::Error> {
    let source_file = File::open(source_file_path)?;
    let dist_file = File::create(dist_file_path)?;

    let salt = generate_salt();
    let key = hash_password(&password, salt)?;
    write_key_to_file(&dist_file, &key)?;

    let nonce = generate_nonce();
    write_nonce_to_file(&dist_file, &nonce)?;

    stream_encrypt_to_file(source_file, dist_file, &key, &nonce)?;

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            password,
            source_file_path,
            dist_file_path,
        } => encrypt_file(source_file_path, dist_file_path, password).unwrap(),
        Commands::Decrypt { .. } => {}
    }
}
