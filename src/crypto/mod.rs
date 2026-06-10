use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use aes_gcm::Aes256Gcm;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};

mod decryptor;
mod encryptor;
mod parallel_stream;
mod utils;

// todo!
// struct FileHeader {
//     compression: Compression,
//     encryption: Encryption,
// }

pub struct EncryptArgs {
    pub input_paths: Vec<PathBuf>,
    pub output_path: PathBuf,
    pub password: String,
    pub algorithm: Algorithm,
    pub compression: bool, // todo!
    pub compression_level: i32,
}

#[derive(Clone, PartialEq)]
pub enum Algorithm {
    Aes256Gcm,
    XChaCha20Poly1305,
}

/// The main function responsible for encrypting the file.
///
/// Processes the data in the following order:
/// ```text
/// Input file(s) -> Archiver -> Encoder (Compression) -> Encryptor -> BufWriter -> Output file
/// ```
/// Each layer implements the [`std::io::Write`] trait to pass data to the next layer.
///
/// # Atomicity
/// The entire operation is atomic, meaning that a temporary file ([`utils::TempFile`]) is created to which the data is written; if an error or panic occurs, the file is deleted; otherwise, an atomic (from the file system’s perspective) rename operation takes place (which removes the temporary part from the file name).
/// > If a situation arises where, after the entire process is complete, the temporary file remains on the disk, such a file should be considered corrupted.
pub fn encrypt(args: EncryptArgs) -> Result<(), anyhow::Error> {
    let (temp_guard, temp_file) = utils::TempFile::create(args.output_path)?;

    let mut buffered_output = BufWriter::with_capacity(1024 * 1024, temp_file);

    let salt: [u8; 16] = utils::generate_random_bytes()?;

    buffered_output.write_all(&salt)?;

    let key = utils::hash_password(&args.password, salt)?;

    let encryptor = match &args.algorithm {
        Algorithm::Aes256Gcm => {
            let nonce: [u8; 7] = utils::generate_random_bytes()?;

            buffered_output.write_all(&nonce)?;

            let aead = Aes256Gcm::new(&key.into());
            encryptor::Encryptor::Aes256Gcm(encryptor::GenericEncryptor::new(
                buffered_output,
                aead,
                nonce.into(),
                1024 * 1024,
                4,
            ))
        }
        Algorithm::XChaCha20Poly1305 => {
            let nonce: [u8; 19] = utils::generate_random_bytes()?;

            buffered_output.write_all(&nonce)?;

            let aead = XChaCha20Poly1305::new(&key.into());
            encryptor::Encryptor::XChaCha20Poly1305(encryptor::GenericEncryptor::new(
                buffered_output,
                aead,
                nonce.into(),
                1024 * 1024,
                4,
            ))
        }
    };

    let mut encoder = zstd::Encoder::new(encryptor, args.compression_level)?;
    encoder.multithread(3)?;
    let mut archiver = tar::Builder::new(encoder);

    for path in &args.input_paths {
        let path = Path::new(path);

        if let Some(file_name) = path.file_name() {
            if path.is_dir() {
                archiver.append_dir_all(file_name, path)?;
            } else {
                archiver.append_path_with_name(path, file_name)?;
            }
        }
    }

    let encoder = archiver.into_inner()?;
    let encryptor = encoder.finish()?;
    encryptor.finish()?;

    temp_guard.commit()?;

    Ok(())
}

pub struct DecryptArgs {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub password: String,
    pub algorithm: Algorithm,
}

/// The main function responsible for decrypting the file.
///
/// Processes the data in the following order:
/// ```text
/// Input file -> BufReader -> Decryptor -> Decoder (Decompression) -> Dearchiver -> Output dir
/// ```
/// > All decrypted files are placed in the output folder, which means that even if only a single file was encrypted, the decryption process will result in a folder containing that single file.
///
/// # Atomicity
/// The entire operation is atomic, meaning that a temporary directory ([`utils::TempDir`]) is created to store the data (decrypted files); if an error or panic occurs, the directory (and the files it contains) is deleted; otherwise, an atomic (from the file system’s perspective) rename operation takes place (which removes the temporary part from the directory name).
/// > If a situation arises where, after the entire process is complete, the temporary directory remains on the disk, such a directory (and the files it contains) should be considered corrupted.
pub fn decrypt(args: DecryptArgs) -> Result<(), anyhow::Error> {
    let input_file = File::open(args.input_path)?;
    let mut buffered_input = BufReader::with_capacity(1024 * 1024, input_file);

    let mut salt = [0u8; 16];
    buffered_input.read_exact(&mut salt)?;

    let key = utils::hash_password(&args.password, salt)?;

    let decryptor = match &args.algorithm {
        Algorithm::Aes256Gcm => {
            let mut nonce = [0u8; 7];
            buffered_input.read_exact(&mut nonce)?;

            let aead = Aes256Gcm::new(&key.into());
            decryptor::Decryptor::Aes256Gcm(decryptor::GenericDecryptor::new(
                buffered_input,
                aead,
                nonce.into(),
                1024 * 1024 + 16,
                4,
            ))
        }
        Algorithm::XChaCha20Poly1305 => {
            let mut nonce = [0u8; 19];
            buffered_input.read_exact(&mut nonce)?;

            let aead = XChaCha20Poly1305::new(&key.into());
            decryptor::Decryptor::XChaCha20Poly1305(decryptor::GenericDecryptor::new(
                buffered_input,
                aead,
                nonce.into(),
                1024 * 1024 + 16,
                4,
            ))
        }
    };
    let decoder = zstd::Decoder::new(decryptor)?;
    let mut dearchiver = tar::Archive::new(decoder);

    let temp_dir = utils::TempDir::create(args.output_path)?;

    dearchiver.unpack(&temp_dir.temp_dir_path)?;

    temp_dir.commit()?;

    Ok(())
}
