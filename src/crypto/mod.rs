use std::{
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
};

use flate2::{Compression, write::ZlibEncoder};
use tar::Builder;

mod encryptor;
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
}

pub fn encrypt(opts: EncryptArgs) -> Result<(), anyhow::Error> {
    let output_file = File::create(opts.output_path)?;
    let mut buffered_output = BufWriter::with_capacity(1024 * 1024, output_file);

    let salt = utils::generate_random_bytes::<16>()?;
    let nonce = utils::generate_random_bytes::<19>()?;

    buffered_output.write_all(&salt)?;
    buffered_output.write_all(&nonce)?;

    let key = utils::hash_password(&opts.password, salt)?;

    let encryptor = encryptor::Encryptor::new(buffered_output, &key, &nonce);
    let compressor = ZlibEncoder::new(encryptor, Compression::fast());
    let mut archiver = Builder::new(compressor);

    for path in &opts.input_paths {
        archiver.append_path(path)?;
    }

    let compressor = archiver.into_inner()?;
    let encryptor = compressor.finish()?;
    encryptor.finish()?;

    Ok(())
}

// todo!
// pub struct DecryptArgs {
//     pub input_path: PathBuf,
//     pub output_path: PathBuf,
//     pub password: String,
// }
