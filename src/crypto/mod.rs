use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::PathBuf,
};

mod decryptor;
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

pub fn encrypt(args: EncryptArgs) -> Result<(), anyhow::Error> {
    let (temp_guard, temp_file) = utils::TempFile::create(args.output_path)?;

    let mut buffered_output = BufWriter::with_capacity(1024 * 1024, temp_file);

    let salt = utils::generate_random_bytes::<16>()?;
    let nonce = utils::generate_random_bytes::<19>()?;

    buffered_output.write_all(&salt)?;
    buffered_output.write_all(&nonce)?;

    let key = utils::hash_password(&args.password, salt)?;

    let encryptor = encryptor::Encryptor::new(buffered_output, &key, &nonce);
    let compressor = zstd::Encoder::new(encryptor, 9)?;
    let mut archiver = tar::Builder::new(compressor);

    for path in &args.input_paths {
        archiver.append_path(path)?;
    }

    let compressor = archiver.into_inner()?;
    let encryptor = compressor.finish()?;
    encryptor.finish()?;

    temp_guard.commit()?;

    Ok(())
}

pub struct DecryptArgs {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub password: String,
}

pub fn decrypt(args: DecryptArgs) -> Result<(), anyhow::Error> {
    let input_file = File::open(args.input_path)?;
    let mut buffered_input = BufReader::with_capacity(1024 * 1024, input_file);

    let mut salt = [0u8; 16];
    buffered_input.read_exact(&mut salt)?;
    let mut nonce = [0u8; 19];
    buffered_input.read_exact(&mut nonce)?;

    let key = utils::hash_password(&args.password, salt)?;

    let decryptor = decryptor::Decryptor::new(buffered_input, &key, &nonce);
    let decompressor = zstd::Decoder::new(decryptor)?;
    let mut dearchiver = tar::Archive::new(decompressor);

    dearchiver.unpack(args.output_path)?;

    Ok(())
}
