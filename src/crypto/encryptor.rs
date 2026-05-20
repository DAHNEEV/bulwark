use std::io::{self, Write};

use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::stream};

const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB

pub struct Encryptor<T: Write> {
    inner: T,
    stream_encryptor: stream::EncryptorBE32<XChaCha20Poly1305>,
    buffer: Vec<u8>,
}

impl<T: Write> Encryptor<T> {
    pub fn new(inner: T, key: &[u8; 32], nonce: &[u8; 19]) -> Self {
        let aead = XChaCha20Poly1305::new(key.as_ref().into());
        let stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());

        Self {
            inner,
            stream_encryptor,
            buffer: Vec::with_capacity(CHUNK_SIZE),
        }
    }

    pub fn finish(mut self) -> io::Result<T> {
        let ciphertext = self
            .stream_encryptor
            .encrypt_last(self.buffer.as_slice())
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Error encrypting last buffer")
            })?;

        self.inner.write_all(&ciphertext)?;

        self.inner.flush()?;

        Ok(self.inner)
    }
}

impl<T: Write> Write for Encryptor<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let input_len = buf.len();
        let space_left = CHUNK_SIZE - self.buffer.len();

        let to_write = std::cmp::min(input_len, space_left);

        self.buffer.extend_from_slice(&buf[..to_write]);

        if CHUNK_SIZE == self.buffer.len() {
            let ciphertext = self
                .stream_encryptor
                .encrypt_next(self.buffer.as_slice())
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Error encrypting buffer")
                })?;

            self.inner.write_all(&ciphertext)?;

            self.buffer.clear();
        }

        Ok(to_write)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
