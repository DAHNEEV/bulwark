use std::{
    io::{self, Cursor, Read},
    ops::Sub,
};

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, generic_array::GenericArray},
    aes::cipher::ArrayLength,
};
use chacha20poly1305::{XChaCha20Poly1305, consts::U5};

use crate::crypto::parallel_stream;

pub enum Decryptor<R: Read> {
    Aes256Gcm(GenericDecryptor<R, Aes256Gcm>),
    XChaCha20Poly1305(GenericDecryptor<R, XChaCha20Poly1305>),
}

impl<R: Read> Read for Decryptor<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Aes256Gcm(d) => d.read(buf),
            Self::XChaCha20Poly1305(d) => d.read(buf),
        }
    }
}

pub struct GenericDecryptor<R, A>
where
    R: Read,
    A: Aead + Sync,
    A::NonceSize: Sub<U5>,
    <A::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    inner: R,
    parallel_stream: Option<parallel_stream::DecryptorBE32<A>>,
    buffer: Cursor<Vec<u8>>,
    next_chunk: Option<Vec<u8>>,
    is_eof: bool,
    buffer_size: usize,
}

impl<R, A> GenericDecryptor<R, A>
where
    R: Read,
    A: Aead + Sync,
    A::NonceSize: Sub<U5>,
    <A::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    pub fn new(
        inner: R,
        aead: A,
        nonce: GenericArray<u8, <A::NonceSize as Sub<U5>>::Output>,
        chunk_size: usize,
        threads: usize,
    ) -> Self {
        let buffer_size = chunk_size * threads;
        Self {
            inner,
            parallel_stream: Some(parallel_stream::DecryptorBE32::from_aead(
                aead, nonce, chunk_size,
            )),
            buffer: Cursor::new(Vec::with_capacity(buffer_size)),
            next_chunk: None,
            is_eof: false,
            buffer_size,
        }
    }

    fn read_full_chunk(&mut self) -> io::Result<Vec<u8>> {
        let mut chunk = vec![0u8; self.buffer_size];
        let mut total_read = 0;

        while total_read < self.buffer_size {
            let bytes_read = self.inner.read(&mut chunk[total_read..])?;
            if bytes_read == 0 {
                break;
            }
            total_read += bytes_read;
        }

        chunk.truncate(total_read);
        Ok(chunk)
    }
}

impl<R, A> Read for GenericDecryptor<R, A>
where
    R: Read,
    A: Aead + Sync,
    A::NonceSize: Sub<U5>,
    <A::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.next_chunk.is_none() {
                self.next_chunk = Some(self.read_full_chunk()?);
            }

            let bytes_read = self.buffer.read(buf)?;
            if bytes_read > 0 {
                return Ok(bytes_read);
            }

            if self.is_eof {
                return Ok(0);
            }

            let following_chunk = self.read_full_chunk()?;

            let current_chunk = self.next_chunk.take().expect("next_chunk missing");

            let plaintext = if following_chunk.is_empty() {
                self.is_eof = true;
                self.parallel_stream
                    .take()
                    .expect("Decryptor already consumed")
                    .decrypt_last(current_chunk.as_slice())
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "Error decrypting last buffer")
                    })?
            } else {
                self.parallel_stream
                    .as_mut()
                    .expect("Missing decryptor")
                    .decrypt_next(current_chunk.as_slice())
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "Error decrypting buffer")
                    })?
            };

            self.buffer = Cursor::new(plaintext);
            self.next_chunk = Some(following_chunk);
        }
    }
}
