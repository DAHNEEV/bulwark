use std::{
    io::{self, Write},
    ops::Sub,
};

use chacha20poly1305::{
    aead::{
        Aead,
        generic_array::{ArrayLength, GenericArray},
    },
    consts::U5,
};

use crate::crypto::parallel_stream;

pub struct Encryptor<W, A>
where
    W: Write,
    A: Aead + Sync,
    A::NonceSize: Sub<U5>,
    <A::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    inner: W,
    parallel_stream: parallel_stream::EncryptorBE32<A>,
    buffer: Vec<u8>,
    buffer_size: usize,
}

impl<W, A> Encryptor<W, A>
where
    W: Write,
    A: Aead + Sync,
    A::NonceSize: Sub<U5>,
    <A::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    pub fn new(
        inner: W,
        aead: A,
        nonce: GenericArray<u8, <A::NonceSize as Sub<U5>>::Output>,
        chunk_size: usize,
        threads: usize,
    ) -> Self {
        let buffer_size = chunk_size * threads;
        Self {
            inner,
            parallel_stream: parallel_stream::EncryptorBE32::from_aead(aead, nonce, chunk_size),
            buffer: Vec::with_capacity(buffer_size),
            buffer_size,
        }
    }

    pub fn finish(mut self) -> io::Result<W> {
        let ciphertext = self.parallel_stream.encrypt_last(self.buffer.as_slice())?;

        self.inner.write_all(&ciphertext)?;

        self.buffer.clear();

        self.inner.flush()?;

        Ok(self.inner)
    }
}

impl<W, A> Write for Encryptor<W, A>
where
    W: Write,
    A: Aead + Sync,
    A::NonceSize: Sub<U5>,
    <A::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // if there is not enough data to perform the encryption, just save them
        if self.buffer.len() + buf.len() < self.buffer_size {
            self.buffer.extend_from_slice(buf);
            return Ok(buf.len());
        }

        // otherwise, read as much data as needed to fill the buffer
        let space_left = self.buffer_size - self.buffer.len();
        self.buffer.extend_from_slice(&buf[..space_left]);

        let ciphertext = self.parallel_stream.encrypt_next(self.buffer.as_slice())?;

        self.inner.write_all(&ciphertext)?;

        self.buffer.clear();

        Ok(space_left)
    }

    fn flush(&mut self) -> io::Result<()> {
        let ciphertext = self.parallel_stream.encrypt_next(self.buffer.as_slice())?;

        self.inner.write_all(&ciphertext)?;

        self.buffer.clear();

        self.inner.flush()
    }
}
