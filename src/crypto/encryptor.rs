use std::io::{self, Write};

use chacha20poly1305::aead::Aead;
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSlice,
};

use crate::crypto::nonce::NonceGenerator;

const CHUNK_SIZE: usize = 1024 * 1024 * 4; // 4 MB
const THREADS: usize = 4;
const PART_CHUNK_SIZE: usize = CHUNK_SIZE / THREADS;

pub struct Encryptor<W: Write, A: Aead + Sync, N: NonceGenerator<A> + Sync> {
    inner: W,
    aead: A,
    nonce_generator: N,
    buffer: Vec<u8>,
    chunk_count: u32,
}

impl<W: Write, A: Aead + Sync, N: NonceGenerator<A> + Sync> Encryptor<W, A, N> {
    pub fn new(inner: W, aead: A, nonce_generator: N) -> Self {
        Self {
            inner,
            aead,
            nonce_generator,
            buffer: Vec::with_capacity(CHUNK_SIZE),
            chunk_count: 0,
        }
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.encrypt_chunk(true)?;

        self.inner.flush()?;

        Ok(self.inner)
    }

    fn encrypt_chunk(&mut self, is_last: bool) -> io::Result<()> {
        let subchunks_count = self.buffer.len().div_ceil(PART_CHUNK_SIZE);

        let ciphertext: Vec<Vec<u8>> = self
            .buffer
            .par_chunks(PART_CHUNK_SIZE)
            .enumerate()
            .map(|(i, chunk)| {
                let num = self.chunk_count + i as u32;
                let is_last = (subchunks_count - 1 == i) && is_last;

                let nonce = self.nonce_generator.generate(num, is_last);

                self.aead
                    .encrypt(&nonce, chunk)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error encrypting buffer"))
            })
            .collect::<Result<_, _>>()?;

        self.chunk_count += subchunks_count as u32;

        for ct in &ciphertext {
            self.inner.write_all(ct)?;
        }

        self.buffer.clear();

        Ok(())
    }
}

impl<W: Write, A: Aead + Sync, N: NonceGenerator<A> + Sync> Write for Encryptor<W, A, N> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // if there is not enough data to perform the encryption, just save them
        if self.buffer.len() + buf.len() < CHUNK_SIZE {
            self.buffer.extend_from_slice(buf);
            return Ok(buf.len());
        }

        // otherwise, read as much data as needed to fill the buffer
        let space_left = CHUNK_SIZE - self.buffer.len();
        self.buffer.extend_from_slice(&buf[..space_left]);

        self.encrypt_chunk(false)?;

        Ok(space_left)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.encrypt_chunk(false)?;

        self.inner.flush()
    }
}
