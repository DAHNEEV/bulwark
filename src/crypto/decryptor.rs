use std::io::{self, Cursor, Read};

use chacha20poly1305::{KeyInit, XChaCha20Poly1305, aead::stream};

const CHUNK_SIZE: usize = 1024 * 1024 + 16;

pub struct Decryptor<T: Read> {
    inner: T,
    stream_decryptor: Option<stream::DecryptorBE32<XChaCha20Poly1305>>,
    buffer: Cursor<Vec<u8>>,
    next_chunk: Option<Vec<u8>>,
    is_eof: bool,
}

impl<T: Read> Decryptor<T> {
    pub fn new(inner: T, key: &[u8; 32], nonce: &[u8; 19]) -> Self {
        let aead = XChaCha20Poly1305::new(key.as_ref().into());
        let stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());

        Self {
            inner,
            stream_decryptor: Some(stream_decryptor),
            buffer: Cursor::new(Vec::with_capacity(CHUNK_SIZE)),
            next_chunk: None,
            is_eof: false,
        }
    }

    fn read_full_chunk(inner: &mut T) -> io::Result<Vec<u8>> {
        let mut chunk = vec![0u8; CHUNK_SIZE];
        let mut total_read = 0;

        while total_read < CHUNK_SIZE {
            let bytes_read = inner.read(&mut chunk[total_read..])?;
            if bytes_read == 0 {
                break;
            }
            total_read += bytes_read;
        }

        chunk.truncate(total_read);
        Ok(chunk)
    }
}

impl<T: Read> Read for Decryptor<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.next_chunk.is_none() {
                self.next_chunk = Some(Self::read_full_chunk(&mut self.inner)?);
            }

            let bytes_read = self.buffer.read(buf)?;
            if bytes_read > 0 {
                return Ok(bytes_read);
            }

            if self.is_eof {
                return Ok(0);
            }

            let following_chunk = Self::read_full_chunk(&mut self.inner)?;

            let current_chunk = self.next_chunk.take().expect("next_chunk missing");

            let plaintext = if following_chunk.is_empty() {
                self.is_eof = true;
                self.stream_decryptor
                    .take()
                    .expect("Decryptor already consumed")
                    .decrypt_last(current_chunk.as_slice())
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "Error decrypting last buffer")
                    })?
            } else {
                self.stream_decryptor
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
