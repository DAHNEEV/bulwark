use std::io;
use std::ops::Sub;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::generic_array::ArrayLength;
use chacha20poly1305::aead::{Payload, generic_array::GenericArray};
use chacha20poly1305::consts::U5;
use rayon::iter::{IndexedParallelIterator, ParallelIterator};
use rayon::slice::ParallelSlice;

struct StreamBE32<A>
where
    A: Aead + Sync,
    A::NonceSize: Sub<U5>,
    <A::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    aead: A,
    base_nonce: GenericArray<u8, <A::NonceSize as Sub<U5>>::Output>,
    chunk_count: u32,
    chunk_size: usize,
}

impl<A> StreamBE32<A>
where
    A: Aead + Sync,
    A::NonceSize: Sub<U5>,
    <A::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    fn from_aead(
        aead: A,
        nonce: GenericArray<u8, <A::NonceSize as Sub<U5>>::Output>,
        chunk_size: usize,
    ) -> Self {
        Self {
            aead,
            base_nonce: nonce,
            chunk_count: 0,
            chunk_size,
        }
    }

    fn encrypt_chunk<'msg, 'aad>(
        &mut self,
        is_last: bool,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> io::Result<Vec<u8>> {
        let payload: Payload = plaintext.into();

        let chunks_count = payload.msg.len().div_ceil(self.chunk_size);

        let ciphertext: Vec<Vec<u8>> = payload
            .msg
            .par_chunks(self.chunk_size)
            .enumerate()
            .map(|(i, chunk)| {
                let num = self.chunk_count + i as u32;
                let is_last = (chunks_count - 1 == i) && is_last;

                let nonce = self.generate_nonce(num, is_last);

                self.aead
                    .encrypt(&nonce, chunk)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error encrypting buffer"))
            })
            .collect::<Result<_, _>>()?;

        self.chunk_count += chunks_count as u32;

        Ok(ciphertext.concat())
    }

    fn decrypt_chunk<'msg, 'aad>(
        &mut self,
        is_last: bool,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> io::Result<Vec<u8>> {
        let payload: Payload = ciphertext.into();

        let chunks_count = payload.msg.len().div_ceil(self.chunk_size);

        let ciphertext: Vec<Vec<u8>> = payload
            .msg
            .par_chunks(self.chunk_size)
            .enumerate()
            .map(|(i, chunk)| {
                let num = self.chunk_count + i as u32;
                let is_last = (chunks_count - 1 == i) && is_last;

                let nonce = self.generate_nonce(num, is_last);

                self.aead
                    .decrypt(&nonce, chunk)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error decrypting buffer"))
            })
            .collect::<Result<_, _>>()?;

        self.chunk_count += chunks_count as u32;

        Ok(ciphertext.concat())
    }

    fn generate_nonce(&self, num: u32, is_last: bool) -> GenericArray<u8, A::NonceSize> {
        let mut nonce = GenericArray::<u8, A::NonceSize>::default();
        let base_len = self.base_nonce.len();

        nonce[..base_len].copy_from_slice(&self.base_nonce);
        nonce[base_len..base_len + 4].copy_from_slice(&num.to_be_bytes());
        nonce[base_len + 4] = if is_last { 1 } else { 0 };

        nonce
    }
}

pub struct EncryptorBE32<A>
where
    A: Aead + Sync,
    A::NonceSize: Sub<U5>,
    <A::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    stream: StreamBE32<A>,
}

impl<A> EncryptorBE32<A>
where
    A: Aead + Sync,
    A::NonceSize: Sub<U5>,
    <A::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    pub fn from_aead(
        aead: A,
        nonce: GenericArray<u8, <A::NonceSize as Sub<U5>>::Output>,
        chunk_size: usize,
    ) -> Self {
        Self {
            stream: StreamBE32::from_aead(aead, nonce, chunk_size),
        }
    }

    pub fn encrypt_next<'msg, 'aad>(
        &mut self,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> io::Result<Vec<u8>> {
        self.stream.encrypt_chunk(false, plaintext)
    }

    pub fn encrypt_last<'msg, 'aad>(
        &mut self,
        plaintext: impl Into<Payload<'msg, 'aad>>,
    ) -> io::Result<Vec<u8>> {
        self.stream.encrypt_chunk(true, plaintext)
    }
}

pub struct DecryptorBE32<A>
where
    A: Aead + Sync,
    A::NonceSize: Sub<U5>,
    <A::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    stream: StreamBE32<A>,
}

impl<A> DecryptorBE32<A>
where
    A: Aead + Sync,
    A::NonceSize: Sub<U5>,
    <A::NonceSize as Sub<U5>>::Output: ArrayLength<u8>,
{
    pub fn from_aead(
        aead: A,
        nonce: GenericArray<u8, <A::NonceSize as Sub<U5>>::Output>,
        chunk_size: usize,
    ) -> Self {
        Self {
            stream: StreamBE32::from_aead(aead, nonce, chunk_size),
        }
    }

    pub fn decrypt_next<'msg, 'aad>(
        &mut self,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> io::Result<Vec<u8>> {
        self.stream.decrypt_chunk(false, ciphertext)
    }

    pub fn decrypt_last<'msg, 'aad>(
        &mut self,
        ciphertext: impl Into<Payload<'msg, 'aad>>,
    ) -> io::Result<Vec<u8>> {
        self.stream.decrypt_chunk(true, ciphertext)
    }
}
