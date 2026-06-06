use chacha20poly1305::{AeadCore, XChaCha20Poly1305, aead::generic_array::GenericArray};

//
pub struct NonceXChaCha20Poly1305 {
    pub base_nonce: [u8; 19],
}

pub trait NonceGenerator<A: AeadCore> {
    fn generate(&self, num: u32, is_last: bool) -> GenericArray<u8, A::NonceSize>;
}

impl NonceGenerator<XChaCha20Poly1305> for NonceXChaCha20Poly1305 {
    fn generate(
        &self,
        num: u32,
        is_last: bool,
    ) -> GenericArray<u8, <XChaCha20Poly1305 as AeadCore>::NonceSize> {
        let mut nonce = [0u8; 24];

        nonce[..19].copy_from_slice(&self.base_nonce);
        nonce[19..23].copy_from_slice(&num.to_be_bytes());
        nonce[23] = if is_last { 1 } else { 0 };

        GenericArray::clone_from_slice(&nonce)
    }
}
