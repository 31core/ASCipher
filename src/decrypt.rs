use crate::encrypt::*;

pub fn decrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let nonce = u64::from_be_bytes(data[0..8].try_into().unwrap());
    encrypt_or_decrypt_with_nonce(&data[8..], key, nonce)
}
