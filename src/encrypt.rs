use crate::block::Block512;

const CONFUSE_ROUND: usize = 20;

fn shl(mut num: u32, offset: u32) -> u32 {
    let loss = num.wrapping_shr(32 - offset);
    num <<= offset;
    num |= loss;
    num
}

fn shr(mut num: u32, offset: u32) -> u32 {
    let loss = num.wrapping_shl(32 - offset);
    num >>= offset;
    num |= loss;
    num
}

fn confuse(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    let a1 = shr((a ^ b).wrapping_add(1), c % 32);
    let b1 = shl(b.wrapping_add(c) ^ 1, d % 32);
    let c1 = shr((c ^ d).wrapping_sub(1), a % 32);
    let d1 = shl(d.wrapping_sub(a) ^ 1, b % 32);
    (a1, b1, c1, d1)
}

fn confuse_key_one_round(key: &mut Block512) {
    for row in 0..4 {
        (
            key.items[row][0],
            key.items[row][1],
            key.items[row][2],
            key.items[row][3],
        ) = confuse(
            key.items[row][0],
            key.items[row][1],
            key.items[row][2],
            key.items[row][3],
        );
    }

    for col in 0..4 {
        (
            key.items[0][col],
            key.items[1][col],
            key.items[2][col],
            key.items[3][col],
        ) = confuse(
            key.items[0][col],
            key.items[1][col],
            key.items[2][col],
            key.items[3][col],
        );
    }
    for i in 0..4 {
        (
            key.items[0][i % 4],
            key.items[1][(1 + i) % 4],
            key.items[2][(2 + i) % 4],
            key.items[3][(3 + i) % 4],
        ) = confuse(
            key.items[0][i % 4],
            key.items[1][(1 + i) % 4],
            key.items[2][(2 + i) % 4],
            key.items[3][(3 + i) % 4],
        );
    }
    for i in 0..4 {
        (
            key.items[0][(7 - i) % 4],
            key.items[1][(6 - i) % 4],
            key.items[2][(5 - i) % 4],
            key.items[3][(4 - i) % 4],
        ) = confuse(
            key.items[0][(7 - i) % 4],
            key.items[1][(6 - i) % 4],
            key.items[2][(5 - i) % 4],
            key.items[3][(4 - i) % 4],
        );
    }
}

pub fn confuse_key(block: &Block512) -> Block512 {
    let mut block = block.clone();
    for _ in 0..CONFUSE_ROUND {
        confuse_key_one_round(&mut block);
    }
    block
}

/** Generate the initial block to be confused */
fn generate_bytes(key: &[u8; 32], count: u64, nonce: u64) -> [u8; 64] {
    let mut bytes = [0_u8; 64];
    bytes[0..32].copy_from_slice(key);
    bytes[32..40].copy_from_slice(&(count ^ crate::MAGIC_NUMBER).to_be_bytes());
    bytes[40..48].copy_from_slice(&nonce.to_be_bytes());
    bytes[48..64].copy_from_slice(&crate::CONSTANT);
    bytes
}

/** Do encryption or decryption with specified nonce */
pub fn encrypt_or_decrypt_with_nonce(data: &[u8], key: &[u8; 32], nonce: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut count = 0;
    let mut key_block = generate_bytes(key, count, nonce);
    let mut xor_key = confuse_key(&Block512::from_bytes(&key_block)).dump();
    for i in 0..data.len() {
        if i % 64 == 0 {
            key_block = generate_bytes(key, count, nonce);
            xor_key = confuse_key(&Block512::from_bytes(&key_block)).dump();
            count += 1;
        }
        bytes.push(data[i] ^ xor_key[i % 64]);
    }
    bytes
}

pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let nonce = rand::random::<u64>();
    let mut bytes = Vec::new();
    bytes.extend(&nonce.to_be_bytes());
    bytes.extend(encrypt_or_decrypt_with_nonce(data, key, nonce));
    bytes
}
