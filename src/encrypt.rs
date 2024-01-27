use crate::{block::Block512, *};

const CONFUSE_ROUND_512: usize = 20;

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

fn confuse512(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    let a1 = shr((a ^ b).wrapping_add(1), c % 32);
    let b1 = shl(b.wrapping_add(c) ^ 1, d % 32);
    let c1 = shr((c ^ d).wrapping_sub(1), a % 32);
    let d1 = shl(d.wrapping_sub(a) ^ 1, b % 32);
    (a1, b1, c1, d1)
}

fn confuse512_key_one_round(key: &mut Block512) {
    for row in 0..4 {
        (key.0[row][0], key.0[row][1], key.0[row][2], key.0[row][3]) =
            confuse512(key.0[row][0], key.0[row][1], key.0[row][2], key.0[row][3]);
    }

    for col in 0..4 {
        (key.0[0][col], key.0[1][col], key.0[2][col], key.0[3][col]) =
            confuse512(key.0[0][col], key.0[1][col], key.0[2][col], key.0[3][col]);
    }
    for i in 0..4 {
        (
            key.0[0][i % 4],
            key.0[1][(1 + i) % 4],
            key.0[2][(2 + i) % 4],
            key.0[3][(3 + i) % 4],
        ) = confuse512(
            key.0[0][i % 4],
            key.0[1][(1 + i) % 4],
            key.0[2][(2 + i) % 4],
            key.0[3][(3 + i) % 4],
        );
    }
    for i in 0..4 {
        (
            key.0[0][(7 - i) % 4],
            key.0[1][(6 - i) % 4],
            key.0[2][(5 - i) % 4],
            key.0[3][(4 - i) % 4],
        ) = confuse512(
            key.0[0][(7 - i) % 4],
            key.0[1][(6 - i) % 4],
            key.0[2][(5 - i) % 4],
            key.0[3][(4 - i) % 4],
        );
    }
}

pub fn confuse_key512(block: &Block512) -> Block512 {
    let mut block = block.clone();
    for _ in 0..CONFUSE_ROUND_512 {
        confuse512_key_one_round(&mut block);
    }
    block
}

/** Generate the initial block to be confused */
fn generate_bytes512(key: &[u8; KEY_SIZE_512], count: u64, nonce: u64) -> [u8; BLOCK_SIZE_512] {
    let mut bytes = [0_u8; BLOCK_SIZE_512];
    bytes[0..32].copy_from_slice(key);
    bytes[32..40].copy_from_slice(&(count ^ crate::MAGIC_NUMBER).to_be_bytes());
    bytes[40..48].copy_from_slice(&nonce.to_be_bytes());
    bytes[48..64].copy_from_slice(&crate::CONSTANT);
    bytes
}

/** Do encryption or decryption with specified nonce */
pub fn apply_with_nonce(data: &[u8], key: &[u8; KEY_SIZE_512], nonce: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut count = 0;
    let mut key_block = generate_bytes512(key, count, nonce);
    let mut xor_key = confuse_key512(&Block512::from_bytes(&key_block)).dump();
    for i in 0..data.len() {
        if i % BLOCK_SIZE_512 == 0 {
            key_block = generate_bytes512(key, count, nonce);
            xor_key = confuse_key512(&Block512::from_bytes(&key_block)).dump();
            count += 1;
        }
        bytes.push(data[i] ^ xor_key[i % BLOCK_SIZE_512]);
    }
    bytes
}

/** Encrypt whole data.
 *
 * It will call function `apply_with_nonce` and concat the nonce to the start of the encrypted data. */
pub fn apply512(data: &[u8], key: &[u8; KEY_SIZE_512]) -> Vec<u8> {
    let nonce = rand::random::<u64>();
    let mut bytes = Vec::new();
    bytes.extend(&nonce.to_be_bytes());
    bytes.extend(apply_with_nonce(data, key, nonce));
    bytes
}

pub struct Cipher512 {
    pub key: [u8; KEY_SIZE_512],
    pub counter: u64,
    pub nonce: u64,

    last: usize,
    block: [u8; BLOCK_SIZE_512],
}

impl Cipher512 {
    pub fn new(key: &[u8; KEY_SIZE_512]) -> Self {
        let nonce = rand::random::<u64>();
        Self {
            key: *key,
            counter: 0,
            nonce,

            last: 0,
            block: [0; BLOCK_SIZE_512],
        }
    }
    fn generate_block(&mut self) {
        self.block = confuse_key512(&Block512::from_bytes(&generate_bytes512(
            &self.key,
            self.counter,
            self.nonce,
        )))
        .dump();
    }
    /** Apply on any length of data */
    pub fn apply_any(&mut self, data: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        if self.last > 0 {
            for (i, _) in data.iter().enumerate().take(self.last) {
                bytes.push(data[i] ^ self.block[BLOCK_SIZE_512 - self.last + i]);
            }
        }
        for (i, _) in data.iter().enumerate().skip(self.last) {
            if i % BLOCK_SIZE_512 == 0 {
                self.generate_block();
                self.counter += 1;
            }
            bytes.push(data[i] ^ self.block[i % BLOCK_SIZE_512]);
        }
        self.last = data.len() % BLOCK_SIZE_512;
        bytes
    }
    /** Apply a 512-bit block */
    pub fn apply_block(&mut self, block: &[u8; BLOCK_SIZE_512]) -> [u8; BLOCK_SIZE_512] {
        let e = apply_with_nonce(block, &self.key, self.nonce);
        self.counter += 1;
        e.try_into().unwrap()
    }
}
