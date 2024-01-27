use crate::block::Block512;
use crate::{encrypt::*, BLOCK_SIZE_512};

const ROUND_SIZE: usize = 54;

fn generate_block(data: &[u8], size: u16, count: u64) -> [u8; BLOCK_SIZE_512] {
    let mut bytes = [0_u8; BLOCK_SIZE_512];
    bytes[0..size as usize].copy_from_slice(data);
    bytes[54..56].copy_from_slice(&size.to_be_bytes());
    bytes[56..64].copy_from_slice(&count.to_be_bytes());
    bytes
}

/** Compute ascipher-hash-512 summary for all bytes at one time */
pub fn hash512(data: &[u8]) -> [u8; BLOCK_SIZE_512] {
    let mut count = 0;
    let mut block = [0; BLOCK_SIZE_512];
    for i in 0..data.len() / ROUND_SIZE {
        let block_data = &data[i * ROUND_SIZE..(i + 1) * ROUND_SIZE];
        let this_block = confuse_key512(&Block512::from_bytes(&generate_block(
            block_data,
            ROUND_SIZE as u16,
            count,
        )))
        .dump();
        count += 1;
        for b in 0..BLOCK_SIZE_512 {
            block[b] ^= this_block[b];
        }
    }

    if data.len() % ROUND_SIZE > 0 {
        let block_data = &data[count as usize * ROUND_SIZE..];
        let this_block = confuse_key512(&Block512::from_bytes(&generate_block(
            block_data,
            (data.len() % ROUND_SIZE) as u16,
            count,
        )))
        .dump();
        for b in 0..BLOCK_SIZE_512 {
            block[b] ^= this_block[b];
        }
    }
    block
}

pub struct Hasher512 {
    counter: u64,

    result: [u8; BLOCK_SIZE_512],
    block_last: [u8; ROUND_SIZE],
    last_size: usize,
}

impl Hasher512 {
    pub fn update(&mut self, bytes_src: &[u8]) {
        let mut bytes = self.block_last[..self.last_size].to_vec();
        bytes.extend(bytes_src);
        self.last_size = 0;
        for i in 0..bytes.len() / ROUND_SIZE {
            let this_block = confuse_key512(&Block512::from_bytes(&generate_block(
                &bytes[ROUND_SIZE * i..ROUND_SIZE * (i + 1)],
                ROUND_SIZE as u16,
                self.counter,
            )))
            .dump();
            for (b, _) in this_block.iter().enumerate().take(BLOCK_SIZE_512) {
                self.result[b] ^= this_block[b];
            }
            self.counter += 1;
        }
        if bytes.len() % ROUND_SIZE > 0 {
            self.block_last[self.last_size..self.last_size + bytes.len() % ROUND_SIZE]
                .copy_from_slice(&bytes[bytes.len() - bytes.len() % ROUND_SIZE..]);
            self.last_size += bytes.len() % ROUND_SIZE;
        }
    }
    pub fn digest(&mut self) -> [u8; BLOCK_SIZE_512] {
        let this_block = confuse_key512(&Block512::from_bytes(&generate_block(
            &self.block_last[..self.last_size],
            self.last_size as u16,
            self.counter,
        )))
        .dump();
        for (b, _) in this_block.iter().enumerate().take(BLOCK_SIZE_512) {
            self.result[b] ^= this_block[b];
        }
        self.result
    }
}

impl Default for Hasher512 {
    fn default() -> Self {
        Self {
            counter: 0,
            result: [0; BLOCK_SIZE_512],
            block_last: [0; ROUND_SIZE],
            last_size: 0,
        }
    }
}
