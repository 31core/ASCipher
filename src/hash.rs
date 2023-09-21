use crate::block::Block512;
use crate::encrypt::*;

fn generate_block(data: &[u8], size: u16, count: u64) -> [u8; 64] {
    let mut bytes = [0_u8; 64];
    bytes[0..size as usize].copy_from_slice(data);
    bytes[54..56].copy_from_slice(&size.to_be_bytes());
    bytes[56..64].copy_from_slice(&count.to_be_bytes());
    bytes
}

pub fn hash(data: &[u8]) -> [u8; 64] {
    let mut count = 0;
    let mut block = [0; 64];
    for i in 0..data.len() / 54 {
        let block_data = &data[i * 54..(i + 1) * 54];
        let this_block = confuse_key(&Block512::from_bytes(&generate_block(
            block_data, 54, count,
        )))
        .dump();
        count += 1;
        for b in 0..64 {
            block[b] ^= this_block[b];
        }
    }

    if data.len() / 54 > 0 {
        let block_data = &data[count as usize * 54..];
        let this_block = confuse_key(&Block512::from_bytes(&generate_block(
            block_data,
            (data.len() % 54) as u16,
            count,
        )))
        .dump();
        for b in 0..64 {
            block[b] ^= this_block[b];
        }
    }
    block
}
