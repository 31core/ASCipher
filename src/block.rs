#[derive(Clone, Debug)]
pub struct Block512 {
    pub items: [[u32; 4]; 4],
}

impl Block512 {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut items = [[0_u32; 4]; 4];
        for row in 0..4 {
            for col in 0..4 {
                items[row][col] = u32::from_be_bytes(
                    bytes[row * 16 + col * 4..row * 16 + (col + 1) * 4]
                        .try_into()
                        .unwrap(),
                );
            }
        }
        Self { items }
    }
    /** dump to bytes */
    pub fn dump(&self) -> [u8; 64] {
        let mut bytes = [0; 64];
        for row in 0..4 {
            for cow in 0..4 {
                bytes[row * 16 + cow * 4..row * 16 + (cow + 1) * 4]
                    .copy_from_slice(&self.items[row][cow].to_be_bytes());
            }
        }
        bytes
    }
}
