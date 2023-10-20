use ascipher::hash::*;
use std::io::Read;

const BUFFER_SIZE: usize = 54 * 1024;

fn main() -> std::io::Result<()> {
    let args = std::env::args().collect::<Vec<String>>();
    let mut input_f = std::fs::File::open(&args[1])?;
    let mut hasher = Hasher512::default();
    loop {
        let mut buffer = [0; BUFFER_SIZE];
        let len = input_f.read(&mut buffer)?;
        hasher.update(&buffer[..len]);
        if len == 0 {
            break;
        }
    }
    let hash_sum = hasher.digest();
    for i in hash_sum {
        print!("{:x}", i);
    }
    println!();
    Ok(())
}
