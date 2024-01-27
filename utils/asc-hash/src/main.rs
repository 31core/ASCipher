use ascipher::hash::*;
use std::io::Read;

const BUFFER_SIZE: usize = 54 * 4096;

fn hash_stdin() -> std::io::Result<()> {
    let mut hasher = Hasher512::default();
    loop {
        let mut buffer = [0; BUFFER_SIZE];
        let len = std::io::stdin().read(&mut buffer)?;
        hasher.update(&buffer[..len]);
        if len == 0 {
            break;
        }
    }
    let hash_sum = hasher.digest();
    for i in hash_sum {
        print!("{:02x}", i);
    }
    println!("  -");
    Ok(())
}

fn hash_file(path: &str) -> std::io::Result<()> {
    if std::path::Path::new(path).is_dir() {
        println!("{}: Is a directory", path);
        return Ok(());
    }
    let mut input_f = std::fs::File::open(path)?;
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
        print!("{:02x}", i);
    }
    println!("  {}", path);
    Ok(())
}

fn main() -> std::io::Result<()> {
    let args = std::env::args().collect::<Vec<String>>();
    if args.len() == 1 {
        hash_stdin()?;
    } else {
        for file in &args[1..] {
            hash_file(file)?;
        }
    }
    Ok(())
}
