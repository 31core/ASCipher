use ascipher::hash::hash;

fn main() -> std::io::Result<()> {
    let args = std::env::args().collect::<Vec<String>>();
    let hash_sum = hash(&std::fs::read(&args[1])?);
    for i in hash_sum {
        print!("{:x}", i);
    }
    println!();
    Ok(())
}
