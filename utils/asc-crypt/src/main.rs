use ascipher::decrypt::decrypt;
use ascipher::encrypt::encrypt;
use clap::Parser;

#[derive(Parser, Debug)]

struct Args {
    #[arg(short, long)]
    encrypt: bool,
    #[arg(short, long)]
    decrypt: bool,
    #[arg(short, long)]
    input: String,
    #[arg(short, long)]
    output: String,
    #[arg(short, long)]
    key: String,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    if args.encrypt {
        let data = std::fs::read(&args.input)?;
        let mut key = [0; 32];
        for (i, k) in args.key.as_bytes().iter().enumerate() {
            key[i] = *k;
        }
        let data = encrypt(&data, &key);
        std::fs::write(&args.output, &data)?;
    }
    if args.decrypt {
        let data = std::fs::read(&args.input)?;
        let mut key = [0; 32];
        for (i, k) in args.key.as_bytes().iter().enumerate() {
            key[i] = *k;
        }
        let data = decrypt(&data, &key);
        std::fs::write(&args.output, &data)?;
    }
    Ok(())
}
