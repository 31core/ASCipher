use clap::{Parser, Subcommand};
use std::fs::*;
use std::io::{Read, Result as IOResult, Write};

const BUFFER_SIZE: usize = 4096;

#[derive(Parser)]

struct Args {
    #[arg(short, long)]
    input: String,
    #[arg(short, long)]
    output: String,
    #[arg(short, long)]
    key: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Clone)]
enum Command {
    /// Encrypt a file
    Encrypt,
    /// Decrypt a file
    Decrypt,
}

fn main() -> IOResult<()> {
    let args = Args::parse();

    match args.command {
        Command::Encrypt => {
            let mut key = [0; 32];
            for (i, k) in args.key.as_bytes().iter().enumerate() {
                key[i] = *k;
            }
            let mut cipher = ascipher::encrypt::Cipher512::new(&key);
            let mut input_f = File::open(&args.input)?;
            let mut out_f = OpenOptions::new()
                .write(true)
                .create(true)
                .open(&args.output)?;
            out_f.write_all(&cipher.nonce.to_be_bytes())?;
            loop {
                let mut buffer = [0; BUFFER_SIZE];
                let len = input_f.read(&mut buffer)?;
                if len == 0 {
                    break;
                }
                out_f.write_all(&cipher.apply_any(&buffer[..len]))?;
            }
        }
        Command::Decrypt => {
            let mut input_f = File::open(args.input)?;
            let mut nonce = [0_u8; 8];
            input_f.read_exact(&mut nonce)?;
            let nonce = u64::from_be_bytes(nonce);
            let mut key = [0; 32];
            for (i, k) in args.key.as_bytes().iter().enumerate() {
                key[i] = *k;
            }
            let mut cipher = ascipher::encrypt::Cipher512::new(&key);
            cipher.nonce = nonce;
            let mut out_f = OpenOptions::new()
                .write(true)
                .create(true)
                .open(&args.output)?;
            loop {
                let mut buffer = [0; BUFFER_SIZE];
                let len = input_f.read(&mut buffer)?;
                if len == 0 {
                    break;
                }
                out_f.write_all(&cipher.apply_any(&buffer[..len]))?;
            }
        }
    }
    Ok(())
}
