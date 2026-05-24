use std::{path::PathBuf, time::Instant};

use clap::{Args, Parser, Subcommand};

mod crypto;

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt(CliEncryptArgs),
    Decrypt(CliDecryptArgs),
}

#[derive(Args)]
struct CliEncryptArgs {
    #[arg(short, long)]
    password: String,

    #[arg(short, long, required = true, num_args = 1..)]
    input_paths: Vec<PathBuf>,

    #[arg(short, long)]
    output_path: PathBuf,
}

#[derive(Args)]
struct CliDecryptArgs {
    #[arg(short, long)]
    password: String,

    #[arg(short, long)]
    input_path: PathBuf,

    #[arg(short, long)]
    output_path: PathBuf,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt(args) => {
            let options = crypto::EncryptArgs {
                input_paths: args.input_paths,
                output_path: args.output_path,
                password: args.password,
            };
            let t0 = Instant::now();
            crypto::encrypt(options).unwrap();
            println!("Time: {:?}", t0.elapsed());
        }
        Commands::Decrypt(args) => {
            let options = crypto::DecryptArgs {
                input_path: args.input_path,
                output_path: args.output_path,
                password: args.password,
            };
            let t0 = Instant::now();
            crypto::decrypt(options).unwrap();
            println!("Time: {:?}", t0.elapsed());
        }
    }
}
