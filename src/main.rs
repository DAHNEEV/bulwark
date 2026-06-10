use app::CryptoApp;
use clap::{Args, Parser, Subcommand};
use std::{path::PathBuf, time::Instant};

use crate::crypto::Algorithm;

mod app;
mod crypto;

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
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

    #[arg(short, long, value_parser = parse_algorithm)]
    algorithm: Algorithm,

    #[arg(short, long)]
    compression_level: Option<i32>,
}

#[derive(Args)]
struct CliDecryptArgs {
    #[arg(short, long)]
    password: String,

    #[arg(short, long)]
    input_path: PathBuf,

    #[arg(short, long)]
    output_path: PathBuf,

    #[arg(short, long, value_parser = parse_algorithm)]
    algorithm: Algorithm,
}

fn parse_algorithm(s: &str) -> Result<Algorithm, String> {
    match s.to_lowercase().as_str() {
        "aes" => Ok(Algorithm::Aes256Gcm),
        "cha" => Ok(Algorithm::XChaCha20Poly1305),
        _ => Err("Please choose \"cha\" (XChaCha20-Poly1305) or \"aes\" (AES-256-GCM)".to_string()),
    }
}

fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Encrypt(args)) => {
            let options = crypto::EncryptArgs {
                input_paths: args.input_paths,
                output_path: args.output_path,
                password: args.password,
                algorithm: args.algorithm,
                compression: args.compression_level.is_some(),
                compression_level: args.compression_level.unwrap_or(0),
            };
            let t0 = Instant::now();
            crypto::encrypt(options).unwrap();
            println!("Time: {:?}", t0.elapsed());
        }
        Some(Commands::Decrypt(args)) => {
            let options = crypto::DecryptArgs {
                input_path: args.input_path,
                output_path: args.output_path,
                password: args.password,
                algorithm: args.algorithm,
            };
            let t0 = Instant::now();
            crypto::decrypt(options).unwrap();
            println!("Time: {:?}", t0.elapsed());
        }
        None => {
            let options = eframe::NativeOptions::default();
            eframe::run_native(
                "Crypto App",
                options,
                Box::new(|cc| {
                    catppuccin_egui::set_theme(&cc.egui_ctx, catppuccin_egui::MACCHIATO);
                    Box::new(CryptoApp::default())
                }),
            )
            .unwrap()
        }
    }
    Ok(())
}
