mod crypto;
mod app;
use app::CryptoApp;



use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Encrypt {
        password: String,
        source_file_path: String,
        dist_file_path: String,
    },
    Decrypt {
        password: String,
        encrypted_file_path: String,
        dist_file_path: String,
    },
}


fn main() -> Result<(), eframe::Error> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Encrypt {
            password,
            source_file_path,
            dist_file_path,
        }) => {
            crypto::encrypt_file(source_file_path, dist_file_path, password).unwrap();
            Ok(())}
        Some(Commands::Decrypt {
            password,
            encrypted_file_path,
            dist_file_path,
        }) => {
            crypto::decrypt_file(encrypted_file_path, dist_file_path, password).unwrap();
            Ok(())}
        None => {
            let options = eframe::NativeOptions::default();
            eframe::run_native(
            "Crypto App",
            options,
            Box::new(|cc|{
                    catppuccin_egui::set_theme(&cc.egui_ctx, catppuccin_egui::MACCHIATO);
                    Box::new(CryptoApp::default())
                }),
            )
        }
    }
}
