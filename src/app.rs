use eframe::egui;
use rfd::FileDialog;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::Instant;

use crate::crypto;

#[derive(Default, PartialEq, Debug)]
enum Mode {
    #[default]
    Encrypt,
    Decrypt,
}
#[derive(Default)]
enum State {
    Success,
    Error(String),
    Processing,
    #[default]
    Idle,
}

pub struct CryptoApp {
    mode: Mode,
    password: String,
    input_paths: Option<Vec<PathBuf>>,
    output_path: Option<PathBuf>,
    status: State,
    hide_password: bool,
    rx: Option<Receiver<Result<(), String>>>,
    status_changed_at: Option<Instant>,
    algorithm: String,
    compresion: bool,
    compresion_level: i32,
}

impl Default for CryptoApp {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            password: String::new(),
            input_paths: None,
            output_path: None,
            status: State::default(),
            hide_password: true,
            rx: None,
            status_changed_at: None,
            algorithm: "AES".to_string(),
            compresion: true,
            compresion_level: 3,
        }
    }
}

impl eframe::App for CryptoApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.rx {
            if let Ok(result) = rx.try_recv() { 
                match result {
                    Ok(()) => {
                        self.status = State::Success;
                        self.password.clear();      
                        self.input_paths = None;  
                        self.output_path = None;
                    }
                    Err(e) => self.status = State::Error(e),
                }
                self.rx = None; 
                self.status_changed_at = Some(Instant::now());
            } else if let State::Processing = self.status {
                ctx.request_repaint(); 
            }
        }
        if let Some(changed_at) = self.status_changed_at {
            if changed_at.elapsed().as_secs() >= 3 {
                self.status = State::Idle;
                self.status_changed_at = None;
            } else {
                ctx.request_repaint();
            }
        }
            
        egui::TopBottomPanel::top("mode_swicher").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Mode:");
                ui.selectable_value(&mut self.mode, Mode::Decrypt, "Decrypt");
                ui.selectable_value(&mut self.mode, Mode::Encrypt, "Encrypt")
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            let is_idle = matches!(self.status, State::Idle | State::Success | State::Error(_));
            ui.add_enabled_ui(is_idle, |ui| {
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        //Password
                        ui.label("Password:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.password).password(self.hide_password),
                        );
                        ui.checkbox(&mut self.hide_password, String::new());
                    });
                    ui.horizontal(|ui| {
                        ui.label("Algorithm:");
                        ui.selectable_value(&mut self.algorithm, "AES".to_string(), "AES-256 (GCM)");
                        ui.selectable_value(&mut self.algorithm, "ChaCha".to_string(), "ChaCha20-Poly1305");
                    });
                    ui.checkbox(&mut self.compresion, "Enable compression");
                    ui.add_enabled_ui(self.compresion, |ui|{
                        ui.horizontal(|ui|{
                            ui.label("Compression level:");
                            ui.add(egui::Slider::new(&mut self.compresion_level, 1..=12).text("level"));
                        })
                    });
                    ui.horizontal(|ui| {
                        //Src File
                        if ui.button("Load source file").clicked() {
                            if self.mode == Mode::Encrypt{
                                let paths = FileDialog::new().pick_files();
                                if let Some(paths) = paths {
                                    self.input_paths = Some(paths);
                                }
                            } else {
                                let path = FileDialog::new().pick_file();
                                if let Some(path) = path {
                                    self.input_paths = Some(vec![path]);
                                }
                            }
                            
                        }
                        if let Some(paths) = &self.input_paths {
                            ui.label(
                                paths
                                    .iter()
                                    .map(|path| path.to_string_lossy())
                                    .collect::<Vec<_>>()
                                    .join(";"),
                            );
                        } else {
                            ui.label("No path selected");
                        }
                    });
                    ui.horizontal(|ui| {
                        //Dist File
                        if ui.button("Create new dist file").clicked() {
                            if let Some(path) = FileDialog::new().save_file() {
                                self.output_path = Some(path);
                            }
                        }
                        if let Some(path) = &self.output_path {
                            ui.label(path.to_string_lossy());
                        } else {
                            ui.label("No path selected");
                        }
                    });

                    let button_text = if self.mode == Mode::Decrypt {
                        "Decrypt file"
                    } else {
                        "Encrypt file"
                    };
                    if ui.button(button_text).clicked() {
                        if let (Some(input_paths), Some(output_path)) =
                            (&self.input_paths, &self.output_path)
                        {
                            if !self.password.is_empty() {
                                match self.mode {
                                    Mode::Encrypt => {
                                        self.status = State::Processing;
                                        let (tx, rx) = std::sync::mpsc::channel();
                                        self.rx = Some(rx);

                                        let args = crypto::EncryptArgs {
                                            input_paths: input_paths.clone(),
                                            output_path: output_path.clone(),
                                            password: self.password.clone(),
                                        };

                                        std::thread::spawn(move || {
                                            let result = crypto::encrypt(args).map_err(|e| e.to_string());
                                            let _ = tx.send(result);
                                        });
                                    }
                                    Mode::Decrypt => {
                                        if let Some(first_input_path) = input_paths.first() {
                                            self.status = State::Processing;

                                            let (tx, rx) = std::sync::mpsc::channel();
                                            self.rx = Some(rx);

                                            let args = crypto::DecryptArgs {
                                                input_path: first_input_path.clone(),
                                                output_path: output_path.clone(),
                                                password: self.password.clone(),
                                            };

                                            std::thread::spawn(move || {
                                                let result = crypto::decrypt(args).map_err(|e| e.to_string());
                                                let _ = tx.send(result);
                                            });

                                        } else {
                                            self.status = State::Error("No input file selected".to_string())
                                        }
                                    }
                                }
                            }
                        }
                    }
                });

                match &self.status {
                    State::Idle => {
                        ui.label("Waiting for user...");
                    }
                    State::Success => {
                        ui.colored_label(egui::Color32::GREEN, "Success!");
                    }
                    State::Error(e) => {
                        ui.colored_label(egui::Color32::RED, format!("Error: {}", e));
                    }
                    State::Processing => {
                        ui.horizontal(|ui| {
                            ui.spinner(); 
                            ui.label("Processing file(s)... Please wait.");
                        }); 
                    }
                }
            });
        });
    }
}
