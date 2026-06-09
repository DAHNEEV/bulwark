use eframe::egui;
use rfd::FileDialog;
use std::path::PathBuf;

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
    Process(String),
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
        }
    }
}

impl eframe::App for CryptoApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("mode_swicher").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Mode:");
                ui.selectable_value(&mut self.mode, Mode::Decrypt, "Decrypt");
                ui.selectable_value(&mut self.mode, Mode::Encrypt, "Encrypt")
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
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
                                    let args = crypto::EncryptArgs {
                                        input_paths: input_paths.clone(),
                                        output_path: output_path.clone(),
                                        password: self.password.clone(),
                                    };
                                    self.status = State::Process("Encrypting...".to_string());

                                    match crypto::encrypt(args) {
                                        Ok(()) => self.status = State::Success,
                                        Err(e) => self.status = State::Error(e.to_string()),
                                    }
                                }
                                Mode::Decrypt => {
                                    if let Some(first_input_path) = input_paths.first(){
                                        let args = crypto::DecryptArgs {
                                        input_path: first_input_path.clone(),
                                        output_path: output_path.clone(),
                                        password: self.password.clone(),
                                        };
                                        

                                        match crypto::decrypt(args) {
                                            Ok(()) => self.status = State::Success,
                                            Err(e) => self.status = State::Error(e.to_string()),
                                        }
                                    } else{
                                        self.status = State::Error("No input file selected".to_string())
                                    }


                                }
                            }
                        }
                    }
                }

                match &self.status {
                    State::Idle => {
                        ui.label("Waiting...");
                    }
                    State::Success => {
                        ui.colored_label(egui::Color32::GREEN, "Success!");
                    }
                    State::Error(e) => {
                        ui.colored_label(egui::Color32::RED, format!("Error: {}", e));
                    }
                    State::Process(mes) => {
                        ui.label(mes);
                    }
                }
            });
        });
    }
}
