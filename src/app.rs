use eframe::egui;
use rfd::FileDialog;
use std::path::PathBuf;
use crate::crypto;

#[derive(Default, PartialEq, Debug)]
enum Mode{
    #[default]
    Encrypt,
    Decrypt,
}
#[derive(Default)]
enum State{
    Success,
    Error(String),
    #[default]
    Idle,
}

pub struct CryptoApp {
    mode: Mode,
    password: String,
    src_filepath: Option<PathBuf>,
    dist_filepath: Option<PathBuf>,
    status: State,
    hide_password: bool,
}

impl Default for CryptoApp{
    fn default() -> Self {
        Self { mode: (Mode::default()), password: (String::new()), src_filepath: (None), dist_filepath: (None), status: (State::default()), hide_password: true }
    }
}

impl eframe::App for CryptoApp{
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame){
        egui::TopBottomPanel::top("mode_swicher").show(ctx, |ui|{
            ui.horizontal(|ui|{
                ui.label("Mode:");
                ui.selectable_value(&mut self.mode, Mode::Decrypt, "Decrypt");
                ui.selectable_value(&mut self.mode, Mode::Encrypt, "Encrypt")
            });
        });
        egui::CentralPanel::default().show(ctx, |ui|{
            ui.separator();
            ui.vertical(|ui|{
                ui.horizontal(|ui|{
                    //Password
                    ui.label("Password:");
                    ui.add(egui::TextEdit::singleline(&mut self.password).password(self.hide_password));
                    ui.checkbox(&mut self.hide_password, String::new());
                    ui.separator();
                });
                ui.horizontal(|ui|{
                    //Src File
                    if ui.button("Load source file").clicked(){
                        let path = FileDialog::new().pick_file();
                        if let Some(path) = path{
                            self.src_filepath = Some(path);
                        }
                    }
                    if let Some(path) = &self.src_filepath {
                        ui.label(path.to_string_lossy());
                    } else {
                        ui.label("No path selected");
                    }
                });
                ui.horizontal(|ui|{
                    //Dist File
                    if ui.button("Load dist file").clicked(){
                        let path = FileDialog::new().pick_file();
                        if let Some(path) = path{
                            self.dist_filepath = Some(path)
                        }
                    }
                    if ui.button("Create new dist file").clicked() {
                        if let Some(path) = FileDialog::new().save_file() {
                            self.dist_filepath = Some(path);
                        }
                    }
                    if let Some(path) = &self.dist_filepath {
                        ui.label(path.to_string_lossy());
                    } else {
                        ui.label("No path selected");
                    }
                });

                let button_text = if self.mode == Mode::Decrypt{"Decrypt file"} else {"Encrypt file"};
                if ui.button(button_text).clicked(){
                    if let (Some(source_file_path), Some(dist_file_path)) = (&self.src_filepath, &self.dist_filepath) {
                        let src_str = source_file_path.to_string_lossy().into_owned();
                        let dist_str = dist_file_path.to_string_lossy().into_owned();
                        if !self.password.is_empty(){
                             match self.mode {
                                Mode::Decrypt => {
                                    match crypto::decrypt_file(src_str, dist_str, self.password.clone()){
                                        Ok(()) => {self.status = State::Success}
                                        Err(e) => {self.status = State::Error(e.to_string())}
                                    }
                                }
                                Mode::Encrypt => {
                                    match crypto::encrypt_file(src_str, dist_str, self.password.clone()){
                                        Ok(()) => {self.status = State::Success}
                                        Err(e) => {self.status = State::Error(e.to_string())}
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
                }
            });
        });
    }
}