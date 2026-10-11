use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use image::GenericImageView;
use eframe::egui::{self, Align, Color32, Layout, RichText, Stroke, TextEdit, Ui, Vec2};
use rand::{Rng, RngCore, distributions::Uniform, seq::SliceRandom};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::{
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const FORMAT_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const DEFAULT_LENGTH: usize = 20;
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}:,.?";
const PASS_PHRASE_WORDS: &[&str] = &[
    "abandon", "ability", "absent", "abyss", "acorn", "admiral", "adobe", "afloat", "agate",
    "agent", "albatross", "alley", "amber", "ancient", "apex", "apricot", "archer", "argon",
    "arrow", "atlas", "autumn", "avalanche", "azure", "bamboo", "basil", "beacon", "beetle",
    "beryl", "birch", "blossom", "bramble", "breeze", "bridge", "brook", "brutal", "cabin",
    "canyon", "carlton", "cedar", "chamber", "charcoal", "cherry", "cinder", "cobalt", "comet",
    "coral", "copper", "cosmic", "cove", "crimson", "crow", "dahlia", "dawn", "decoy", "delta",
    "diamond", "dune", "ember", "enigma", "everest", "falcon", "fable", "feather", "fern",
    "field", "finch", "firefly", "flint", "flora", "forest", "fossil", "foxglove", "froth",
    "garden", "gemstone", "glacier", "glimmer", "golden", "grape", "harbor", "harvest", "haven",
    "hazel", "heather", "honey", "horizon", "iceberg", "island", "ivory", "jasmine", "juniper",
    "keystone", "kiwi", "lagoon", "lark", "lattice", "lemur", "lilac", "linden", "marble",
    "meadow", "meteor", "midnight", "mint", "mirth", "moss", "mountain", "native", "nebula",
    "nectar", "nimbus", "oak", "opal", "orbit", "orchid", "outpost", "parade", "pebble",
    "pedal", "pine", "pioneer", "plume", "quartz", "quiet", "raven", "reef", "ribbon",
    "river", "robin", "rose", "saffron", "sailor", "sandal", "scout", "shadow", "silken",
    "silver", "siren", "smoke", "solar", "spruce", "storm", "summit", "sunrise", "sylvan",
    "tangent", "thorn", "thunder", "tide", "timber", "tundra", "valley", "velvet", "violet",
    "wander", "willow", "wind", "winter", "wisdom", "zephyr", "zenith", "zodiac",
    "acacia", "bison", "cinder", "drift", "echo", "emberglow", "evergreen", "garnet", "hemlock",
    "jungle", "lighthouse", "lotus", "magnet", "petal", "sage", "sequoia", "solstice", "teak",
    "twilight", "whistle", "wren", "yonder",
];
const SPLASH_DURATION: Duration = Duration::from_millis(1400);
const MAX_ENTRY_IMAGE_DIMENSION: u32 = 600;
const MAX_IMAGE_INPUT_BYTES: u64 = 20 * 1024 * 1024;
const MAX_IMAGE_DECODE_DIMENSION: u32 = 16_384;
const MAX_IMAGE_DECODE_ALLOCATION: u64 = 256 * 1024 * 1024;
const MAX_VAULT_FILE_BYTES: u64 = 128 * 1024 * 1024;
#[cfg(test)]
static HOME_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn main() -> eframe::Result<()> {
    eframe::run_native(
        "Passbee",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1100.0, 720.0])
                .with_min_inner_size([820.0, 560.0])
                .with_icon(
                    eframe::icon_data::from_png_bytes(include_bytes!("../assets/passbee-mark.png"))
                    .unwrap_or_default(),
                ),
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(PassbeeApp::new(cc)))),
    )
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u8,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct VaultData {
    entries: Vec<Entry>,
}

#[derive(Clone, Serialize, Deserialize, Default, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
struct SensitiveField {
    label: String,
    value: String,
    hidden: bool,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Entry {
    name: String,
    username: String,
    password: String,
    image_data: Option<String>,
    #[serde(default)]
    custom_fields: Vec<SensitiveField>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Preferences {
    accent: Accent,
    theme: Theme,
    font_scale: f32,
    show_splash: bool,
    default_password_length: usize,
    default_generator_mode: GeneratorMode,
    default_passphrase_word_count: usize,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
enum Theme {
    Light,
    Dark,
}

impl Default for Theme {
    fn default() -> Self {
        Self::Light
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
enum Accent {
    Honey,
    Apricot,
    Gold,
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
enum GeneratorMode {
    Password,
    Passphrase,
}

impl Default for GeneratorMode {
    fn default() -> Self {
        Self::Password
    }
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            accent: Accent::Honey,
            theme: Theme::Light,
            font_scale: 1.0,
            show_splash: true,
            default_password_length: DEFAULT_LENGTH,
            default_generator_mode: GeneratorMode::Password,
            default_passphrase_word_count: 8,
        }
    }
}

#[derive(PartialEq, Eq)]
enum View {
    Splash,
    Unlock,
    Create,
    Vault,
}

struct PassbeeApp {
    path: PathBuf,
    preferences_path: PathBuf,
    preferences: Preferences,
    interface_scale_draft: f32,
    brand_logo: Option<egui::TextureHandle>,
    splash_started: Instant,
    view: View,
    vault: VaultData,
    master: String,
    confirmation: String,
    search: String,
    selected: Option<usize>,
    reveal: bool,
    editor_open: bool,
    generator_open: bool,
    entry_name: String,
    entry_username: String,
    entry_password: String,
    generator_length: usize,
    generator_sets: [bool; 4],
    generator_mode: GeneratorMode,
    passphrase_word_count: usize,
    entry_image_data: Option<String>,
    entry_custom_fields: Vec<SensitiveField>,
    custom_field_label: String,
    custom_field_value: String,
    username: String,
    users: Vec<String>,
    generated: String,
    status: Option<String>,
    error: Option<String>,
    new_vault_confirm: bool,
    delete_user_confirm: bool,
    delete_user_password: String,
    settings_open: bool,
}

impl Drop for PassbeeApp {
    fn drop(&mut self) {
        self.vault.zeroize();
        self.master.zeroize();
        self.confirmation.zeroize();
        self.delete_user_password.zeroize();
        self.entry_name.zeroize();
        self.entry_username.zeroize();
        self.entry_password.zeroize();
        self.entry_image_data.zeroize();
        self.entry_custom_fields.zeroize();
        self.custom_field_label.zeroize();
        self.custom_field_value.zeroize();
        self.generated.zeroize();
    }
}

impl PassbeeApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let preferences_path = preferences_path();
        let preferences = load_preferences(&preferences_path);
        let interface_scale_draft = preferences.font_scale;
        let mut style = (*cc.egui_ctx.style()).clone();
        style.spacing.item_spacing = Vec2::new(10.0, 10.0);
        style.spacing.button_padding = Vec2::new(12.0, 8.0);
        if preferences.theme == Theme::Dark {
            style.visuals = egui::Visuals::dark();
            style.visuals.panel_fill = Color32::from_rgb(18, 22, 28);
            style.visuals.window_fill = Color32::from_rgb(24, 29, 36);
            style.visuals.extreme_bg_color = Color32::from_rgb(30, 36, 45);
            style.visuals.selection.bg_fill = accent_tint(preferences.accent);
            style.visuals.selection.stroke = Stroke::new(1.0_f32, accent_primary(preferences.accent));
            style.visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(39, 47, 58);
            style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(32, 39, 49);
            style.visuals.widgets.inactive.bg_stroke =
                Stroke::new(1.0_f32, Color32::from_rgb(55, 65, 80));
            style.visuals.widgets.hovered.bg_fill = accent_tint(preferences.accent);
            style.visuals.widgets.hovered.bg_stroke =
                Stroke::new(1.0_f32, accent_primary(preferences.accent));
            style.visuals.widgets.active.bg_fill = accent_active(preferences.accent);
            style.visuals.widgets.active.bg_stroke =
                Stroke::new(1.0_f32, accent_primary(preferences.accent));
        } else {
            style.visuals = egui::Visuals::light();
            style.visuals.panel_fill = Color32::from_rgb(245, 247, 249);
            style.visuals.window_fill = Color32::from_rgb(250, 251, 252);
            style.visuals.extreme_bg_color = Color32::from_rgb(233, 237, 240);
            style.visuals.selection.bg_fill = accent_tint(preferences.accent);
            style.visuals.selection.stroke = Stroke::new(1.0_f32, accent_primary(preferences.accent));
            style.visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(246, 248, 250);
            style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(236, 240, 243);
            style.visuals.widgets.inactive.bg_stroke =
                Stroke::new(1.0_f32, Color32::from_rgb(216, 221, 226));
            style.visuals.widgets.hovered.bg_fill = accent_tint(preferences.accent);
            style.visuals.widgets.hovered.bg_stroke =
                Stroke::new(1.0_f32, accent_primary(preferences.accent));
            style.visuals.widgets.active.bg_fill = accent_active(preferences.accent);
            style.visuals.widgets.active.bg_stroke =
                Stroke::new(1.0_f32, accent_primary(preferences.accent));
        }
        cc.egui_ctx.set_style(style);
        cc.egui_ctx.set_pixels_per_point(preferences.font_scale);
        let brand_logo = image::load_from_memory(include_bytes!("../assets/passbee-mark.png"))
            .ok()
            .map(|image| {
                let image = image.to_rgba8();
                let color_image = egui::ColorImage::from_rgba_unmultiplied(
                    [image.width() as usize, image.height() as usize],
                    image.as_raw(),
                );
                cc.egui_ctx.load_texture(
                    "passbee-brand-logo",
                    color_image,
                    egui::TextureOptions::LINEAR,
                )
            });

        let users = list_user_profiles();
        let username = String::new();
        let path = default_vault_path();

        let default_generator_mode = preferences.default_generator_mode;
        let default_passphrase_word_count = preferences.default_passphrase_word_count;
        let initial_view = if preferences.show_splash {
            View::Splash
        } else if users.is_empty() {
            if path.exists() { View::Unlock } else { View::Create }
        } else {
            View::Unlock
        };

        Self {
            view: initial_view,
            path,
            preferences_path,
            preferences,
            interface_scale_draft,
            brand_logo,
            splash_started: Instant::now(),
            vault: VaultData::default(),
            master: String::new(),
            confirmation: String::new(),
            search: String::new(),
            selected: None,
            reveal: false,
            editor_open: false,
            generator_open: false,
            entry_name: String::new(),
            entry_username: String::new(),
            entry_password: String::new(),
            generator_length: DEFAULT_LENGTH,
            generator_sets: [true; 4],
            generator_mode: default_generator_mode,
            passphrase_word_count: default_passphrase_word_count,
            entry_image_data: None,
            entry_custom_fields: Vec::new(),
            custom_field_label: String::new(),
            custom_field_value: String::new(),
            username,
            users,
            generated: String::new(),
            status: None,
            error: None,
            new_vault_confirm: false,
            delete_user_confirm: false,
            delete_user_password: String::new(),
            settings_open: false,
        }
    }

    fn finish_splash(&mut self) {
        self.view = splash_destination(!self.users.is_empty(), self.path.exists());
    }

    fn save_preferences(&mut self) {
        if let Some(parent) = self.preferences_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(data) = serde_json::to_vec_pretty(&self.preferences) {
            let _ = fs::write(&self.preferences_path, data);
        }
    }

    fn apply_preferences(&self, ctx: &egui::Context) {
        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = Vec2::new(10.0, 10.0);
        style.spacing.button_padding = Vec2::new(12.0, 8.0);
        if self.preferences.theme == Theme::Dark {
            style.visuals = egui::Visuals::dark();
            style.visuals.panel_fill = Color32::from_rgb(18, 22, 28);
            style.visuals.window_fill = Color32::from_rgb(24, 29, 36);
            style.visuals.extreme_bg_color = Color32::from_rgb(30, 36, 45);
            style.visuals.selection.bg_fill = accent_tint(self.preferences.accent);
            style.visuals.selection.stroke = Stroke::new(1.0_f32, accent_primary(self.preferences.accent));
            style.visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(39, 47, 58);
            style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(32, 39, 49);
            style.visuals.widgets.inactive.bg_stroke =
                Stroke::new(1.0_f32, Color32::from_rgb(55, 65, 80));
            style.visuals.widgets.hovered.bg_fill = accent_tint(self.preferences.accent);
            style.visuals.widgets.hovered.bg_stroke =
                Stroke::new(1.0_f32, accent_primary(self.preferences.accent));
            style.visuals.widgets.active.bg_fill = accent_active(self.preferences.accent);
            style.visuals.widgets.active.bg_stroke =
                Stroke::new(1.0_f32, accent_primary(self.preferences.accent));
        } else {
            style.visuals = egui::Visuals::light();
            style.visuals.panel_fill = Color32::from_rgb(245, 247, 249);
            style.visuals.window_fill = Color32::from_rgb(250, 251, 252);
            style.visuals.extreme_bg_color = Color32::from_rgb(233, 237, 240);
            style.visuals.selection.bg_fill = accent_tint(self.preferences.accent);
            style.visuals.selection.stroke = Stroke::new(1.0_f32, accent_primary(self.preferences.accent));
            style.visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(246, 248, 250);
            style.visuals.widgets.inactive.bg_fill = Color32::from_rgb(236, 240, 243);
            style.visuals.widgets.inactive.bg_stroke =
                Stroke::new(1.0_f32, Color32::from_rgb(216, 221, 226));
            style.visuals.widgets.hovered.bg_fill = accent_tint(self.preferences.accent);
            style.visuals.widgets.hovered.bg_stroke =
                Stroke::new(1.0_f32, accent_primary(self.preferences.accent));
            style.visuals.widgets.active.bg_fill = accent_active(self.preferences.accent);
            style.visuals.widgets.active.bg_stroke =
                Stroke::new(1.0_f32, accent_primary(self.preferences.accent));
        }
        ctx.set_style(style);
        ctx.set_pixels_per_point(self.preferences.font_scale);
        ctx.request_repaint();
    }

    fn accent(&self) -> Color32 {
        accent_primary(self.preferences.accent)
    }

    fn lifecycle_windows(&mut self, ctx: &egui::Context) {
        if self.new_vault_confirm {
            let mut open = self.new_vault_confirm;
            egui::Window::new("Create new vault?")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("This will permanently replace the current encrypted vault.");
                    ui.label("Make sure you have a backup before continuing.");
                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.new_vault_confirm = false;
                        }
                        if ui
                            .add(egui::Button::new("Replace vault").fill(self.accent()))
                            .clicked()
                        {
                            self.replace_with_new_vault();
                        }
                    });
                });
            self.new_vault_confirm = open && self.new_vault_confirm;
        }
        if self.delete_user_confirm {
            let mut open = self.delete_user_confirm;
            egui::Window::new("Delete user?")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("This removes the entire user profile and its vault.");
                    ui.label("This action cannot be undone.");
                    ui.add_space(10.0);
                    ui.label("Enter the master password to confirm:");
                    ui.add(
                        TextEdit::singleline(&mut self.delete_user_password)
                            .password(true)
                            .desired_width(ui.available_width()),
                    );
                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.delete_user_confirm = false;
                            self.delete_user_password.zeroize();
                        }
                        if ui
                            .add(
                                egui::Button::new("Delete user")
                                    .fill(Color32::from_rgb(177, 65, 57)),
                            )
                            .clicked()
                        {
                            self.delete_user();
                        }
                    });
                });
            self.delete_user_confirm = open && self.delete_user_confirm;
            if !self.delete_user_confirm {
                self.delete_user_password.zeroize();
            }
        }
        if self.settings_open {
            self.settings_window(ctx);
        }
    }

    fn splash_view(&mut self, ctx: &egui::Context) {
        if self.splash_started.elapsed() >= SPLASH_DURATION {
            self.finish_splash();
            return;
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(if self.preferences.theme == Theme::Dark {
                Color32::from_rgb(18, 22, 28)
            } else {
                Color32::from_rgb(242, 245, 246)
            }))
            .show(ctx, |ui| {
            let available = ui.available_size();
            ui.allocate_ui_with_layout(
                available,
                Layout::centered_and_justified(egui::Direction::TopDown),
                |ui| {
                    if let Some(logo) = &self.brand_logo {
                        ui.add(
                            egui::Image::new(logo)
                                .fit_to_exact_size(Vec2::splat(144.0))
                                .maintain_aspect_ratio(true),
                        );
                    } else {
                        bee_symbol(ui, 112.0, self.accent());
                    }
                    ui.add_space(18.0);
                    ui.label(RichText::new("PASSBEE").size(26.0).strong().color(self.accent()));
                    ui.add_space(6.0);
                    ui.label(RichText::new("A little more peace of mind.").color(if self.preferences.theme == Theme::Dark {
                        Color32::from_rgb(177, 187, 199)
                    } else {
                        Color32::from_rgb(105, 117, 125)
                    }));
                },
            );
        });
        if ctx.input(|input| input.pointer.any_click() || input.key_pressed(egui::Key::Escape)) {
            self.finish_splash();
        } else {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }

    fn clear_messages(&mut self) {
        self.status = None;
        self.error = None;
    }

    fn refresh_users(&mut self) {
        self.users = list_user_profiles();
        if !self.username.trim().is_empty() && !self.users.iter().any(|user| user == &self.username) {
            self.username.clear();
        }
    }

    fn active_path_for_username(&self, username: &str) -> PathBuf {
        if username.trim().is_empty() {
            default_vault_path()
        } else {
            user_vault_path(username)
        }
    }

    fn unlock(&mut self) {
        self.clear_messages();
        let username = self.username.trim();
        if username.is_empty() {
            self.error = Some("Enter your username to continue.".into());
            return;
        }
        match verified_user_vault_path(username, &self.users, &self.master) {
            Ok((path, vault)) => {
                self.path = path;
                self.vault = vault;
                self.selected = self.vault.entries.first().map(|_| 0);
                self.view = View::Vault;
            }
            Err(_) => self.error = Some("Wrong username or master password.".into()),
        }
    }

    fn create_vault(&mut self) {
        self.clear_messages();
        let username = self.username.trim().to_string();
        if username.is_empty() {
            self.error = Some("Pick a username before creating a vault.".into());
            return;
        }
        if !valid_profile_name(&username) {
            self.error = Some("Use a username without path separators or control characters.".into());
            return;
        }
        if self.master.len() < 12 {
            self.error = Some("Use at least 12 characters for the master password.".into());
            return;
        }
        if self.master != self.confirmation {
            self.error = Some("The master passwords do not match.".into());
            return;
        }
        if self.users.iter().any(|user| user == &username) {
            self.error = Some("That user already exists. Choose a different username.".into());
            return;
        }
        self.path = self.active_path_for_username(&username);
        match save_vault(&self.path, &VaultData::default(), &self.master) {
            Ok(()) => {
                self.confirmation.zeroize();
                self.username = username;
                self.refresh_users();
                self.view = View::Vault;
                self.status = Some("Your encrypted vault is ready.".into());
            }
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn lock(&mut self) {
        self.vault.zeroize();
        self.vault = VaultData::default();
        self.selected = None;
        self.master.zeroize();
        self.confirmation.zeroize();
        self.delete_user_password.zeroize();
        self.entry_name.zeroize();
        self.entry_username.zeroize();
        self.entry_password.zeroize();
        self.custom_field_label.zeroize();
        self.custom_field_value.zeroize();
        self.generated.zeroize();
        self.entry_custom_fields.zeroize();
        self.entry_image_data.zeroize();
        self.editor_open = false;
        self.generator_open = false;
        self.view = View::Unlock;
        self.path = self.active_path_for_username(self.username.trim());
        self.status = Some(format!("Vault locked for {}.", self.username.trim()));
    }

    fn save(&mut self) {
        match save_vault(&self.path, &self.vault, &self.master) {
            Ok(()) => self.status = Some("Vault saved.".into()),
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn start_new_vault(&mut self) {
        self.clear_messages();
        self.master.zeroize();
        self.confirmation.zeroize();
        self.username.clear();
        self.path = default_vault_path();
        self.new_vault_confirm = false;
        self.view = View::Create;
        self.status = Some("Create a new user and vault.".into());
    }

    fn replace_with_new_vault(&mut self) {
        self.clear_messages();
        match fs::remove_file(&self.path) {
            Ok(()) => {
                self.vault = VaultData::default();
                self.vault.zeroize();
                self.master.zeroize();
                self.confirmation.zeroize();
                self.selected = None;
                self.new_vault_confirm = false;
                self.username = self.username.trim().to_string();
                self.path = self.active_path_for_username(&self.username);
                self.view = View::Create;
            }
            Err(error) => self.error = Some(format!("Could not replace vault: {error}")),
        }
    }

    fn delete_user(&mut self) {
        self.clear_messages();
        let username = self.username.trim().to_string();
        if username.is_empty() {
            self.error = Some("Enter the username of the profile to delete.".into());
            return;
        }

        let path = match verified_user_vault_path(
            &username,
            &self.users,
            &self.delete_user_password,
        ) {
            Ok((path, _vault)) => path,
            Err(_) => {
                self.error = Some("Wrong username or master password.".into());
                return;
            }
        };
        let delete_result = if path == default_vault_path() {
            fs::remove_file(&path).map_err(Into::into)
        } else {
            delete_user_profile(&username)
        };
        match delete_result {
            Ok(()) => {
                self.vault.zeroize();
                self.vault = VaultData::default();
                self.master.zeroize();
                self.confirmation.zeroize();
                self.selected = None;
                self.delete_user_confirm = false;
                self.delete_user_password.zeroize();
                self.users.retain(|user| user != &username);
                self.username.clear();
                self.path = default_vault_path();
                self.refresh_users();

                if !self.users.is_empty() {
                    self.view = View::Unlock;
                    self.status = Some(format!("User '{}' deleted. Enter a username to continue.", username));
                } else {
                    self.view = View::Create;
                    self.status = Some("User deleted. Create a new profile to continue.".into());
                }
            }
            Err(error) => self.error = Some(format!("Could not delete user: {error}")),
        }
    }

    fn auth_view(&mut self, ui: &mut Ui, create: bool) {
        ui.vertical_centered(|ui| {
            ui.add_space(32.0);
            if let Some(logo) = &self.brand_logo {
                ui.add(
                    egui::Image::new(logo)
                        .fit_to_exact_size(Vec2::splat(66.0))
                        .maintain_aspect_ratio(true),
                );
            } else {
                bee_symbol(ui, 58.0, self.accent());
            }
            ui.add_space(8.0);
            ui.label(RichText::new("PASSBEE").small().strong().color(self.accent()));
            ui.add_space(14.0);
            ui.heading(RichText::new(if create { "Make yourself at home" } else { "Welcome back" }).size(28.0));
            ui.label(RichText::new(if create {
                "A fresh start for your private space."
            } else {
                "Your space is ready when you are."
            }).color(if self.preferences.theme == Theme::Dark {
                Color32::from_rgb(177, 187, 199)
            } else {
                Color32::from_rgb(105, 117, 125)
            }));
            ui.add_space(22.0);
            egui::Frame::new()
                .fill(if self.preferences.theme == Theme::Dark {
                    Color32::from_rgb(32, 39, 49)
                } else {
                    Color32::WHITE
                })
                .stroke(Stroke::new(
                    1.0_f32,
                    if self.preferences.theme == Theme::Dark {
                        Color32::from_rgb(56, 67, 82)
                    } else {
                        Color32::from_rgb(226, 229, 235)
                    },
                ))
                .corner_radius(12)
                .inner_margin(30.0)
                .show(ui, |ui| {
                    ui.set_width(360.0);
                    ui.label(RichText::new("User").strong());
                    ui.add_space(7.0);
                    let response = ui.add(
                        TextEdit::singleline(&mut self.username)
                            .hint_text("Username")
                            .desired_width(ui.available_width()),
                    );
                    if create && response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.create_vault();
                    }
                    ui.add_space(14.0);
                    ui.label(
                        RichText::new(if create {
                            "Master password"
                        } else {
                            "Enter master password"
                        })
                        .strong(),
                    );
                    ui.add_space(7.0);
                    let response = ui.add(
                        TextEdit::singleline(&mut self.master)
                            .password(true)
                            .desired_width(ui.available_width()),
                    );
                    if !create && response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.unlock();
                    }
                    if create {
                        ui.add_space(14.0);
                        ui.label(RichText::new("Confirm password").strong());
                        ui.add_space(7.0);
                        ui.add(
                            TextEdit::singleline(&mut self.confirmation)
                                .password(true)
                                .desired_width(ui.available_width()),
                        );
                    }
                    ui.add_space(20.0);
                    if ui
                        .add_sized(
                            [ui.available_width(), 38.0],
                            egui::Button::new(if create {
                                "Create vault"
                            } else {
                                "Unlock vault"
                            })
                            .fill(self.accent()),
                        )
                        .clicked()
                    {
                        if create {
                            self.create_vault();
                        } else {
                            self.unlock();
                        }
                    }
                    if let Some(error) = &self.error {
                        ui.add_space(12.0);
                        ui.label(RichText::new(error).color(Color32::from_rgb(177, 65, 57)));
                    }
                });
            ui.add_space(20.0);
            ui.label(
                RichText::new(format!("Stored locally at {}", self.path.display()))
                    .small()
                    .color(Color32::from_rgb(145, 151, 161)),
            );
            if !create {
                ui.add_space(20.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Create user").clicked() {
                        self.start_new_vault();
                    }
                    if ui.button("Delete user").clicked() {
                        self.clear_messages();
                        self.delete_user_confirm = true;
                    }
                });
            }
            if let Some(status) = &self.status {
                ui.add_space(10.0);
                ui.label(RichText::new(status).color(self.accent()));
            }
        });
    }

    fn vault_view(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("topbar")
            .frame(
                egui::Frame::new()
                    .fill(if self.preferences.theme == Theme::Dark {
                        Color32::from_rgb(22, 27, 35)
                    } else {
                        Color32::WHITE
                    })
                    .inner_margin(egui::Margin::symmetric(24, 15)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if let Some(logo) = &self.brand_logo {
                        ui.add(
                            egui::Image::new(logo)
                                .fit_to_exact_size(Vec2::splat(25.0))
                                .maintain_aspect_ratio(true),
                        );
                    }
                    ui.label(RichText::new("PASSBEE").strong().color(self.accent()));
                    ui.separator();
                    ui.label(RichText::new("Vault").color(if self.preferences.theme == Theme::Dark {
                        Color32::from_rgb(162, 175, 191)
                    } else {
                        Color32::from_rgb(125, 132, 144)
                    }));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.button("Lock").on_hover_text("Lock this vault").clicked() {
                            self.lock();
                        }
                        if ui.button("Preferences").on_hover_text("Appearance and defaults").clicked() {
                            self.settings_open = true;
                        }
                        if ui.button("Generator").on_hover_text("Generate a password or passphrase").clicked() {
                            self.generated.zeroize();
                            self.generator_length = self.preferences.default_password_length;
                            self.generator_open = true;
                        }
                        if ui
                            .add(
                                egui::Button::new("+  New entry")
                                    .fill(self.accent())
                                    .stroke(Stroke::NONE),
                            )
                            .clicked()
                        {
                            self.new_entry();
                        }
                    });
                });
            });
        egui::SidePanel::left("entries")
            .resizable(false)
            .default_width(300.0)
            .width_range(300.0..=300.0)
            .frame(
                egui::Frame::new()
                    .fill(if self.preferences.theme == Theme::Dark {
                        Color32::from_rgb(18, 22, 28)
                    } else {
                        Color32::from_rgb(247, 248, 250)
                    })
                    .inner_margin(20.0),
            )
            .show(ctx, |ui| {
                ui.label(
                    RichText::new("YOUR ENTRIES")
                        .small()
                        .strong()
                        .color(Color32::from_rgb(125, 132, 144)),
                );
                ui.add_space(10.0);
                ui.add(
                    TextEdit::singleline(&mut self.search)
                        .hint_text("Search entries")
                        .desired_width(ui.available_width()),
                );
                ui.add_space(14.0);
                let entries: Vec<(usize, String, String, Option<String>)> = self
                    .vault
                    .entries
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| {
                        let q = self.search.to_lowercase();
                        q.is_empty()
                            || e.name.to_lowercase().contains(&q)
                            || e.username.to_lowercase().contains(&q)
                    })
                    .map(|(i, e)| (i, e.name.clone(), e.username.clone(), e.image_data.clone()))
                    .collect();
                if entries.is_empty() {
                    ui.add_space(22.0);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("No entries yet").strong());
                        ui.label(
                            RichText::new("Create one to get started.")
                                .small()
                                .color(Color32::from_rgb(130, 137, 148)),
                        );
                    });
                }
                for (index, name, username, image_data) in entries {
                    let selected = self.selected == Some(index);
                    let row_width = ui.available_width();
                    let row = ui.allocate_ui_with_layout(
                        Vec2::new(row_width, 72.0),
                        Layout::left_to_right(Align::Center),
                        |ui| {
                            egui::Frame::new()
                                .fill(if selected {
                                    accent_tint(self.preferences.accent)
                                } else if self.preferences.theme == Theme::Dark {
                                    Color32::from_rgb(25, 31, 40)
                                } else {
                                    Color32::WHITE
                                })
                                .stroke(Stroke::new(
                                    1.0_f32,
                                    if selected {
                                        self.accent()
                                    } else if self.preferences.theme == Theme::Dark {
                                        Color32::from_rgb(55, 65, 80)
                                    } else {
                                        Color32::from_rgb(226, 229, 235)
                                    },
                                ))
                                .corner_radius(8)
                                .inner_margin(egui::Margin::symmetric(10, 8))
                                .show(ui, |ui| {
                                    ui.set_width(row_width - 20.0);
                                    ui.horizontal(|ui| {
                                        self.render_entry_image_preview(
                                            ui,
                                            image_data.as_deref(),
                                            &format!("entry-list-{index}"),
                                            48.0,
                                        );
                                        ui.add_space(10.0);
                                        ui.vertical(|ui| {
                                            let text_width = ui.available_width().max(1.0);
                                            ui.add_sized(
                                                [text_width, 20.0],
                                                egui::Label::new(
                                                    RichText::new(&name)
                                                        .strong()
                                                        .color(if self.preferences.theme == Theme::Dark {
                                                            Color32::from_rgb(230, 236, 244)
                                                        } else {
                                                            Color32::from_rgb(55, 61, 72)
                                                        }),
                                                )
                                                .truncate(),
                                            );
                                            ui.add_sized(
                                                [text_width, 18.0],
                                                egui::Label::new(
                                                    RichText::new(if username.is_empty() {
                                                        "No username"
                                                    } else {
                                                        &username
                                                    })
                                                    .small()
                                                    .color(if self.preferences.theme == Theme::Dark {
                                                        Color32::from_rgb(162, 175, 191)
                                                    } else {
                                                        Color32::from_rgb(125, 132, 144)
                                                    }),
                                                )
                                                .truncate(),
                                            );
                                        });
                                    });
                                });
                        },
                    );
                    let row = row.response.interact(egui::Sense::click()).clicked();
                    if row {
                        self.selected = Some(index);
                        self.reveal = false;
                    }
                    ui.add_space(3.0);
                }
            });
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(if self.preferences.theme == Theme::Dark {
                        Color32::from_rgb(16, 20, 26)
                    } else {
                        Color32::from_rgb(252, 252, 253)
                    })
                    .inner_margin(38.0),
            )
            .show(ctx, |ui| {
                if let Some(index) = self.selected {
                    if index < self.vault.entries.len() {
                        self.entry_view(ui, index);
                    }
                } else {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            RichText::new("Select an entry")
                                .size(18.0)
                                .color(Color32::from_rgb(130, 137, 148)),
                        );
                    });
                }
            });
        if self.editor_open {
            self.editor_window(ctx);
        }
        if self.generator_open {
            self.generator_window(ctx);
        }
    }

    fn entry_view(&mut self, ui: &mut Ui, index: usize) {
        let entry = self.vault.entries[index].clone();
        let mut deleted = false;
        ui.horizontal(|ui| {
            self.render_entry_image_preview(ui, entry.image_data.as_deref(), &format!("entry-view-{index}"), 72.0);
            ui.vertical(|ui| {
                ui.heading(&entry.name);
                ui.label(
                    RichText::new("SECURE ENTRY")
                        .small()
                        .strong()
                        .color(Color32::from_rgb(125, 132, 144)),
                );
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("Delete").clicked() {
                    self.selected = remove_entry(&mut self.vault.entries, index);
                    self.save();
                    deleted = true;
                }
                if ui.button("Edit").clicked() {
                    self.edit_entry(index);
                }
            });
        });
        if deleted {
            return;
        }
        ui.add_space(18.0);
        egui::Frame::new()
            .fill(if self.preferences.theme == Theme::Dark {
                Color32::from_rgb(25, 31, 40)
            } else {
                Color32::WHITE
            })
            .stroke(Stroke::new(
                1.0_f32,
                if self.preferences.theme == Theme::Dark {
                    Color32::from_rgb(56, 67, 82)
                } else {
                    Color32::from_rgb(226, 229, 235)
                },
            ))
            .corner_radius(10)
            .inner_margin(24.0)
            .show(ui, |ui| {
                self.field(ui, "Username", &entry.username, false);
                ui.separator();
                self.field(ui, "Password", &entry.password, !self.reveal);
            });

        if !self.vault.entries[index].custom_fields.is_empty() {
            ui.add_space(18.0);
            ui.label(
                RichText::new("SENSITIVE DETAILS")
                    .small()
                    .strong()
                    .color(Color32::from_rgb(125, 132, 144)),
            );
            let mut copied = None;
            for field_index in 0..self.vault.entries[index].custom_fields.len() {
                let field = &mut self.vault.entries[index].custom_fields[field_index];
                if let Some(value) = Self::render_sensitive_field(ui, field) {
                    copied = Some(value);
                }
            }
            if let Some(value) = copied {
                self.status = Some(value);
            }
        }

        if let Some(status) = &self.status {
            ui.add_space(18.0);
            ui.label(RichText::new(status).color(self.accent()));
        }
    }

    fn render_sensitive_field(ui: &mut Ui, field: &mut SensitiveField) -> Option<String> {
        let mut result = None;
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.allocate_ui_with_layout(
                Vec2::new(120.0, 30.0),
                Layout::left_to_right(Align::Center),
                |ui| {
                    ui.label(
                        RichText::new(&field.label)
                            .strong()
                            .color(if ui.ctx().style().visuals.dark_mode {
                                Color32::from_rgb(228, 234, 242)
                            } else {
                                Color32::from_rgb(55, 61, 72)
                            }),
                    );
                },
            );
            ui.label(
                RichText::new(if field.hidden {
                    "••••••••••••"
                } else {
                    &field.value
                })
                .monospace()
                .color(if ui.ctx().style().visuals.dark_mode {
                    Color32::from_rgb(230, 236, 244)
                } else {
                    Color32::from_rgb(55, 61, 72)
                }),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button(if field.hidden { "Show" } else { "Hide" }).clicked() {
                    field.hidden = !field.hidden;
                }
                if ui.button("Copy").clicked() {
                    ui.ctx().copy_text(field.value.clone());
                    result = Some(format!("{} copied to clipboard.", field.label));
                }
            });
        });
        result
    }

    fn field(&mut self, ui: &mut Ui, label: &str, value: &str, concealed: bool) {
        ui.horizontal(|ui| {
            ui.allocate_ui_with_layout(
                Vec2::new(100.0, 30.0),
                Layout::left_to_right(Align::Center),
                |ui| {
                    ui.label(RichText::new(label).color(Color32::from_rgb(125, 132, 144)));
                },
            );
            ui.label(
                RichText::new(if concealed {
                    "••••••••••••"
                } else {
                    value
                })
                .monospace()
                .color(if ui.ctx().style().visuals.dark_mode {
                    Color32::from_rgb(230, 236, 244)
                } else {
                    Color32::from_rgb(55, 61, 72)
                }),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if label == "Password"
                    && ui.button(if concealed { "Show" } else { "Hide" }).clicked()
                {
                    self.reveal = self.reveal == false;
                }
                if ui.button("Copy").clicked() {
                    ui.ctx().copy_text(value.to_string());
                    self.status = Some(format!("{} copied to clipboard.", label));
                }
            });
        });
    }

    fn new_entry(&mut self) {
        self.selected = None;
        self.entry_name.zeroize();
        self.entry_username.zeroize();
        self.entry_password.zeroize();
        self.entry_image_data = None;
        self.entry_custom_fields.zeroize();
        self.custom_field_label.zeroize();
        self.custom_field_value.zeroize();
        self.editor_open = true;
        self.clear_messages();
    }

    fn upload_entry_image(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("image", &["png", "jpg", "jpeg", "webp"])
            .pick_file()
        else {
            return;
        };

        let Ok(bytes) = read_bounded_file(&path, MAX_IMAGE_INPUT_BYTES) else {
            self.error = Some("Could not read the selected image.".into());
            return;
        };
        let Ok(dyn_img) = decode_entry_image(&bytes) else {
            self.error = Some("The selected file is not a valid image.".into());
            return;
        };
        let scaled = resize_image_to_fit(dyn_img, MAX_ENTRY_IMAGE_DIMENSION);
        let mut buffer = std::io::Cursor::new(Vec::new());
        let Ok(()) = scaled.write_to(&mut buffer, image::ImageFormat::Png) else {
            self.error = Some("The image could not be processed.".into());
            return;
        };
        self.entry_image_data = Some(format!(
            "data:image/png;base64,{}",
            BASE64.encode(buffer.into_inner())
        ));
        self.clear_messages();
    }

    fn render_entry_image_preview(
        &self,
        ui: &mut Ui,
        image_data: Option<&str>,
        key: &str,
        size: f32,
    ) {
        if let Some(data) = image_data.and_then(parse_data_uri) {
            if let Some(texture) = load_entry_texture(ui.ctx(), key, data) {
                ui.add_sized(
                    [size, size],
                    egui::Image::new(&texture)
                        .fit_to_exact_size(Vec2::splat(size))
                        .maintain_aspect_ratio(true),
                );
                return;
            }
        }

        let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 10.0, self.accent());
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            "\u{1F9F8}",
            egui::FontId::new(size * 0.42, egui::FontFamily::Proportional),
            Color32::WHITE,
        );
    }

    fn settings_window(&mut self, ctx: &egui::Context) {
        let mut open = self.settings_open;
        egui::Window::new("Preferences")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(410.0)
            .show(ctx, |ui| {
                ui.label(RichText::new("Appearance").strong().size(16.0));
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    ui.label("Accent");
                    ui.add_space(12.0);
                    for (accent, label) in [
                        (Accent::Honey, "Honey"),
                        (Accent::Apricot, "Apricot"),
                        (Accent::Gold, "Gold"),
                    ] {
                        let selected = self.preferences.accent == accent;
                        let (rect, response) =
                            ui.allocate_exact_size(Vec2::splat(30.0), egui::Sense::click());
                        let painter = ui.painter_at(rect);
                        painter.circle_filled(rect.center(), 10.0, accent_primary(accent));
                        painter.circle_stroke(
                            rect.center(),
                            if selected { 14.0 } else { 12.0 },
                            Stroke::new(
                                if selected { 2.0_f32 } else { 1.0_f32 },
                                if selected {
                                    accent_primary(accent)
                                } else if self.preferences.theme == Theme::Dark {
                                    Color32::from_rgb(77, 89, 105)
                                } else {
                                    Color32::from_rgb(205, 211, 217)
                                },
                            ),
                        );
                        if response.on_hover_text(label).clicked() {
                            self.preferences.accent = accent;
                            self.save_preferences();
                            self.apply_preferences(ctx);
                        }
                    }
                });
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.label("Theme");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let dark_changed = ui
                            .selectable_value(&mut self.preferences.theme, Theme::Dark, "Dark")
                            .changed();
                        let light_changed = ui
                            .selectable_value(&mut self.preferences.theme, Theme::Light, "Light")
                            .changed();
                        if light_changed || dark_changed {
                            self.save_preferences();
                            self.apply_preferences(ctx);
                        }
                    });
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label("Interface size");
                    ui.add_space(8.0);
                    let response = ui.add(
                        egui::Slider::new(&mut self.interface_scale_draft, 0.85..=1.25)
                            .suffix("x"),
                    );
                    ui.label(RichText::new(format!("{:.0}%", self.interface_scale_draft * 100.0)).monospace());
                    if response.drag_stopped() || (response.changed() && !response.dragged()) {
                        self.preferences.font_scale = self.interface_scale_draft;
                        self.save_preferences();
                        self.apply_preferences(ctx);
                    }
                });
                if ui
                    .checkbox(&mut self.preferences.show_splash, "Show opening screen")
                    .changed()
                {
                    self.save_preferences();
                }

                ui.add_space(18.0);
                ui.separator();
                ui.add_space(12.0);
                ui.label(RichText::new("Defaults").strong().size(16.0));
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.label("Generator mode");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let passphrase_changed = ui
                            .selectable_value(
                                &mut self.preferences.default_generator_mode,
                                GeneratorMode::Passphrase,
                                "Passphrase",
                            )
                            .changed();
                        let password_changed = ui
                            .selectable_value(
                                &mut self.preferences.default_generator_mode,
                                GeneratorMode::Password,
                                "Password",
                            )
                            .changed();
                        if password_changed || passphrase_changed {
                            self.save_preferences();
                        }
                    });
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label("Passphrase words");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add(
                                egui::DragValue::new(&mut self.preferences.default_passphrase_word_count)
                                    .range(3..=8)
                                    .suffix(" words"),
                            )
                            .changed()
                        {
                            self.save_preferences();
                        }
                    });
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label("Password length");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add(
                                egui::DragValue::new(&mut self.preferences.default_password_length)
                                    .range(4..=64)
                                    .suffix(" chars"),
                            )
                            .changed()
                        {
                            self.save_preferences();
                        }
                    });
                });
                ui.add_space(16.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Done").clicked() {
                    self.settings_open = false;
                    }
                });
            });
        self.settings_open = open && self.settings_open;
    }
    fn edit_entry(&mut self, index: usize) {
        let entry = self.vault.entries[index].clone();
        self.entry_name.zeroize();
        self.entry_username.zeroize();
        self.entry_password.zeroize();
        self.entry_image_data.zeroize();
        self.entry_custom_fields.zeroize();
        self.entry_name.clone_from(&entry.name);
        self.entry_username.clone_from(&entry.username);
        self.entry_password.clone_from(&entry.password);
        self.entry_image_data.clone_from(&entry.image_data);
        self.entry_custom_fields.clone_from(&entry.custom_fields);
        self.custom_field_label.zeroize();
        self.custom_field_value.zeroize();
        self.selected = Some(index);
        self.editor_open = true;
        self.clear_messages();
    }

    fn editor_window(&mut self, ctx: &egui::Context) {
        let mut open = self.editor_open;
        egui::Window::new(if self.selected.is_some() {
            "Edit entry"
        } else {
            "New entry"
        })
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .default_width(420.0)
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                self.render_entry_image_preview(
                    ui,
                    self.entry_image_data.as_deref(),
                    "editor-entry-preview",
                    64.0,
                );
                ui.vertical(|ui| {
                    ui.label("Service name");
                    ui.add(TextEdit::singleline(&mut self.entry_name).desired_width(ui.available_width()));
                    ui.add_space(10.0);
                    ui.label("Username");
                    ui.add(
                        TextEdit::singleline(&mut self.entry_username).desired_width(ui.available_width()),
                    );
                });
            });
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.button("Upload image").clicked() {
                    self.upload_entry_image();
                }
                if self.entry_image_data.is_some() && ui.button("Remove image").clicked() {
                    self.entry_image_data = None;
                }
            });
            ui.add_space(10.0);
            ui.label("Password");
            ui.add(
                TextEdit::singleline(&mut self.entry_password)
                    .password(true)
                    .desired_width(ui.available_width()),
            );
            ui.add_space(18.0);
            ui.label("Sensitive details");
            let mut remove_index = None;
            for index in (0..self.entry_custom_fields.len()).rev() {
                let mut field_label = self.entry_custom_fields[index].label.clone();
                let mut field_value = self.entry_custom_fields[index].value.clone();
                let mut field_hidden = self.entry_custom_fields[index].hidden;
                let remove = {
                    let mut should_remove = false;
                    ui.horizontal(|ui| {
                        ui.add(
                            TextEdit::singleline(&mut field_label)
                                .hint_text("Phone, card, note...")
                                .desired_width(120.0),
                        );
                        ui.add(
                            TextEdit::singleline(&mut field_value)
                                .password(field_hidden)
                                .desired_width((ui.available_width() - 105.0).clamp(90.0, 210.0)),
                        );
                        if ui.button(if field_hidden { "Show" } else { "Hide" }).clicked() {
                            field_hidden = !field_hidden;
                        }
                        if ui.button("Remove").clicked() {
                            should_remove = true;
                        }
                    });
                    should_remove
                };
                self.entry_custom_fields[index].label = field_label;
                self.entry_custom_fields[index].value = field_value;
                self.entry_custom_fields[index].hidden = field_hidden;
                if remove {
                    remove_index = Some(index);
                }
            }
            if let Some(index) = remove_index {
                self.entry_custom_fields.remove(index);
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.add(
                    TextEdit::singleline(&mut self.custom_field_label)
                        .hint_text("Phone")
                        .desired_width(120.0),
                );
                ui.add(
                    TextEdit::singleline(&mut self.custom_field_value)
                        .password(true)
                        .desired_width((ui.available_width() - 45.0).clamp(100.0, 230.0)),
                );
                if ui.button("Add").clicked() {
                    let label = self.custom_field_label.trim().to_string();
                    if !label.is_empty() {
                        self.entry_custom_fields.push(SensitiveField {
                            label,
                            value: self.custom_field_value.trim().to_string(),
                            hidden: true,
                        });
                        self.custom_field_label.zeroize();
                        self.custom_field_value.zeroize();
                    }
                }
            });
            ui.add_space(18.0);
            ui.horizontal(|ui| {
                if ui.button("Generate").clicked() {
                    self.entry_password = match self.preferences.default_generator_mode {
                        GeneratorMode::Password => generate_password(
                            self.preferences.default_password_length,
                            true,
                            true,
                            true,
                            true,
                        )
                        .unwrap_or_default(),
                        GeneratorMode::Passphrase => generate_passphrase(
                            self.preferences.default_passphrase_word_count,
                            "-",
                            true,
                        )
                        .unwrap_or_default(),
                    };
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .add(
                            egui::Button::new("Save entry")
                                .fill(self.accent())
                                .stroke(Stroke::NONE),
                        )
                        .clicked()
                    {
                        self.save_entry();
                    }
                    if ui.button("Cancel").clicked() {
                        self.editor_open = false;
                        self.clear_entry_editor();
                    }
                });
            });
            if let Some(error) = &self.error {
                ui.add_space(10.0);
                ui.label(RichText::new(error).color(Color32::from_rgb(177, 65, 57)));
            }
        });
        let was_open = self.editor_open;
        self.editor_open = open && self.editor_open;
        if was_open && !self.editor_open {
            self.clear_entry_editor();
        }
    }

    fn save_entry(&mut self) {
        self.clear_messages();
        let name = self.entry_name.trim().to_string();
        if name.is_empty() || self.entry_password.is_empty() {
            self.error = Some("Name and password are required.".into());
            return;
        }
        if let Some(index) = self.selected.filter(|i| *i < self.vault.entries.len()) {
            self.vault.entries[index] = Entry {
                name,
                username: self.entry_username.trim().into(),
                password: self.entry_password.clone(),
                image_data: self.entry_image_data.clone(),
                custom_fields: self.entry_custom_fields.clone(),
            };
        } else {
            if self.vault.entries.iter().any(|e| e.name == name) {
                self.error = Some("An entry with this name already exists.".into());
                return;
            }
            self.vault.entries.push(Entry {
                name,
                username: self.entry_username.trim().into(),
                password: self.entry_password.clone(),
                image_data: self.entry_image_data.clone(),
                custom_fields: self.entry_custom_fields.clone(),
            });
            self.selected = Some(self.vault.entries.len() - 1);
        }
        self.editor_open = false;
        self.save();
        self.clear_entry_editor();
    }

    fn clear_entry_editor(&mut self) {
        self.entry_name.zeroize();
        self.entry_username.zeroize();
        self.entry_password.zeroize();
        self.entry_image_data.zeroize();
        self.entry_custom_fields.zeroize();
        self.custom_field_label.zeroize();
        self.custom_field_value.zeroize();
    }

    fn generator_window(&mut self, ctx: &egui::Context) {
        let was_open = self.generator_open;
        let mut open = self.generator_open;
        egui::Window::new("Password generator")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(430.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.generator_mode, GeneratorMode::Password, "Password");
                    ui.selectable_value(&mut self.generator_mode, GeneratorMode::Passphrase, "Passphrase");
                });
                ui.add_space(12.0);

                match self.generator_mode {
                    GeneratorMode::Password => {
                        ui.label(RichText::new("Password options").strong());
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.label("Length");
                            ui.add(egui::Slider::new(&mut self.generator_length, 4..=64));
                            ui.label(RichText::new(self.generator_length.to_string()).monospace());
                        });
                        ui.horizontal_wrapped(|ui| {
                            ui.checkbox(self.generator_sets.get_mut(0).unwrap(), "Lowercase");
                            ui.checkbox(self.generator_sets.get_mut(1).unwrap(), "Uppercase");
                            ui.checkbox(self.generator_sets.get_mut(2).unwrap(), "Numbers");
                            ui.checkbox(self.generator_sets.get_mut(3).unwrap(), "Symbols");
                        });
                    }
                    GeneratorMode::Passphrase => {
                        ui.label(RichText::new("Passphrase options").strong());
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.label("Words");
                            ui.add(egui::Slider::new(&mut self.passphrase_word_count, 3..=8));
                            ui.label(RichText::new(self.passphrase_word_count.to_string()).monospace());
                        });
                    }
                }

                ui.add_space(12.0);
                egui::Frame::new()
                    .fill(if self.preferences.theme == Theme::Dark {
                        Color32::from_rgb(18, 22, 28)
                    } else {
                        Color32::from_rgb(244, 246, 248)
                    })
                    .corner_radius(8)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.add(
                                TextEdit::singleline(&mut self.generated)
                                    .desired_width(ui.available_width() - 55.0),
                            );
                            if ui.button("Copy").clicked() {
                                ui.ctx().copy_text(self.generated.clone());
                            }
                        });
                    });
                ui.add_space(10.0);
                if ui
                    .add_sized(
                        [ui.available_width(), 38.0],
                        egui::Button::new(match self.generator_mode {
                            GeneratorMode::Password => "Generate password",
                            GeneratorMode::Passphrase => "Generate passphrase",
                        })
                        .fill(self.accent()),
                    )
                    .clicked()
                {
                    self.generated.zeroize();
                    self.generated = match self.generator_mode {
                        GeneratorMode::Password => generate_password(
                            self.generator_length,
                            *self.generator_sets.first().unwrap(),
                            *self.generator_sets.get(1).unwrap(),
                            *self.generator_sets.get(2).unwrap(),
                            *self.generator_sets.get(3).unwrap(),
                        )
                        .unwrap_or_else(|e| e.to_string()),
                        GeneratorMode::Passphrase => generate_passphrase(
                            self.passphrase_word_count,
                            "-",
                            true,
                        )
                        .unwrap_or_else(|e| e.to_string()),
                    };
                }
                ui.add_space(4.0);
            });
        self.generator_open = open && self.generator_open;
        if was_open && !self.generator_open {
            self.generated.zeroize();
        }
    }
}

impl eframe::App for PassbeeApp {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        if self.preferences.theme == Theme::Dark {
            [16.0 / 255.0, 20.0 / 255.0, 26.0 / 255.0, 1.0]
        } else {
            [242.0 / 255.0, 244.0 / 255.0, 246.0 / 255.0, 1.0]
        }
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        match self.view {
            View::Splash => {
                self.splash_view(ctx);
            }
            View::Unlock => {
                egui::CentralPanel::default().show(ctx, |ui| self.auth_view(ui, false));
            }
            View::Create => {
                egui::CentralPanel::default().show(ctx, |ui| self.auth_view(ui, true));
            }
            View::Vault => {
                self.vault_view(ctx);
            }
        }
        self.lifecycle_windows(ctx);
    }
}

fn platform_data_root() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
            .or_else(|| {
                std::env::var_os("USERPROFILE")
                    .map(|home| PathBuf::from(home).join("AppData").join("Local"))
            })
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

fn platform_config_root() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("LOCALAPPDATA").map(PathBuf::from))
            .or_else(|| {
                std::env::var_os("USERPROFILE")
                    .map(|home| PathBuf::from(home).join("AppData").join("Roaming"))
            })
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

fn default_vault_path() -> PathBuf {
    platform_data_root().join("passbee").join("vault.json")
}

fn splash_destination(has_profiles: bool, legacy_vault_exists: bool) -> View {
    if has_profiles || legacy_vault_exists {
        View::Unlock
    } else {
        View::Create
    }
}

fn user_root_path() -> PathBuf {
    platform_data_root().join("passbee").join("users")
}

fn user_vault_path(username: &str) -> PathBuf {
    let clean = username.trim();
    let safe = if clean.is_empty() { "default" } else { clean };
    user_root_path().join(safe).join("vault.json")
}

fn valid_profile_name(username: &str) -> bool {
    let username = username.trim();
    !username.is_empty()
        && username != "."
        && username != ".."
        && !username.contains(['/', '\\'])
        && !username.chars().any(char::is_control)
}

fn verified_user_vault_path(
    username: &str,
    users: &[String],
    password: &str,
) -> Result<(PathBuf, VaultData)> {
    let username = username.trim();
    if !valid_profile_name(username) {
        bail!("Enter a valid username.");
    }

    let path = if users.iter().any(|user| user == username) {
        user_vault_path(username)
    } else if users.is_empty() && username == "default" && default_vault_path().exists() {
        default_vault_path()
    } else {
        bail!("Wrong username or master password.");
    };

    let vault = load_vault(&path, password)
        .map_err(|_| anyhow::anyhow!("Wrong username or master password."))?;
    Ok((path, vault))
}

fn list_user_profiles() -> Vec<String> {
    let root = user_root_path();
    let Ok(entries) = fs::read_dir(&root) else {
        return Vec::new();
    };

    let mut users = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.trim().is_empty() { None } else { Some(name) }
        })
        .collect::<Vec<_>>();

    users.sort();
    users
}

fn delete_user_profile(username: &str) -> Result<()> {
    let path = user_root_path().join(username.trim());
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    Ok(())
}

fn bee_symbol(ui: &mut Ui, size: f32, accent: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    let center = rect.center();
    let body_radius = size * 0.22;
    let wing_radius = size * 0.18;
    let outline = Stroke::new(size * 0.035, Color32::from_rgb(70, 64, 54));
    painter.circle_filled(
        center + Vec2::new((-size) * 0.20, (-size) * 0.13),
        wing_radius,
        Color32::from_rgb(232, 239, 238),
    );
    painter.circle_filled(
        center + Vec2::new(size * 0.20, (-size) * 0.13),
        wing_radius,
        Color32::from_rgb(232, 239, 238),
    );
    painter.circle_stroke(
        center + Vec2::new((-size) * 0.20, (-size) * 0.13),
        wing_radius,
        outline,
    );
    painter.circle_stroke(
        center + Vec2::new(size * 0.20, (-size) * 0.13),
        wing_radius,
        outline,
    );
    painter.circle_filled(center, body_radius, accent);
    painter.circle_stroke(center, body_radius, outline);
    for offset in [-0.09_f32, 0.09_f32] {
        painter.line_segment(
            [
                center + Vec2::new(-body_radius * 0.85, size * offset),
                center + Vec2::new(body_radius * 0.85, size * offset),
            ],
            Stroke::new(size * 0.045, Color32::from_rgb(70, 64, 54)),
        );
    }
    painter.circle_filled(
        center + Vec2::new((-size) * 0.07, (-size) * 0.04),
        size * 0.025,
        Color32::from_rgb(45, 42, 38),
    );
    painter.circle_filled(
        center + Vec2::new(size * 0.07, (-size) * 0.04),
        size * 0.025,
        Color32::from_rgb(45, 42, 38),
    );
    painter.line_segment(
        [
            center + Vec2::new((-size) * 0.08, -body_radius),
            center + Vec2::new((-size) * 0.16, size * -0.38),
        ],
        outline,
    );
    painter.line_segment(
        [
            center + Vec2::new(size * 0.08, -body_radius),
            center + Vec2::new(size * 0.16, size * -0.38),
        ],
        outline,
    );
}

fn preferences_path() -> PathBuf {
    platform_config_root().join("passbee").join("preferences.json")
}

fn load_preferences(path: &Path) -> Preferences {
    fs::read(path)
        .ok()
        .and_then(|data| serde_json::from_slice(&data).ok())
        .unwrap_or_default()
}

fn accent_tint(accent: Accent) -> Color32 {
    match accent {
        Accent::Honey => Color32::from_rgb(250, 232, 190),
        Accent::Apricot => Color32::from_rgb(250, 218, 202),
        Accent::Gold => Color32::from_rgb(244, 231, 177),
    }
}

fn accent_active(accent: Accent) -> Color32 {
    match accent {
        Accent::Honey => Color32::from_rgb(244, 218, 155),
        Accent::Apricot => Color32::from_rgb(242, 190, 169),
        Accent::Gold => Color32::from_rgb(232, 208, 125),
    }
}

fn accent_primary(accent: Accent) -> Color32 {
    match accent {
        Accent::Honey => Color32::from_rgb(212, 139, 35),
        Accent::Apricot => Color32::from_rgb(203, 91, 53),
        Accent::Gold => Color32::from_rgb(174, 132, 20),
    }
}

fn generate_password(
    length: usize,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
) -> Result<String> {
    if !(4..=512).contains(&length) {
        bail!("length must be between 4 and 512");
    }
    let groups: Vec<&[u8]> = [
        lowercase.then_some(LOWER.as_bytes()),
        uppercase.then_some(UPPER.as_bytes()),
        digits.then_some(DIGITS.as_bytes()),
        symbols.then_some(SYMBOLS.as_bytes()),
    ]
    .into_iter()
    .flatten()
    .collect();
    if groups.is_empty() {
        bail!("at least one character set must be enabled");
    }
    if length < groups.len() {
        bail!(
            "length must be at least {} for the selected character sets",
            groups.len()
        );
    }
    let mut rng = rand::thread_rng();
    let mut password: Vec<u8> = groups
        .iter()
        .map(|group| group[rng.gen_range(0..group.len())])
        .collect();
    let alphabet: Vec<u8> = groups
        .iter()
        .flat_map(|group| group.iter().copied())
        .collect();
    let distribution = Uniform::new(0, alphabet.len());
    password.extend((password.len()..length).map(|_| alphabet[rng.sample(distribution)]));
    password.shuffle(&mut rng);
    Ok(String::from_utf8(password)?)
}

fn load_passphrase_words() -> Vec<String> {
    if let Some(words) = load_passphrase_words_from_system() {
        return words;
    }
    PASS_PHRASE_WORDS.iter().map(|word| word.to_string()).collect()
}

fn load_passphrase_words_from_system() -> Option<Vec<String>> {
    for path in [
        "/usr/share/dict/words",
        "/usr/share/dict/american-english",
        "/usr/share/dict/british-english",
        "/usr/share/dict/web2",
    ] {
        let Ok(contents) = fs::read_to_string(path) else {
            continue;
        };

        let mut words = contents
            .lines()
            .filter_map(|line| {
                let word = line.trim().to_ascii_lowercase();
                if word.len() >= 3
                    && word.len() <= 8
                    && word.chars().all(|ch| ch.is_ascii_lowercase())
                {
                    Some(word)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if words.len() >= 200 {
            words.sort();
            words.dedup();
            return Some(words);
        }
    }

    None
}

fn generate_passphrase(word_count: usize, separator: &str, include_number: bool) -> Result<String> {
    if !(3..=12).contains(&word_count) {
        bail!("passphrase word count must be between 3 and 12");
    }
    let dictionary = load_passphrase_words();
    let mut rng = rand::thread_rng();
    let mut words = Vec::with_capacity(word_count);
    for _ in 0..word_count {
        words.push(dictionary[rng.gen_range(0..dictionary.len())].clone());
    }
    if include_number {
        let suffix = rng.gen_range(0..99);
        if let Some(word) = words.first_mut() {
            word.push_str(&suffix.to_string());
        }
    }
    Ok(words.join(separator))
}

fn remove_entry(entries: &mut Vec<Entry>, index: usize) -> Option<usize> {
    if index < entries.len() {
        entries.remove(index);
    }
    (!entries.is_empty()).then_some(0)
}

fn parse_data_uri(data_uri: &str) -> Option<&str> {
    let (_, encoded) = data_uri.split_once(',')?;
    Some(encoded)
}

fn resize_image_to_fit(image: image::DynamicImage, max_dimension: u32) -> image::DynamicImage {
    let (width, height) = image.dimensions();
    let max_size = width.max(height);
    if max_size <= max_dimension {
        return image;
    }

    let scale = max_dimension as f32 / max_size as f32;
    let new_width = (width as f32 * scale).max(1.0) as u32;
    let new_height = (height as f32 * scale).max(1.0) as u32;
    image.resize(new_width, new_height, image::imageops::FilterType::Lanczos3)
}

fn read_bounded_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > max_bytes {
        bail!("file exceeds the {} byte limit", max_bytes);
    }

    let mut bytes = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        bail!("file exceeds the {} byte limit", max_bytes);
    }
    Ok(bytes)
}

fn decode_entry_image(bytes: &[u8]) -> Result<image::DynamicImage> {
    let mut reader = image::ImageReader::new(Cursor::new(bytes)).with_guessed_format()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DECODE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DECODE_DIMENSION);
    limits.max_alloc = Some(MAX_IMAGE_DECODE_ALLOCATION);
    reader.limits(limits);
    Ok(reader.decode()?)
}

fn load_entry_texture(
    ctx: &egui::Context,
    key: &str,
    encoded: &str,
) -> Option<egui::TextureHandle> {
    let image_bytes = BASE64.decode(encoded).ok()?;
    let image = resize_image_to_fit(
        decode_entry_image(&image_bytes).ok()?,
        MAX_ENTRY_IMAGE_DIMENSION,
    );
    let rgba = image.to_rgba8();
    let color_image = egui::ColorImage::from_rgba_unmultiplied(
        [rgba.width() as usize, rgba.height() as usize],
        &rgba,
    );
    Some(ctx.load_texture(key, color_image, egui::TextureOptions::LINEAR))
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Key<Aes256Gcm>> {
    let params = Params::new(19 * 1024, 3, 1, Some(32))
        .map_err(|_| anyhow::anyhow!("invalid Argon2 parameters"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| anyhow::anyhow!("could not derive encryption key"))?;
    Ok(*Key::<Aes256Gcm>::from_slice(key.as_slice()))
}

fn save_vault(path: &Path, data: &VaultData, password: &str) -> Result<()> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(salt.as_mut_slice());
    rand::thread_rng().fill_bytes(nonce.as_mut_slice());
    let key = derive_key(password, &salt)?;
    let plaintext = serde_json::to_vec(data)?;
    let ciphertext = Aes256Gcm::new(&key)
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| anyhow::anyhow!("could not encrypt vault"))?;
    let file = VaultFile {
        version: FORMAT_VERSION,
        salt: BASE64.encode(salt),
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(ciphertext),
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    let payload = serde_json::to_vec_pretty(&file)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::Builder::new()
        .prefix(".passbee-vault-")
        .tempfile_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    temp.write_all(&payload)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn load_vault(path: &Path, password: &str) -> Result<VaultData> {
    let raw = read_bounded_file(path, MAX_VAULT_FILE_BYTES)
        .with_context(|| format!("could not read vault at {}", path.display()))?;
    let file: VaultFile = serde_json::from_slice(&raw).context("vault file is not valid")?;
    if file.version != FORMAT_VERSION {
        bail!("unsupported vault format version {}", file.version);
    }
    let salt = BASE64.decode(file.salt).context("invalid vault salt")?;
    let nonce = BASE64.decode(file.nonce).context("invalid vault nonce")?;
    let ciphertext = BASE64
        .decode(file.ciphertext)
        .context("invalid vault ciphertext")?;
    if salt.len() != SALT_LEN || nonce.len() != NONCE_LEN {
        bail!("vault metadata has invalid length");
    }
    let key = derive_key(password, &salt)?;
    let plaintext = Aes256Gcm::new(&key)
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("wrong master password or corrupted vault"))?;
    Ok(serde_json::from_slice(&plaintext).context("decrypted vault is invalid")?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_password_has_requested_character_sets() {
        let password = generate_password(64, true, true, true, true).unwrap();
        assert_eq!(password.len(), 64);
        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(password.chars().any(|c| SYMBOLS.contains(c)));
    }
    #[test]
    fn generated_passphrase_uses_requested_word_count() {
        let passphrase = generate_passphrase(4, "-", true).unwrap();
        let parts: Vec<_> = passphrase.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert!(parts.iter().all(|word| !word.is_empty()));
        assert!(passphrase.chars().any(|c| c.is_ascii_digit()) || passphrase.chars().any(|c| c.is_ascii_alphabetic()));
    }

    #[test]
    fn default_passphrase_length_is_eight_words() {
        assert_eq!(Preferences::default().default_passphrase_word_count, 8);
    }

    #[test]
    fn deleting_only_entry_clears_selection() {
        let mut entries = vec![Entry {
            name: "mail".into(),
            username: "me".into(),
            password: "secret".into(),
            image_data: None,
            custom_fields: vec![],
        }];

        let selection = remove_entry(&mut entries, 0);

        assert!(entries.is_empty());
        assert_eq!(selection, None);
    }

    #[test]
    fn splash_routes_to_unlock_when_named_profiles_exist() {
        assert!(matches!(splash_destination(true, false), View::Unlock));
        assert!(matches!(splash_destination(false, true), View::Unlock));
        assert!(matches!(splash_destination(false, false), View::Create));
    }

    #[test]
    fn bounded_image_read_rejects_oversized_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large-image.png");
        std::fs::write(&path, b"12345").unwrap();

        assert!(read_bounded_file(&path, 4).is_err());
    }

    #[test]
    fn image_decoder_rejects_dimensions_over_the_limit() {
        let image = image::DynamicImage::new_rgba8(MAX_IMAGE_DECODE_DIMENSION + 1, 1);
        let mut encoded = Cursor::new(Vec::new());
        image
            .write_to(&mut encoded, image::ImageFormat::Png)
            .unwrap();

        assert!(decode_entry_image(&encoded.into_inner()).is_err());
    }

    #[test]
    fn encryption_round_trip_rejects_wrong_password() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.json");
        let data = VaultData {
            entries: vec![Entry {
                name: "mail".into(),
                username: "me".into(),
                password: "secret".into(),
                image_data: None,
                custom_fields: vec![],
            }],
        };
        save_vault(&path, &data, "correct horse battery staple").unwrap();
        save_vault(&path, &data, "correct horse battery staple").unwrap();
        assert!(!String::from_utf8_lossy(&std::fs::read(&path).unwrap()).contains("secret"));
        assert!(load_vault(&path, "wrong password").is_err());
        assert_eq!(
            load_vault(&path, "correct horse battery staple")
                .unwrap()
                .entries[0]
                .password,
            "secret"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn custom_fields_round_trip_through_vault() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.json");
        let data = VaultData {
            entries: vec![Entry {
                name: "wallet".into(),
                username: "alex".into(),
                password: "very-strong-pass".into(),
                image_data: None,
                custom_fields: vec![
                    SensitiveField {
                        label: "Phone".into(),
                        value: "+1 555 123 4567".into(),
                        hidden: true,
                    },
                    SensitiveField {
                        label: "Credit card".into(),
                        value: "4242 4242 4242 4242".into(),
                        hidden: true,
                    },
                ],
            }],
        };

        save_vault(&path, &data, "correct horse battery staple").unwrap();
        let loaded = load_vault(&path, "correct horse battery staple").unwrap();

        assert_eq!(loaded.entries[0].custom_fields.len(), 2);
        assert_eq!(loaded.entries[0].custom_fields[0].label, "Phone");
        assert_eq!(loaded.entries[0].custom_fields[1].value, "4242 4242 4242 4242");
    }

    #[test]
    fn user_vault_paths_are_unique_per_user() {
        let first = user_vault_path("alice");
        let second = user_vault_path("bob");
        assert_ne!(first, second);
        assert!(first.ends_with("alice/vault.json"));
        assert!(second.ends_with("bob/vault.json"));
    }

    #[test]
    fn deleting_user_profile_removes_user_directory() {
        let _guard = HOME_MUTEX.lock().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path();
        let user_dir = home.join(".local/share/passbee/users/alice");
        std::fs::create_dir_all(&user_dir).unwrap();
        std::fs::write(user_dir.join("vault.json"), "{}").unwrap();

        let original_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", home);
        }
        let result = delete_user_profile("alice");
        unsafe {
            if let Some(value) = original_home {
                std::env::set_var("HOME", value);
            } else {
                std::env::remove_var("HOME");
            }
        }

        result.unwrap();
        assert!(!user_dir.exists());
    }

    #[test]
    fn profile_lookup_requires_a_valid_username_and_master_password() {
        let _guard = HOME_MUTEX.lock().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path();
        let original_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", home);
        }

        let path = user_vault_path("alice");
        save_vault(&path, &VaultData::default(), "correct horse battery staple").unwrap();
        let users = vec!["alice".to_string()];

        assert!(verified_user_vault_path("alice", &users, "correct horse battery staple").is_ok());
        let wrong_password_error = verified_user_vault_path("alice", &users, "wrong password")
            .map_err(|error| error.to_string())
            .err()
            .unwrap();
        let unknown_user_error = verified_user_vault_path("bob", &users, "correct horse battery staple")
            .map_err(|error| error.to_string())
            .err()
            .unwrap();
        assert_eq!(wrong_password_error, unknown_user_error);
        assert!(verified_user_vault_path("../alice", &users, "correct horse battery staple").is_err());

        unsafe {
            if let Some(value) = original_home {
                std::env::set_var("HOME", value);
            } else {
                std::env::remove_var("HOME");
            }
        }
    }

    #[test]
    fn creating_a_new_profile_after_deleting_a_user_still_works() {
        let _guard = HOME_MUTEX.lock().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path();

        let original_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", home);
        }

        let alice_dir = user_root_path().join("alice");
        std::fs::create_dir_all(&alice_dir).unwrap();
        std::fs::write(alice_dir.join("vault.json"), "{}").unwrap();

        let bob_dir = user_root_path().join("bob");
        std::fs::create_dir_all(&bob_dir).unwrap();
        std::fs::write(bob_dir.join("vault.json"), "{}").unwrap();

        delete_user_profile("alice").unwrap();

        let users = list_user_profiles();
        assert_eq!(users, vec!["bob".to_string()]);

        let new_path = user_vault_path("charlie");
        save_vault(&new_path, &VaultData::default(), "correct horse battery staple").unwrap();
        assert!(new_path.exists());

        unsafe {
            if let Some(value) = original_home {
                std::env::set_var("HOME", value);
            } else {
                std::env::remove_var("HOME");
            }
        }
    }
}
