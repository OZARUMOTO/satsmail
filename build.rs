use std::path::{Path, PathBuf};

use slint_keyos_platform_build::{compile_options, CompileOptions};

/// SATSMAIL's UI is written against the fork's widget library (BasePage,
/// TextMd/TextSm/TextXs, Qrcode, DynamicQrCode, ScrollBody — plus the
/// theme.slint globals Utils/Size/CurrentTheme/Palettes) which the stock 1.0.0
/// `@ui` does not ship. The Foundation CLI stages the stock `@ui` library
/// into `target/foundation/ui/ui` and points `FOUNDATION_UI_LIBRARY_PATH` at
/// it, which would shadow SATSMAIL's widgets. Sync the app's own library over
/// the staged dir (if any) so `@ui/theme.slint` + `@ui/widgets.slint` always
/// resolve, on every build — same pattern as QXXX.
fn sync_app_ui_library() {
    let staged = std::env::var_os("FOUNDATION_UI_LIBRARY_PATH").map(PathBuf::from);
    let staged = match staged {
        Some(p) if p.is_dir() => Some(p),
        _ => None,
    };
    let workspace = std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let app_ui = workspace.join("ui/ui");
    if !app_ui.is_dir() {
        return;
    }
    if let Some(dst) = &staged {
        if dst == &app_ui {
            return; // already pointed at our own library
        }
        if std::fs::exists(dst).unwrap_or(false) {
            let _ = std::fs::remove_dir_all(dst);
        }
        if let Err(e) = copy_dir(&app_ui, dst) {
            eprintln!("satsmail build.rs: failed to sync app UI library: {e}");
        }
    }
}

fn copy_dir(from: &Path, to: &Path) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        if src.is_dir() {
            copy_dir(&src, &dst)?;
        } else {
            std::fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}

fn main() {
    sync_app_ui_library();

    compile_options(CompileOptions {
        module_path: "ui/app.slint",
        include_slint: true,
        include_router: false,
        include_translations: false,
        include_time_localization: false,
    });
}
