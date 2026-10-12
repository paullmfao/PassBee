fn main() {
    println!("cargo:rerun-if-changed=assets/passbee.ico");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let icon_path = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("assets/passbee.ico");

        if !icon_path.exists() {
            eprintln!(
                "Warning: icon file not found at '{}'; continuing without embedding the app icon.",
                icon_path.display()
            );
            return;
        }

        let icon_path = icon_path.to_string_lossy();
        let mut resources = winres::WindowsResource::new();
        resources.set_icon(&icon_path);

        if std::env::var("HOST").ok() != std::env::var("TARGET").ok() {
            let target = std::env::var("TARGET").expect("Cargo sets TARGET for build scripts");
            let tool_prefix = target.replace("-pc-windows-gnu", "-w64-mingw32");
            resources
                .set_windres_path(&format!("{tool_prefix}-windres"))
                .set_ar_path(&format!("{tool_prefix}-ar"));
        }

        if let Err(err) = resources.compile() {
            eprintln!(
                "Warning: could not embed the Passbee application icon: {}. Continuing without it.",
                err
            );
        }
    }
}
