# Passbee branding assets

`passbee-mark.svg` is the editable logo source. It has a transparent background.

`passbee-mark.png` is generated from that SVG and is used by the splash/auth screens and the running application window icon. `passbee.ico` is the multi-size Windows executable icon and is embedded automatically by `build.rs` on Windows builds.

On Linux, the running window uses the PNG. A launcher/menu icon is installed by the desktop integration package, not embedded in the executable; when packaging Passbee, install the PNG as `hicolor/512x512/apps/passbee.png` and provide a `.desktop` entry with `Icon=passbee`.

To replace the bee artwork, edit or replace `passbee-mark.svg`, then regenerate the runtime PNG and Windows icon from the project root:

```sh
magick -background none assets/passbee-mark.svg -resize 512x512 assets/passbee-mark.png
magick assets/passbee-mark.png -define icon:auto-resize=256,128,64,48,32,16 assets/passbee.ico
```

Rebuild the application after regenerating the assets. The SVG is the source of truth; keep the PNG and ICO in sync with it.
