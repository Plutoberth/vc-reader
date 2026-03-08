mod tui;

use std::env;
use std::fs::File;

use vc_reader::fs;
use vc_reader::veracrypt::Volume;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <container>", args[0]);
        std::process::exit(1);
    }
    let in_path = &args[1];

    let password = rpassword::prompt_password("Password: ")
        .expect("failed to read password");

    let file = File::open(in_path).unwrap_or_else(|e| {
        eprintln!("Cannot open '{in_path}': {e}");
        std::process::exit(1);
    });

    println!("Trying all KDFs (AES-256 only)...");
    let mut vol = Volume::open(file, password.as_bytes()).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        std::process::exit(1);
    });

    println!();
    println!("[SUCCESS] Header decrypted with {}", vol.kdf_name());
    println!("  Format version    : {}", vol.format_version());
    println!("  Volume size       : {} bytes ({:.2} MiB)",
        vol.volume_size(),
        vol.volume_size() as f64 / (1024.0 * 1024.0));
    println!("  Sector size       : {} bytes", vol.sector_size());

    println!();
    println!("Volume key (data)  : {}", hex_bytes(&vol.master_key()[..32]));
    println!("Volume key (tweak) : {}", hex_bytes(&vol.master_key()[32..64]));

    // Detect the filesystem before mounting it.
    let kind = fs::detect(&mut vol).unwrap_or_else(|e| {
        eprintln!("Failed to read filesystem: {e}");
        std::process::exit(1);
    });
    println!("  Filesystem        : {}", kind.name());
    if !kind.is_supported() {
        eprintln!("Error: filesystem {} is not supported (only exFAT and NTFS)", kind.name());
        std::process::exit(1);
    }

    let mut filesystem = fs::open(vol, kind).unwrap_or_else(|e| {
        eprintln!("Failed to open {}: {e}", kind.name());
        std::process::exit(1);
    });

    if let Some(label) = filesystem.label() {
        println!("Volume label: {label}");
    }

    // Hand off to the interactive terminal browser.
    if let Err(e) = tui::run(filesystem.as_mut()) {
        eprintln!("Browser error: {e}");
        std::process::exit(1);
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}
