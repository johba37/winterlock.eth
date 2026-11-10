//! Links the firmware (as esp-generate's template does) and checks the partition table
//! (partitions.csv) against the 4 MB flash of an ESP32-WROOM-32: the app partition at a 64 KB
//! boundary after the bootloader and the table, the signer's data partition in whole 4 KB sectors,
//! nothing overlapping, everything inside 4 MB. The build fails if it doesn't fit.

fn main() {
    linker_be_nice();
    check_xtensa_linker_available();
    // make sure linkall.x is the last linker script (otherwise might cause problems with flip-link)
    println!("cargo:rustc-link-arg=-Tlinkall.x");
    partitions();
}

/// The flash of an ESP32-WROOM-32.
const FLASH_SIZE: u64 = 4 * 1024 * 1024;
/// The partition table's place (ESP-IDF's default): everything before it is the bootloader.
const TABLE_OFFSET: u64 = 0x8000;
const TABLE_SIZE: u64 = 0x1000;

fn number(s: &str) -> u64 {
    let s = s.trim();
    let (digits, mul) = match s.strip_suffix(['K', 'k']) {
        Some(d) => (d, 1024),
        None => match s.strip_suffix(['M', 'm']) {
            Some(d) => (d, 1024 * 1024),
            None => (s, 1),
        },
    };
    let v = match digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16),
        None => digits.parse(),
    };
    v.unwrap_or_else(|_| panic!("partitions.csv: bad number {s:?}")) * mul
}

fn partitions() {
    println!("cargo:rerun-if-changed=partitions.csv");
    let csv = std::fs::read_to_string("partitions.csv").expect("partitions.csv");
    let mut parts: Vec<(String, String, String, u64, u64)> = Vec::new();
    for line in csv.lines() {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split(',').map(|x| x.trim()).collect();
        assert!(f.len() >= 5, "partitions.csv: {line:?}");
        parts.push((f[0].into(), f[1].into(), f[2].into(), number(f[3]), number(f[4])));
    }
    let mut spans = vec![(0x1000u64, TABLE_OFFSET, "bootloader".to_string()), (TABLE_OFFSET, TABLE_OFFSET + TABLE_SIZE, "partition table".to_string())];
    for (name, ty, sub, off, size) in &parts {
        assert!(*size > 0, "{name}: empty");
        let end = off + size;
        assert!(end <= FLASH_SIZE, "{name}: ends at {end:#x}, past the 4 MB flash");
        match ty.as_str() {
            "app" => assert!(off % 0x10000 == 0, "{name}: an app partition starts at a 64 KB boundary"),
            _ => assert!(off % 0x1000 == 0 && size % 0x1000 == 0, "{name}: whole 4 KB sectors"),
        }
        for (a, b, other) in &spans {
            assert!(end <= *a || *off >= *b, "{name} overlaps {other}");
        }
        spans.push((*off, end, name.clone()));
        let _ = sub;
    }
    let app = parts.iter().find(|p| p.1 == "app").expect("an app partition");
    let signer = parts.iter().find(|p| p.0 == "signer" && p.1 == "data").expect("the signer's data partition");
    assert_eq!(signer.2, "undefined", "the signer partition's subtype (the firmware looks for it)");
    // the firmware checks the table it boots with against these
    println!("cargo:rustc-env=SIGNER_OFFSET={}", signer.3);
    println!("cargo:rustc-env=SIGNER_SIZE={}", signer.4);
    println!("cargo:rustc-env=APP_SIZE={}", app.4);
}

#[cfg(unix)]
fn check_xtensa_linker_available() {
    println!("cargo:rerun-if-env-changed=PATH");

    let target = std::env::var("TARGET").unwrap_or_default();
    println!(
        "cargo:rerun-if-env-changed={}",
        cargo_linker_env_var(&target)
    );

    let linker = xtensa_linker(&target);

    let error = match std::process::Command::new(&linker)
        .arg("--version")
        .output()
    {
        Ok(_) => return,
        Err(error) => error,
    };

    let export_file = std::env::var("HOME")
        .map(|home| format!("{home}/export-esp.sh"))
        .unwrap_or_else(|_| "$HOME/export-esp.sh".to_string());

    panic!(
        "Xtensa linker `{linker}` was not found in PATH or could not be executed: {error}.\n\n\
         Xtensa targets on Unix require espup's environment export file to be sourced before building.\n\
         Try: `source {export_file}`\n\n\
         If the export file does not exist, run `espup install` first.\n\
         For more details, see:\n\
         https://github.com/esp-rs/espup?tab=readme-ov-file#environment-variables-setup"
    );
}

#[cfg(not(unix))]
fn check_xtensa_linker_available() {}

#[cfg(unix)]
fn xtensa_linker(target: &str) -> String {
    if let Some(linker) = cargo_configured_linker(target) {
        return linker;
    }

    target
        .strip_prefix("xtensa-")
        .and_then(|target| target.strip_suffix("-none-elf"))
        .map(|chip| format!("xtensa-{chip}-elf-gcc"))
        .unwrap_or_else(|| "xtensa-esp32-elf-gcc".to_string())
}

#[cfg(unix)]
fn cargo_configured_linker(target: &str) -> Option<String> {
    std::env::var(cargo_linker_env_var(target)).ok()
}

#[cfg(unix)]
fn cargo_linker_env_var(target: &str) -> String {
    let target = target.replace('-', "_").to_ascii_uppercase();
    format!("CARGO_TARGET_{target}_LINKER")
}

fn linker_be_nice() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        let kind = &args[1];
        let what = &args[2];

        match kind.as_str() {
            "undefined-symbol" => match what.as_str() {
                what if what.starts_with("_defmt_") => {
                    eprintln!();
                    eprintln!(
                        "hint: `defmt` not found - make sure `defmt.x` is added as a linker script and you have included `use defmt_rtt as _;`"
                    );
                    eprintln!();
                }
                "_stack_start" => {
                    eprintln!();
                    eprintln!("hint: Is the linker script `linkall.x` missing?");
                    eprintln!();
                }
                what if what.starts_with("esp_rtos_") => {
                    eprintln!();
                    eprintln!(
                        "hint: `esp-radio` has no scheduler enabled. Make sure you have initialized `esp-rtos` or provided an external scheduler."
                    );
                    eprintln!();
                }
                "embedded_test_linker_file_not_added_to_rustflags" => {
                    eprintln!();
                    eprintln!(
                        "hint: `embedded-test` not found - make sure `embedded-test.x` is added as a linker script for tests"
                    );
                    eprintln!();
                }
                "free"
                | "malloc"
                | "calloc"
                | "get_free_internal_heap_size"
                | "malloc_internal"
                | "realloc_internal"
                | "calloc_internal"
                | "free_internal" => {
                    eprintln!();
                    eprintln!(
                        "hint: Did you forget the `esp-alloc` dependency or didn't enable the `compat` feature on it?"
                    );
                    eprintln!();
                }
                _ => (),
            },
            // we don't have anything helpful for "missing-lib" yet
            _ => {
                std::process::exit(1);
            }
        }

        std::process::exit(0);
    }

    println!(
        "cargo:rustc-link-arg=-Wl,--error-handling-script={}",
        std::env::current_exe().unwrap().display()
    );
}


