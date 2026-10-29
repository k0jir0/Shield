use std::io::{self, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, Prefix};

use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

fn execute() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments.len() != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected an absolute owned marker path and a 64-character hexadecimal nonce",
        ));
    }
    let nonce = arguments[2]
        .to_str()
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid canary nonce"))?;
    let marker = Path::new(&arguments[1]);
    if !marker.is_absolute()
        || !matches!(marker.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)))
        || marker
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        || marker.file_name().and_then(|value| value.to_str()) != Some("marker.txt")
        || marker
            .parent()
            .and_then(Path::file_name)
            .and_then(|value| value.to_str())
            != Some(format!("Shield-admission-{nonce}").as_str())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "marker must be in an explicitly owned Shield-admission-<nonce> directory",
        ));
    }
    let mut parents = Vec::new();
    for parent in marker.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(parent)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "reparse-point marker paths are unsupported",
            ));
        }
        parents.push(
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(parent)?,
        );
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(marker)?;
    writeln!(file, "{} {nonce}", env!("CARGO_BIN_NAME"))?;
    file.sync_all()?;
    Ok(())
}

pub fn main() {
    if let Err(error) = execute() {
        eprintln!("Shield inert admission canary failed: {error}");
        std::process::exit(1);
    }
}
