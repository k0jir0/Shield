use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, Prefix};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Storage::FileSystem::*;

use crate::error::{Error, Result, invalid};
use crate::util;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fingerprint {
    pub volume: u32,
    pub file_index: u64,
    pub write_time: u64,
    pub bytes: u64,
    pub sha256: String,
}

pub fn validate_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(invalid("select an absolute local drive path"));
    }
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)))
    {
        return Err(invalid(
            "UNC, device, verbatim, and remote paths are not supported",
        ));
    }
    for component in components {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => {
                let value = value
                    .to_str()
                    .ok_or_else(|| invalid("path is not Unicode"))?;
                let stem = value.split('.').next().unwrap_or("").to_ascii_uppercase();
                if value.ends_with(['.', ' '])
                    || value.contains([':', '~', '*', '?', '"', '<', '>', '|'])
                    || value.chars().any(char::is_control)
                    || matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                    || (stem.len() == 4
                        && (stem.starts_with("COM") || stem.starts_with("LPT"))
                        && stem.as_bytes()[3].is_ascii_digit())
                {
                    return Err(invalid(
                        "ambiguous, reserved, alternate-stream, or alias paths are unsupported",
                    ));
                }
            }
            _ => return Err(invalid("dot and parent path components are unsupported")),
        }
    }
    Ok(())
}

pub fn check_no_reparse(path: &Path) -> Result<()> {
    validate_path(path)?;
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid(
                "reparse points and synchronized/redirected placeholders are unsupported",
            ));
        }
    }
    Ok(())
}

fn information(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut filesystem = [0_u16; 32];
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(Error::Windows {
            operation: "GetVolumeInformationByHandleW",
            source: std::io::Error::last_os_error(),
        });
    }
    if filesystem[..5] != [b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16, 0] {
        return Err(Error::Unsupported(
            "this file workflow requires a local NTFS volume".into(),
        ));
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(Error::Windows {
            operation: "GetFileInformationByHandle",
            source: std::io::Error::last_os_error(),
        });
    }
    if information.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || information.nNumberOfLinks != 1
    {
        return Err(invalid(
            "only non-reparse, single-link regular files are supported",
        ));
    }
    Ok(information)
}

pub fn snapshot(path: &Path, limit: u64) -> Result<(Vec<u8>, Fingerprint)> {
    let result = snapshot_bytes(path, limit)?;
    util::text(&result.0)?;
    Ok(result)
}

pub fn snapshot_bytes(path: &Path, limit: u64) -> Result<(Vec<u8>, Fingerprint)> {
    let (_, bytes, fingerprint) = capture(path, limit)?;
    Ok((bytes, fingerprint))
}

pub fn pin(path: &Path, limit: u64) -> Result<(File, Fingerprint)> {
    let (file, _, fingerprint) = capture(path, limit)?;
    Ok((file, fingerprint))
}

fn capture(path: &Path, limit: u64) -> Result<(File, Vec<u8>, Fingerprint)> {
    check_no_reparse(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let (bytes, fingerprint) = read_opened(&mut file, limit)?;
    Ok((file, bytes, fingerprint))
}

pub(crate) fn read_opened(file: &mut File, limit: u64) -> Result<(Vec<u8>, Fingerprint)> {
    file.seek(SeekFrom::Start(0))?;
    let first = information(file)?;
    let bytes = util::read_bounded(&mut *file, limit)?;
    let after = information(file)?;
    if first.ftLastWriteTime.dwHighDateTime != after.ftLastWriteTime.dwHighDateTime
        || first.ftLastWriteTime.dwLowDateTime != after.ftLastWriteTime.dwLowDateTime
        || first.nFileSizeHigh != after.nFileSizeHigh
        || first.nFileSizeLow != after.nFileSizeLow
    {
        return Err(Error::Denied(
            "file changed while its snapshot was captured".into(),
        ));
    }
    let fingerprint = Fingerprint {
        volume: after.dwVolumeSerialNumber,
        file_index: (u64::from(after.nFileIndexHigh) << 32) | u64::from(after.nFileIndexLow),
        write_time: (u64::from(after.ftLastWriteTime.dwHighDateTime) << 32)
            | u64::from(after.ftLastWriteTime.dwLowDateTime),
        bytes: bytes.len() as u64,
        sha256: util::digest(&bytes),
    };
    file.seek(SeekFrom::Start(0))?;
    Ok((bytes, fingerprint))
}

pub struct Publication {
    file: File,
    _parents: Vec<File>,
}

impl Publication {
    pub fn lock(path: &Path, expected: &Fingerprint, limit: u64) -> Result<Self> {
        check_no_reparse(path)?;
        let mut parents = Vec::new();
        for parent in path.ancestors().skip(1) {
            parents.push(
                OpenOptions::new()
                    .read(true)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                    .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(parent)?,
            );
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let info = information(&file)?;
        let bytes = util::read_bounded(&mut file, limit)?;
        let actual = Fingerprint {
            volume: info.dwVolumeSerialNumber,
            file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            write_time: (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32)
                | u64::from(info.ftLastWriteTime.dwLowDateTime),
            bytes: bytes.len() as u64,
            sha256: util::digest(&bytes),
        };
        if &actual != expected {
            return Err(Error::Denied(
                "publication target changed since import; nothing was written".into(),
            ));
        }
        Ok(Self {
            file,
            _parents: parents,
        })
    }

    pub fn commit(&mut self, bytes: &[u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(bytes)?;
        self.file.set_len(bytes.len() as u64)?;
        self.file.sync_all()?;
        self.file.seek(SeekFrom::Start(0))?;
        let actual = util::read_bounded(&mut self.file, bytes.len() as u64)?;
        if actual != bytes {
            return Err(Error::Unknown(
                "publication readback differs from the approved artifact".into(),
            ));
        }
        Ok(())
    }
}

pub fn create_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_paths_do_not_reach_the_filesystem() {
        for path in [
            r"relative.txt",
            r"\\server\share\note.txt",
            r"\\?\C:\note.txt",
            r"C:\note.txt:secret",
            r"C:\CON.txt",
            r"C:\note.",
            r#"C:\quote"name.txt"#,
            r"C:\pipe|name.txt",
        ] {
            assert!(validate_path(Path::new(path)).is_err(), "{path}");
        }
    }

    #[test]
    fn publication_rejects_changed_content_and_hardlinks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("note.txt");
        std::fs::write(&path, "original").unwrap();
        let (_, fingerprint) = snapshot(&path, 100).unwrap();
        std::fs::write(&path, "concurrent edit").unwrap();
        assert!(Publication::lock(&path, &fingerprint, 100).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "concurrent edit");
        let link = directory.path().join("alias.txt");
        std::fs::hard_link(&path, &link).unwrap();
        assert!(snapshot(&path, 100).is_err());
    }

    #[test]
    fn locked_publication_changes_only_the_selected_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("note.txt");
        std::fs::write(&path, "old").unwrap();
        let (_, fingerprint) = snapshot(&path, 100).unwrap();
        let mut publication = Publication::lock(&path, &fingerprint, 100).unwrap();
        publication.commit(b"reviewed new text").unwrap();
        drop(publication);
        assert_eq!(std::fs::read(&path).unwrap(), b"reviewed new text");
    }

    #[test]
    fn pinned_admission_input_cannot_be_written_or_deleted_during_authoring() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("application.exe");
        std::fs::write(&path, b"inert executable fixture").unwrap();
        let (pin, fingerprint) = pin(&path, 100).unwrap();
        assert_eq!(
            fingerprint.sha256,
            util::digest(b"inert executable fixture")
        );
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::fs::remove_file(&path).is_err());
        drop(pin);
        std::fs::write(&path, b"authorized later change").unwrap();
    }
}
