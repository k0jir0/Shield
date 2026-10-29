#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::*;

#[cfg(not(windows))]
compile_error!(
    "Shield's current enforcement profile requires Windows; no unprotected fallback exists."
);
