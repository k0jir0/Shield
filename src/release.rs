use std::ffi::c_void;
use std::fs::File;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::{NonNull, null_mut};

use serde::Serialize;
use windows_sys::Win32::Foundation::{HANDLE, HWND};
use windows_sys::Win32::Security::WinTrust::*;
use windows_sys::core::GUID;

use crate::error::{Error, Result, invalid};
use crate::platform::SystemLibrary;
use crate::{files, util};

const IMAGE_BYTES: u64 = 128 * 1024 * 1024;
const CERTIFICATE_BYTES: u32 = 64 * 1024;

type VerifyTrust = unsafe extern "system" fn(HWND, *mut GUID, *mut c_void) -> i32;
type ProviderData = unsafe extern "system" fn(HANDLE) -> *mut CRYPT_PROVIDER_DATA;
type ProviderSigner =
    unsafe extern "system" fn(*mut CRYPT_PROVIDER_DATA, u32, i32, u32) -> *mut CRYPT_PROVIDER_SGNR;

struct TrustApi {
    _library: SystemLibrary,
    verify: VerifyTrust,
    provider: ProviderData,
    signer: ProviderSigner,
}

impl TrustApi {
    fn load() -> Result<Self> {
        let library = SystemLibrary::load("wintrust.dll")?;
        // These exact native signatures keep WinTrust out of LPAC startup imports.
        let verify = unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, VerifyTrust>(
                library.export(b"WinVerifyTrust\0")?,
            )
        };
        let provider = unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, ProviderData>(
                library.export(b"WTHelperProvDataFromStateData\0")?,
            )
        };
        let signer = unsafe {
            std::mem::transmute::<unsafe extern "system" fn() -> isize, ProviderSigner>(
                library.export(b"WTHelperGetProvSignerFromChain\0")?,
            )
        };
        Ok(Self {
            _library: library,
            verify,
            provider,
            signer,
        })
    }
}

fn trust_status(status: i32, operation: &str) -> Result<()> {
    if status != 0 {
        return Err(Error::Denied(format!(
            "{operation} failed with WinTrust status 0x{:08x}; no unsigned, alternate-publisher or revocation-unknown fallback is permitted",
            status as u32,
        )));
    }
    Ok(())
}

struct TrustState<'a> {
    api: &'a TrustApi,
    data: &'a mut WINTRUST_DATA,
    active: bool,
}

impl TrustState<'_> {
    fn call(&mut self) -> i32 {
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        unsafe {
            (self.api.verify)(
                -1_isize as HWND,
                &mut action,
                (self.data as *mut WINTRUST_DATA).cast(),
            )
        }
    }

    fn close(&mut self) -> Result<()> {
        self.active = false;
        self.data.dwStateAction = WTD_STATEACTION_CLOSE;
        trust_status(self.call(), "WinVerifyTrust state close")
    }
}

impl Drop for TrustState<'_> {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = self.close()
        {
            eprintln!("Shield release verification: {error}");
        }
    }
}

fn sha2_algorithm(oid: &[u8]) -> Result<&'static str> {
    match oid {
        b"2.16.840.1.101.3.4.2.1" => Ok("sha256"),
        b"2.16.840.1.101.3.4.2.2" => Ok("sha384"),
        b"2.16.840.1.101.3.4.2.3" => Ok("sha512"),
        _ => Err(Error::Denied(
            "Authenticode primary signature requires SHA-256, SHA-384 or SHA-512".into(),
        )),
    }
}

fn signer_identity(state: &TrustState<'_>, expected_publisher: &str) -> Result<&'static str> {
    if state.data.hWVTStateData.is_null() {
        return Err(invalid("WinTrust verified-state handle is absent"));
    }
    let provider = NonNull::new(unsafe { (state.api.provider)(state.data.hWVTStateData) })
        .ok_or_else(|| invalid("WinTrust did not return verified provider state"))?;
    let signer = NonNull::new(unsafe { (state.api.signer)(provider.as_ptr(), 0, 0, 0) })
        .ok_or_else(|| invalid("WinTrust did not return the primary verified signer"))?;
    checked_signer(unsafe { signer.as_ref() }, expected_publisher)
}

fn checked_signer(signer: &CRYPT_PROVIDER_SGNR, expected_publisher: &str) -> Result<&'static str> {
    if signer.cbStruct < size_of::<CRYPT_PROVIDER_SGNR>() as u32
        || signer.dwError != 0
        || signer.csCertChain == 0
        || signer.csCertChain > 64
        || signer.pasCertChain.is_null()
        || signer.psSigner.is_null()
    {
        return Err(Error::Denied(
            "WinTrust primary signer metadata is incomplete or failed".into(),
        ));
    }
    let certificate = unsafe { &*signer.pasCertChain };
    if certificate.cbStruct < size_of::<CRYPT_PROVIDER_CERT>() as u32
        || certificate.dwError != 0
        || certificate.pCert.is_null()
    {
        return Err(Error::Denied(
            "WinTrust primary certificate metadata is incomplete or failed".into(),
        ));
    }
    let certificate = unsafe { &*certificate.pCert };
    if certificate.pbCertEncoded.is_null()
        || certificate.cbCertEncoded == 0
        || certificate.cbCertEncoded > CERTIFICATE_BYTES
    {
        return Err(invalid(
            "WinTrust signer certificate exceeds its bound or is absent",
        ));
    }
    let encoded = unsafe {
        std::slice::from_raw_parts(
            certificate.pbCertEncoded,
            certificate.cbCertEncoded as usize,
        )
    };
    if util::digest(encoded) != expected_publisher {
        return Err(Error::Denied(
            "verified Authenticode leaf certificate differs from the frozen publisher pin".into(),
        ));
    }
    let oid = unsafe { (*signer.psSigner).HashAlgorithm.pszObjId };
    if oid.is_null() {
        return Err(invalid("WinTrust signer digest algorithm is absent"));
    }
    let mut value = Vec::new();
    for index in 0..64 {
        let byte = unsafe { *oid.add(index) };
        if byte == 0 {
            return sha2_algorithm(&value);
        }
        value.push(byte);
    }
    Err(invalid(
        "WinTrust signer digest algorithm exceeds its bound",
    ))
}

fn verify_native(file: &File, path: &Path, expected_publisher: &str) -> Result<&'static str> {
    let api = TrustApi::load()?;
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut information = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: file.as_raw_handle(),
        pgKnownSubject: null_mut(),
    };
    let mut signature = WINTRUST_SIGNATURE_SETTINGS {
        cbStruct: size_of::<WINTRUST_SIGNATURE_SETTINGS>() as u32,
        dwIndex: 0,
        dwFlags: WSS_VERIFY_SPECIFIC,
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut information,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_CHAIN
            | WTD_CACHE_ONLY_URL_RETRIEVAL
            | WTD_DISABLE_MD2_MD4,
        pSignatureSettings: &mut signature,
        ..Default::default()
    };
    let mut state = TrustState {
        api: &api,
        data: &mut data,
        active: true,
    };
    let verified = trust_status(
        state.call(),
        "WinVerifyTrust cached whole-chain verification",
    )
    .and_then(|()| {
        if signature.dwVerifiedSigIndex != 0 {
            return Err(Error::Denied(
                "WinTrust verified a different signature index".into(),
            ));
        }
        signer_identity(&state, expected_publisher)
    });
    let closed = state.close();
    match (verified, closed) {
        (Ok(algorithm), Ok(())) => Ok(algorithm),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(close)) => Err(Error::Unknown(format!("{error}; additionally: {close}"))),
    }
}

#[derive(Debug, Serialize)]
pub struct PublisherVerification {
    state: &'static str,
    artifact_sha256: String,
    publisher_cert_sha256: String,
    signature_hash_algorithm: &'static str,
    primary_signature_index: u32,
    revocation: &'static str,
    update_authorized: bool,
    effect_gate_pass: bool,
}

pub fn verify(
    path: &Path,
    expected_sha256: &str,
    publisher_cert_sha256: &str,
) -> Result<PublisherVerification> {
    if !util::is_sha256(expected_sha256) || !util::is_sha256(publisher_cert_sha256) {
        return Err(invalid(
            "release verification requires canonical lowercase SHA-256 file and publisher-certificate pins",
        ));
    }
    let (mut file, original) = files::pin(path, IMAGE_BYTES)?;
    if original.sha256 != expected_sha256 {
        return Err(Error::Denied(
            "release artifact differs from the exact reviewed whole-file SHA-256".into(),
        ));
    }
    let algorithm = verify_native(&file, path, publisher_cert_sha256)?;
    let (_, after) = files::read_opened(&mut file, IMAGE_BYTES)?;
    if after != original {
        return Err(Error::Denied(
            "release artifact changed during native publisher verification".into(),
        ));
    }
    Ok(PublisherVerification {
        state: "exact_artifact_publisher_verified_not_update_authorized",
        artifact_sha256: original.sha256,
        publisher_cert_sha256: publisher_cert_sha256.to_owned(),
        signature_hash_algorithm: algorithm,
        primary_signature_index: 0,
        revocation: "whole_chain_cache_only_unknown_is_failure",
        update_authorized: false,
        effect_gate_pass: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Cryptography::{CERT_CONTEXT, CMSG_SIGNER_INFO};

    #[test]
    fn verified_signer_metadata_requires_the_exact_leaf_pin_sha2_and_bounded_native_layout() {
        let mut encoded = vec![b'x'; CERTIFICATE_BYTES as usize];
        let mut certificate = CERT_CONTEXT {
            pbCertEncoded: encoded.as_mut_ptr(),
            cbCertEncoded: encoded.len() as u32,
            ..Default::default()
        };
        let mut message: CMSG_SIGNER_INFO = unsafe { std::mem::zeroed() };
        message.HashAlgorithm.pszObjId = windows_sys::core::s!("2.16.840.1.101.3.4.2.1").cast_mut();
        let check = |certificate: CERT_CONTEXT,
                     mut message: CMSG_SIGNER_INFO,
                     count: u32,
                     error: u32,
                     pin: &str| {
            let mut chain = CRYPT_PROVIDER_CERT {
                cbStruct: size_of::<CRYPT_PROVIDER_CERT>() as u32,
                pCert: &certificate,
                dwError: error,
                ..Default::default()
            };
            let signer = CRYPT_PROVIDER_SGNR {
                cbStruct: size_of::<CRYPT_PROVIDER_SGNR>() as u32,
                csCertChain: count,
                pasCertChain: &mut chain,
                psSigner: &mut message,
                ..Default::default()
            };
            checked_signer(&signer, pin)
        };
        let pin = util::digest(&encoded);
        assert_eq!(check(certificate, message, 1, 0, &pin).unwrap(), "sha256");
        assert!(
            check(
                certificate,
                message,
                1,
                0,
                &util::digest(b"other publisher")
            )
            .is_err()
        );
        certificate.cbCertEncoded = CERTIFICATE_BYTES + 1;
        assert!(check(certificate, message, 1, 0, &pin).is_err());
        certificate.cbCertEncoded = 0;
        assert!(check(certificate, message, 1, 0, &pin).is_err());
        certificate.cbCertEncoded = encoded.len() as u32;
        message.HashAlgorithm.pszObjId = windows_sys::core::s!("1.3.14.3.2.26").cast_mut();
        assert!(check(certificate, message, 1, 0, &pin).is_err());
        message.HashAlgorithm.pszObjId = windows_sys::core::s!("2.16.840.1.101.3.4.2.1").cast_mut();
        assert!(check(certificate, message, 1, 1, &pin).is_err());
        for count in [0, 65] {
            assert!(check(certificate, message, count, 0, &pin).is_err());
        }
        let signer = CRYPT_PROVIDER_SGNR::default();
        assert!(checked_signer(&signer, &pin).is_err());
    }

    #[test]
    fn only_exact_zero_is_a_successful_wintrust_status() {
        trust_status(0, "test").unwrap();
        for status in [1, i32::MAX, i32::MIN, -2146762496] {
            assert!(trust_status(status, "test").is_err());
        }
    }

    #[test]
    fn weak_unknown_or_extended_algorithm_oids_are_rejected() {
        for (oid, expected) in [
            (b"2.16.840.1.101.3.4.2.1".as_slice(), "sha256"),
            (b"2.16.840.1.101.3.4.2.2".as_slice(), "sha384"),
            (b"2.16.840.1.101.3.4.2.3".as_slice(), "sha512"),
        ] {
            assert_eq!(sha2_algorithm(oid).unwrap(), expected);
        }
        for oid in [b"1.3.14.3.2.26".as_slice(), b"2.16.840.1.101.3.4.2.10", b""] {
            assert!(sha2_algorithm(oid).is_err());
        }
    }

    #[test]
    fn malformed_pins_and_changed_artifacts_refuse_before_native_trust() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("candidate.exe");
        let bytes = b"owned unsigned candidate";
        std::fs::write(&path, bytes).unwrap();
        let pin = util::digest(b"publisher");
        for digest in ["", "a", &"G".repeat(64), &"a".repeat(65)] {
            assert!(verify(&path, digest, &pin).is_err());
            assert!(verify(&path, &util::digest(bytes), digest).is_err());
        }
        let error = verify(&path, &util::digest(b"different"), &pin).unwrap_err();
        assert!(error.to_string().contains("reviewed whole-file"));
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn actual_native_trust_rejects_an_unsigned_owned_image_and_releases_the_pin() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unsigned.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        let hash = util::file_digest(&path).unwrap();
        let error = verify(&path, &hash, &util::digest(b"not a signing authority")).unwrap_err();
        assert!(error.to_string().contains("WinTrust status"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn hardlinked_candidates_cannot_get_a_publisher_success_or_be_modified() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("candidate.exe");
        let alias = directory.path().join("alias.exe");
        let bytes = b"owned hardlink fixture";
        std::fs::write(&path, bytes).unwrap();
        std::fs::hard_link(&path, &alias).unwrap();
        let error = verify(&path, &util::digest(bytes), &util::digest(b"publisher")).unwrap_err();
        assert!(error.to_string().contains("single-link"));
        assert_eq!(std::fs::read(path).unwrap(), bytes);
        assert_eq!(std::fs::read(alias).unwrap(), bytes);
    }
}
