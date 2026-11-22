//! Safe wrappers over the Ledger OS endorsement syscalls, slot 1, scheme 1.
//! This is the only `unsafe` code in the app.
//!
//! Scheme 1 means that for `sign(data)` Ledger OS computes an ECDSA
//! (secp256k1) signature over
//!
//!     SHA-256(data || code_hash)
//!
//! where `code_hash` is the SHA-256 of this installed application. The OS
//! appends it; the app cannot choose or omit it. A verifier that pins the
//! Countersign app hash therefore knows which app displayed the bytes it
//! signed. `sys_endorsement_key1_sign_without_code_hash` is deliberately
//! never used.
//!
//! The Owner certificate is a DER ECDSA signature by the Owner (Ledger's
//! HSM) over SHA-256(0xFE || public_key), produced at provisioning time.

use crate::AppSW;
use ledger_secure_sdk_sys::{
    sys_endorsement_get_code_hash, sys_endorsement_get_public_key,
    sys_endorsement_get_public_key_signature, sys_endorsement_key1_sign_data,
};
#[cfg(feature = "probe")]
use ledger_secure_sdk_sys::sys_endorsement_key1_sign_without_code_hash;

pub const PUBLIC_KEY_LENGTH: usize = 65;
pub const CODE_HASH_LENGTH: usize = 32;
/// ENDORSEMENT_SIGNATURE_MAX_LENGTH: a DER ECDSA signature over secp256k1.
pub const SIGNATURE_MAX_LENGTH: usize = 72;

const SLOT_1: u8 = 1;

/// A DER signature (or certificate) with its actual length.
pub struct DerSignature {
    bytes: [u8; SIGNATURE_MAX_LENGTH],
    len: usize,
}

impl DerSignature {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

/// Maps a bolos_err_t to a status word. The listed codes are documented in
/// the SDK's os_endorsement.h as "endorsement not set" / "no private key or
/// certificate in slot 1".
fn check(err: u32) -> Result<(), AppSW> {
    match err {
        0 => Ok(()),
        0x4103 | 0x4104 | 0x4106 | 0x5218 | 0x5219 | 0x521B => Err(AppSW::EndorsementUnavailable),
        _ => Err(AppSW::SigningFailed),
    }
}

/// The slot-1 endorsement public key as a 65-byte uncompressed secp256k1 point.
pub fn public_key() -> Result<[u8; PUBLIC_KEY_LENGTH], AppSW> {
    let mut out = [0u8; PUBLIC_KEY_LENGTH];
    let mut len: usize = out.len();
    // SAFETY: `out` is a 65-byte buffer and `len` tells the OS its capacity.
    check(unsafe { sys_endorsement_get_public_key(SLOT_1, out.as_mut_ptr(), &mut len) })?;
    if len != PUBLIC_KEY_LENGTH {
        return Err(AppSW::SigningFailed);
    }
    Ok(out)
}

/// The Owner certificate stored for slot 1 at provisioning time.
pub fn owner_certificate() -> Result<DerSignature, AppSW> {
    let mut sig = DerSignature { bytes: [0u8; SIGNATURE_MAX_LENGTH], len: SIGNATURE_MAX_LENGTH };
    // SAFETY: `sig.bytes` has SIGNATURE_MAX_LENGTH bytes and `sig.len` holds that capacity.
    check(unsafe { sys_endorsement_get_public_key_signature(SLOT_1, sig.bytes.as_mut_ptr(), &mut sig.len) })?;
    if sig.len == 0 || sig.len > SIGNATURE_MAX_LENGTH {
        return Err(AppSW::SigningFailed);
    }
    Ok(sig)
}

/// SHA-256 of this application, as Ledger OS computed it at install time.
pub fn code_hash() -> Result<[u8; CODE_HASH_LENGTH], AppSW> {
    let mut out = [0u8; CODE_HASH_LENGTH];
    // SAFETY: `out` is a 32-byte buffer and its length is passed alongside.
    check(unsafe { sys_endorsement_get_code_hash(out.as_mut_ptr(), out.len()) })?;
    Ok(out)
}

/// Signs SHA-256(data || code_hash) with the slot-1 endorsement key.
pub fn sign(data: &[u8]) -> Result<DerSignature, AppSW> {
    let mut sig = DerSignature { bytes: [0u8; SIGNATURE_MAX_LENGTH], len: SIGNATURE_MAX_LENGTH };
    // SAFETY: `data` is a valid slice for the call's duration; `sig.bytes`
    // has SIGNATURE_MAX_LENGTH bytes and `sig.len` holds that capacity.
    check(unsafe {
        sys_endorsement_key1_sign_data(data.as_ptr(), data.len(), sig.bytes.as_mut_ptr(), &mut sig.len)
    })?;
    if sig.len == 0 || sig.len > SIGNATURE_MAX_LENGTH {
        return Err(AppSW::SigningFailed);
    }
    Ok(sig)
}

/// PROBE ONLY (feature "probe"): signs SHA-256(data) with the slot-1 key and
/// no code hash. Used once to test whether Ledger OS lets an ordinary app
/// call this syscall; a production build never includes it.
#[cfg(feature = "probe")]
pub fn sign_without_code_hash(data: &[u8]) -> Result<DerSignature, u32> {
    let mut sig = DerSignature { bytes: [0u8; SIGNATURE_MAX_LENGTH], len: SIGNATURE_MAX_LENGTH };
    // SAFETY: same buffer contract as `sign`.
    let err = unsafe {
        sys_endorsement_key1_sign_without_code_hash(data.as_ptr(), data.len(), sig.bytes.as_mut_ptr(), &mut sig.len)
    };
    if err != 0 {
        return Err(err);
    }
    Ok(sig)
}
