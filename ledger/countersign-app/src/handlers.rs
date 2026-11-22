//! APDU handlers. Everything the device signs is either the server's
//! enrollment challenge or the exact message bytes shown on screen.

use crate::{endorsement, ui, AppSW};
use core::str::FromStr;
use ledger_device_sdk::io::{Command, CommandResponse};

pub const APP_NAME: &str = "Countersign";
pub const CHALLENGE_LENGTH: usize = 32;
/// One APDU carries at most 255 data bytes; the message is never chunked, so
/// what the device displays is exactly what one command delivered.
pub const MAX_MESSAGE_LENGTH: usize = 255;

pub fn get_version(command: Command<'_>) -> Result<CommandResponse<'_>, AppSW> {
    let mut parts = env!("CARGO_PKG_VERSION").split('.');
    let mut next = || parts.next().and_then(|p| u8::from_str(p).ok()).ok_or(AppSW::IncorrectData);
    let version = [next()?, next()?, next()?];
    let mut response = command.into_response();
    response.append(&version)?;
    Ok(response)
}

pub fn get_app_name(command: Command<'_>) -> Result<CommandResponse<'_>, AppSW> {
    let mut response = command.into_response();
    response.append(APP_NAME.as_bytes())?;
    Ok(response)
}

/// ENROLL: data = 32-byte server challenge. After the human confirms, returns
/// public_key(65) || code_hash(32) || cert_len(1) || cert || sig_len(1) || sig
/// where sig = endorsement::sign(challenge).
pub fn enroll(command: Command<'_>) -> Result<CommandResponse<'_>, AppSW> {
    let data = command.get_data();
    if data.len() != CHALLENGE_LENGTH {
        return Err(AppSW::IncorrectData);
    }
    let mut challenge = [0u8; CHALLENGE_LENGTH];
    challenge.copy_from_slice(data);

    let comm = command.into_comm();
    if !ui::confirm_enrollment(comm) {
        return Err(AppSW::Deny);
    }
    let public_key = endorsement::public_key()?;
    let code_hash = endorsement::code_hash()?;
    let certificate = endorsement::owner_certificate()?;
    let signature = endorsement::sign(&challenge)?;

    let mut response = comm.begin_response();
    response
        .append(&public_key)?
        .append(&code_hash)?
        .append(&[certificate.len() as u8])?
        .append(certificate.as_slice())?
        .append(&[signature.len() as u8])?
        .append(signature.as_slice())?;
    Ok(response)
}

/// APPROVE: data = the message, UTF-8, 1..=255 bytes. Shown verbatim; on
/// approval returns endorsement::sign(message), a DER ECDSA signature.
pub fn approve(command: Command<'_>) -> Result<CommandResponse<'_>, AppSW> {
    let data = command.get_data();
    if data.is_empty() || data.len() > MAX_MESSAGE_LENGTH {
        return Err(AppSW::IncorrectData);
    }
    let mut message = [0u8; MAX_MESSAGE_LENGTH];
    let len = data.len();
    message[..len].copy_from_slice(data);
    // Displayed as text, so it must be valid UTF-8 without interior NULs.
    let text = core::str::from_utf8(&message[..len]).map_err(|_| AppSW::IncorrectData)?;
    if text.bytes().any(|b| b == 0) {
        return Err(AppSW::IncorrectData);
    }

    let comm = command.into_comm();
    if !ui::review_request(comm, text) {
        return Err(AppSW::Deny);
    }
    // Sign exactly the bytes that were displayed; Ledger OS appends the code hash.
    let signature = endorsement::sign(text.as_bytes())?;

    let mut response = comm.begin_response();
    response.append(signature.as_slice())?;
    Ok(response)
}

/// PROBE ONLY: no UI, signs the raw bytes without the code hash. Returns the
/// OS error code (as two big-endian bytes after 0xEE) when the OS refuses.
#[cfg(feature = "probe")]
pub fn probe_sign_raw(command: Command<'_>) -> Result<CommandResponse<'_>, AppSW> {
    let data = command.get_data();
    let mut buf = [0u8; MAX_MESSAGE_LENGTH];
    let len = data.len().min(MAX_MESSAGE_LENGTH);
    buf[..len].copy_from_slice(&data[..len]);
    let mut response = command.into_response();
    match endorsement::sign_without_code_hash(&buf[..len]) {
        Ok(sig) => {
            response.append(&[0x00])?.append(sig.as_slice())?;
        }
        Err(err) => {
            response.append(&[0xEE])?.append(&err.to_be_bytes())?;
        }
    }
    Ok(response)
}
