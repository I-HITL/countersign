//! Screens, built on the SDK's NBGL use cases so one codebase renders on
//! Nano S+/X, Stax, Flex and Apex. Wording mirrors the Android and iOS apps.

use crate::{AppSW, Instruction};
use ledger_device_sdk::include_gif;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::{
    Field, NbglChoice, NbglGlyph, NbglHomeAndSettings, NbglReview, NbglStatus, TransactionType,
};

#[cfg(target_os = "apex_p")]
const GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/countersign_48x48.png", NBGL));
#[cfg(any(target_os = "stax", target_os = "flex"))]
const GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/countersign_64x64.gif", NBGL));
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
const GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("icons/countersign_14x14.gif", NBGL));

// The Nano home screen wants the icon inverted (dark glyph on light, rounded).
#[cfg(any(target_os = "nanosplus", target_os = "nanox"))]
const HOME_GLYPH: NbglGlyph =
    NbglGlyph::from_include(include_gif!("glyphs/countersign_home_nano.png", NBGL));
#[cfg(target_os = "apex_p")]
const HOME_GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/countersign_48x48.png", NBGL));
#[cfg(any(target_os = "stax", target_os = "flex"))]
const HOME_GLYPH: NbglGlyph = NbglGlyph::from_include(include_gif!("glyphs/countersign_64x64.gif", NBGL));

pub fn home() -> NbglHomeAndSettings {
    NbglHomeAndSettings::new()
        .glyph(&HOME_GLYPH)
        .infos("Countersign", env!("CARGO_PKG_VERSION"), "Countersign contributors")
        .tagline("Approve requests shown on this screen")
}

/// Asks the human to share this device's endorsement key with the service.
pub fn confirm_enrollment(comm: &mut Comm) -> bool {
    NbglChoice::new().glyph(&GLYPH).show(
        comm,
        "Enroll this device?",
        "Share its endorsement key with Countersign.",
        "Confirm enrollment",
        "Cancel",
    )
}

/// Shows the request text verbatim and returns whether the human approved it.
pub fn review_request(comm: &mut Comm, message: &str) -> bool {
    let fields = [Field { name: "Request", value: message }];
    NbglReview::new()
        .tx_type(TransactionType::Operation)
        .titles("Review request", "", "Approve request?")
        .glyph(&GLYPH)
        .show(comm, &fields)
}

/// Status page after enrollment or approval. Returns whether one was shown.
pub fn show_outcome(comm: &mut Comm, ins: &Instruction, outcome: AppSW) -> bool {
    let text = match (ins, outcome) {
        (Instruction::Enroll, AppSW::Ok) => "Enrolled",
        (Instruction::Enroll, AppSW::Deny) => "Enrollment cancelled",
        (Instruction::Enroll, AppSW::EndorsementUnavailable) => "No endorsement key",
        (Instruction::Approve, AppSW::Ok) => "Approved",
        (Instruction::Approve, AppSW::Deny) => "Declined",
        (Instruction::Enroll | Instruction::Approve, _) => "Nothing was signed",
        #[allow(unreachable_patterns)]
        _ => return false,
    };
    NbglStatus::new().text(text).show(comm, outcome == AppSW::Ok);
    true
}
