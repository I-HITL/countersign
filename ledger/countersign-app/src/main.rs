/*****************************************************************************
 *   Countersign for Ledger devices.
 *
 *   A trusted entity for I-HITL: the device shows a request on its own
 *   screen and, once the human approves, signs exactly those bytes with the
 *   OS endorsement key. Two commands, no key derivation, no settings.
 *   See ledger/countersign-app/README.md for the APDU protocol.
 *****************************************************************************/

#![no_std]
#![no_main]

mod endorsement;
mod handlers;
mod ui;

use ledger_device_sdk::io::{self, init_comm, ApduHeader, Command, CommandResponse, Reply, StatusWords};

ledger_device_sdk::set_panic!(ledger_device_sdk::exiting_panic);
ledger_device_sdk::define_comm!(COMM);

/// Status words returned to the host.
#[repr(u16)]
#[derive(Clone, Copy, PartialEq)]
pub enum AppSW {
    /// The human declined on the device. The host bridge records a decline.
    Deny = 0x6985,
    /// Malformed data: wrong challenge length, empty or >255-byte message, invalid UTF-8.
    IncorrectData = 0x6A80,
    WrongP1P2 = 0x6A86,
    InsNotSupported = 0x6D00,
    CommError = 0x6F00,
    /// Slot 1 holds no endorsement key or certificate: run ledger/host/endorse.py first.
    EndorsementUnavailable = 0xB010,
    /// Ledger OS refused to read or sign with the endorsement key.
    SigningFailed = 0xB011,
    WrongApduLength = StatusWords::BadLen as u16,
    Ok = 0x9000,
}

impl From<AppSW> for Reply {
    fn from(sw: AppSW) -> Reply {
        Reply(sw as u16)
    }
}

impl From<io::CommError> for AppSW {
    fn from(_e: io::CommError) -> Self {
        AppSW::CommError
    }
}

/// Commands this app answers. P1 and P2 are always zero.
pub enum Instruction {
    GetVersion,
    GetAppName,
    Enroll,
    Approve,
    #[cfg(feature = "probe")]
    ProbeSignRaw,
}

impl TryFrom<ApduHeader> for Instruction {
    type Error = AppSW;

    fn try_from(header: ApduHeader) -> Result<Self, Self::Error> {
        match (header.ins, header.p1, header.p2) {
            (0x03, 0, 0) => Ok(Instruction::GetVersion),
            (0x04, 0, 0) => Ok(Instruction::GetAppName),
            (0x10, 0, 0) => Ok(Instruction::Enroll),
            (0x20, 0, 0) => Ok(Instruction::Approve),
            #[cfg(feature = "probe")]
            (0x7F, 0, 0) => Ok(Instruction::ProbeSignRaw),
            (0x03 | 0x04 | 0x10 | 0x20, _, _) => Err(AppSW::WrongP1P2),
            (_, _, _) => Err(AppSW::InsNotSupported),
        }
    }
}

#[no_mangle]
extern "C" fn sample_main(_arg0: u32) {
    // Accept only CLA 0xE0; the SDK answers other classes with BadCla itself.
    let comm = init_comm(&COMM);
    comm.set_expected_cla(0xE0);

    let mut home = ui::home();
    home.show_and_return();

    loop {
        let command = comm.next_command();
        let ins = match command.decode::<Instruction>() {
            Ok(ins) => ins,
            Err(sw) => {
                let _ = comm.send(&[], sw);
                continue;
            }
        };

        let outcome = match handle_apdu(command, &ins) {
            Ok(response) => {
                let _ = response.send(AppSW::Ok);
                AppSW::Ok
            }
            Err(sw) => {
                let _ = comm.send(&[], sw);
                sw
            }
        };

        // Enrollment and approval show a status page; afterwards redraw home.
        if ui::show_outcome(comm, &ins, outcome) {
            home.show_and_return();
        }
    }
}

fn handle_apdu<'a>(command: Command<'a>, ins: &Instruction) -> Result<CommandResponse<'a>, AppSW> {
    match ins {
        Instruction::GetVersion => handlers::get_version(command),
        Instruction::GetAppName => handlers::get_app_name(command),
        Instruction::Enroll => handlers::enroll(command),
        Instruction::Approve => handlers::approve(command),
        #[cfg(feature = "probe")]
        Instruction::ProbeSignRaw => handlers::probe_sign_raw(command),
    }
}
