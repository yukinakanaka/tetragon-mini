use crate::api::{Capabilities, ProcessPrivilegesChanged, SecureBitsType};
use tetragon_common::bpf_cred::MsgCapabilities;

/* Execve extra flags */
pub const EXECVE_SETUID: u32 = 0x01;
pub const EXECVE_SETGID: u32 = 0x02;

fn get_capabilities_types(cap_int: u64) -> Vec<i32> {
    let mut caps = Vec::new();
    for i in 0..64 {
        if (1 << i) & cap_int != 0 {
            caps.push(i);
        }
    }
    caps
}

pub fn get_msg_capabilities(caps: &MsgCapabilities) -> Capabilities {
    Capabilities {
        permitted: get_capabilities_types(caps.permitted),
        effective: get_capabilities_types(caps.effective),
        inheritable: get_capabilities_types(caps.inheritable),
    }
}

pub fn get_secure_bits_types(sec_bit: u32) -> Vec<i32> {
    if sec_bit == 0 {
        return vec![];
    }

    let mut bits = Vec::new();

    if sec_bit & SecureBitsType::SecBitNoRoot as u32 != 0 {
        bits.push(SecureBitsType::SecBitNoRoot.into());
    }

    if sec_bit & SecureBitsType::SecBitNoRootLocked as u32 != 0 {
        bits.push(SecureBitsType::SecBitNoRootLocked.into());
    }

    if sec_bit & SecureBitsType::SecBitNoSetUidFixup as u32 != 0 {
        bits.push(SecureBitsType::SecBitNoSetUidFixup.into());
    }

    if sec_bit & SecureBitsType::SecBitNoSetUidFixupLocked as u32 != 0 {
        bits.push(SecureBitsType::SecBitNoSetUidFixupLocked.into());
    }

    if sec_bit & SecureBitsType::SecBitKeepCaps as u32 != 0 {
        bits.push(SecureBitsType::SecBitKeepCaps.into());
    }

    if sec_bit & SecureBitsType::SecBitKeepCapsLocked as u32 != 0 {
        bits.push(SecureBitsType::SecBitKeepCapsLocked.into());
    }

    if sec_bit & SecureBitsType::SecBitNoCapAmbientRaise as u32 != 0 {
        bits.push(SecureBitsType::SecBitNoCapAmbientRaise.into());
    }

    if sec_bit & SecureBitsType::SecBitNoCapAmbientRaiseLocked as u32 != 0 {
        bits.push(SecureBitsType::SecBitNoCapAmbientRaiseLocked.into());
    }

    bits
}

pub fn get_privileges_changed_reasons(reasons: u32) -> Vec<i32> {
    if reasons == 0 {
        return vec![];
    }

    let mut bits = Vec::new();

    if reasons & ProcessPrivilegesChanged::PrivilegesRaisedExecFileCap as u32 != 0 {
        bits.push(ProcessPrivilegesChanged::PrivilegesRaisedExecFileCap.into());
    }

    if reasons & ProcessPrivilegesChanged::PrivilegesRaisedExecFileSetuid as u32 != 0 {
        bits.push(ProcessPrivilegesChanged::PrivilegesRaisedExecFileSetuid.into());
    }

    if reasons & ProcessPrivilegesChanged::PrivilegesRaisedExecFileSetgid as u32 != 0 {
        bits.push(ProcessPrivilegesChanged::PrivilegesRaisedExecFileSetgid.into());
    }

    bits
}
