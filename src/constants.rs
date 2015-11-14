extern crate bitflags;

use super::ffi::*;

pub enum SpecialKeyring {
    ThreadKeyring,
    ProcessKeyring,
    SessionKeyring,
    UserKeyring,
    UserSessionKeyring,
    GroupKeyring,
    RequestKeyAuthKey,
}

pub type KeyringSerial = i32;

impl SpecialKeyring {
    pub fn serial(self) -> KeyringSerial {
        match self {
            SpecialKeyring::ThreadKeyring       => KEY_SPEC_THREAD_KEYRING,
            SpecialKeyring::ProcessKeyring      => KEY_SPEC_PROCESS_KEYRING,
            SpecialKeyring::SessionKeyring      => KEY_SPEC_SESSION_KEYRING,
            SpecialKeyring::UserKeyring         => KEY_SPEC_USER_KEYRING,
            SpecialKeyring::UserSessionKeyring  => KEY_SPEC_USER_SESSION_KEYRING,
            SpecialKeyring::GroupKeyring        => KEY_SPEC_GROUP_KEYRING,
            SpecialKeyring::RequestKeyAuthKey   => KEY_SPEC_REQKEY_AUTH_KEY,
        }
    }
}

pub enum DefaultKeyring {
    NoChange,
    ThreadKeyring,
    ProcessKeyring,
    SessionKeyring,
    UserKeyring,
    UserSessionKeyring,
    GroupKeyring,
    DefaultKeyring,
}

pub type KeyringDefaultSerial = i32;

impl DefaultKeyring {
    pub fn serial(self) -> KeyringDefaultSerial {
        match self {
            DefaultKeyring::NoChange            => KEY_REQKEY_DEFL_NO_CHANGE,
            DefaultKeyring::ThreadKeyring       => KEY_REQKEY_DEFL_THREAD_KEYRING,
            DefaultKeyring::ProcessKeyring      => KEY_REQKEY_DEFL_PROCESS_KEYRING,
            DefaultKeyring::SessionKeyring      => KEY_REQKEY_DEFL_SESSION_KEYRING,
            DefaultKeyring::UserKeyring         => KEY_REQKEY_DEFL_USER_KEYRING,
            DefaultKeyring::UserSessionKeyring  => KEY_REQKEY_DEFL_USER_SESSION_KEYRING,
            DefaultKeyring::GroupKeyring        => KEY_REQKEY_DEFL_GROUP_KEYRING,
            DefaultKeyring::DefaultKeyring      => KEY_REQKEY_DEFL_DEFAULT,
        }
    }
}

pub type KeyPermissions = u32;

bitflags! {
    flags KeyringAction: key_perm_t {
        const ACTION_VIEW           = 0b00000001,
        const ACTION_READ           = 0b00000010,
        const ACTION_WRITE          = 0b00000100,
        const ACTION_SEARCH         = 0b00001000,
        const ACTION_LINK           = 0b00010000,
        const ACTION_SET_ATTRIBUTE  = 0b00100000,
        const ACTION_ALL            = 0b00111111,
    }
}

bitflags! {
    flags KeyringPermission: key_perm_t {
        const POSSESSOR_VIEW            = ACTION_VIEW.bits << 24,
        const POSSESSOR_READ            = ACTION_READ.bits << 24,
        const POSSESSOR_WRITE           = ACTION_WRITE.bits << 24,
        const POSSESSOR_SEARCH          = ACTION_SEARCH.bits << 24,
        const POSSESSOR_LINK            = ACTION_LINK.bits << 24,
        const POSSESSOR_SET_ATTRIBUTE   = ACTION_SET_ATTRIBUTE.bits << 24,
        const POSSESSOR_ALL             = ACTION_ALL.bits << 24,

        const USER_VIEW             = ACTION_VIEW.bits << 16,
        const USER_READ             = ACTION_READ.bits << 16,
        const USER_WRITE            = ACTION_WRITE.bits << 16,
        const USER_SEARCH           = ACTION_SEARCH.bits << 16,
        const USER_LINK             = ACTION_LINK.bits << 16,
        const USER_SET_ATTRIBUTE    = ACTION_SET_ATTRIBUTE.bits << 16,
        const USER_ALL              = ACTION_ALL.bits << 16,

        const GROUP_VIEW            = ACTION_VIEW.bits << 8,
        const GROUP_READ            = ACTION_READ.bits << 8,
        const GROUP_WRITE           = ACTION_WRITE.bits << 8,
        const GROUP_SEARCH          = ACTION_SEARCH.bits << 8,
        const GROUP_LINK            = ACTION_LINK.bits << 8,
        const GROUP_SET_ATTRIBUTE   = ACTION_SET_ATTRIBUTE.bits << 8,
        const GROUP_ALL             = ACTION_ALL.bits << 8,

        const OTHER_VIEW            = ACTION_VIEW.bits << 0,
        const OTHER_READ            = ACTION_READ.bits << 0,
        const OTHER_WRITE           = ACTION_WRITE.bits << 0,
        const OTHER_SEARCH          = ACTION_SEARCH.bits << 0,
        const OTHER_LINK            = ACTION_LINK.bits << 0,
        const OTHER_SET_ATTRIBUTE   = ACTION_SET_ATTRIBUTE.bits << 0,
        const OTHER_ALL             = ACTION_ALL.bits << 0,
    }
}

impl KeyringPermission {
    pub fn permissions(self) -> KeyPermissions {
        self.bits
    }
}

#[test]
fn test_keyring_ids() {
    assert_eq!(SpecialKeyring::ThreadKeyring.serial(), KEY_SPEC_THREAD_KEYRING);
    assert_eq!(SpecialKeyring::ProcessKeyring.serial(), KEY_SPEC_PROCESS_KEYRING);
    assert_eq!(SpecialKeyring::SessionKeyring.serial(), KEY_SPEC_SESSION_KEYRING);
    assert_eq!(SpecialKeyring::UserKeyring.serial(), KEY_SPEC_USER_KEYRING);
    assert_eq!(SpecialKeyring::UserSessionKeyring.serial(), KEY_SPEC_USER_SESSION_KEYRING);
    assert_eq!(SpecialKeyring::GroupKeyring.serial(), KEY_SPEC_GROUP_KEYRING);
    assert_eq!(SpecialKeyring::RequestKeyAuthKey.serial(), KEY_SPEC_REQKEY_AUTH_KEY);
}

#[test]
fn test_default_keyring_ids() {
    assert_eq!(DefaultKeyring::NoChange.serial(), KEY_REQKEY_DEFL_NO_CHANGE);
    assert_eq!(DefaultKeyring::ThreadKeyring.serial(), KEY_REQKEY_DEFL_THREAD_KEYRING);
    assert_eq!(DefaultKeyring::ProcessKeyring.serial(), KEY_REQKEY_DEFL_PROCESS_KEYRING);
    assert_eq!(DefaultKeyring::SessionKeyring.serial(), KEY_REQKEY_DEFL_SESSION_KEYRING);
    assert_eq!(DefaultKeyring::UserKeyring.serial(), KEY_REQKEY_DEFL_USER_KEYRING);
    assert_eq!(DefaultKeyring::UserSessionKeyring.serial(), KEY_REQKEY_DEFL_USER_SESSION_KEYRING);
    assert_eq!(DefaultKeyring::GroupKeyring.serial(), KEY_REQKEY_DEFL_GROUP_KEYRING);
    assert_eq!(DefaultKeyring::DefaultKeyring.serial(), KEY_REQKEY_DEFL_DEFAULT);
}

#[test]
fn test_permission_bits() {
    assert_eq!(POSSESSOR_VIEW.bits, KEY_POS_VIEW);
    assert_eq!(POSSESSOR_READ.bits, KEY_POS_READ);
    assert_eq!(POSSESSOR_WRITE.bits, KEY_POS_WRITE);
    assert_eq!(POSSESSOR_SEARCH.bits, KEY_POS_SEARCH);
    assert_eq!(POSSESSOR_LINK.bits, KEY_POS_LINK);
    assert_eq!(POSSESSOR_SET_ATTRIBUTE.bits, KEY_POS_SETATTR);
    assert_eq!(POSSESSOR_ALL.bits, KEY_POS_ALL);

    assert_eq!(USER_VIEW.bits, KEY_USR_VIEW);
    assert_eq!(USER_READ.bits, KEY_USR_READ);
    assert_eq!(USER_WRITE.bits, KEY_USR_WRITE);
    assert_eq!(USER_SEARCH.bits, KEY_USR_SEARCH);
    assert_eq!(USER_LINK.bits, KEY_USR_LINK);
    assert_eq!(USER_SET_ATTRIBUTE.bits, KEY_USR_SETATTR);
    assert_eq!(USER_ALL.bits, KEY_USR_ALL);

    assert_eq!(GROUP_VIEW.bits, KEY_GRP_VIEW);
    assert_eq!(GROUP_READ.bits, KEY_GRP_READ);
    assert_eq!(GROUP_WRITE.bits, KEY_GRP_WRITE);
    assert_eq!(GROUP_SEARCH.bits, KEY_GRP_SEARCH);
    assert_eq!(GROUP_LINK.bits, KEY_GRP_LINK);
    assert_eq!(GROUP_SET_ATTRIBUTE.bits, KEY_GRP_SETATTR);
    assert_eq!(GROUP_ALL.bits, KEY_GRP_ALL);

    assert_eq!(OTHER_VIEW.bits, KEY_OTH_VIEW);
    assert_eq!(OTHER_READ.bits, KEY_OTH_READ);
    assert_eq!(OTHER_WRITE.bits, KEY_OTH_WRITE);
    assert_eq!(OTHER_SEARCH.bits, KEY_OTH_SEARCH);
    assert_eq!(OTHER_LINK.bits, KEY_OTH_LINK);
    assert_eq!(OTHER_SET_ATTRIBUTE.bits, KEY_OTH_SETATTR);
    assert_eq!(OTHER_ALL.bits, KEY_OTH_ALL);
}
