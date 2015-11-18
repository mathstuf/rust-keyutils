extern crate bitflags;

use super::ffi::*;

/// Special keyrings predefined for a process.
pub enum SpecialKeyring {
    /// A thread-specific keyring.
    ThreadKeyring,
    /// A process-specific keyring.
    ProcessKeyring,
    /// A session-specific keyring.
    SessionKeyring,
    /// TODO
    UserKeyring,
    /// TODO
    UserSessionKeyring,
    /// TODO
    GroupKeyring,
}

/// The kernel type for representing a keyring (or key).
pub type KeyringSerial = i32;

impl SpecialKeyring {
    /// Retrieve the serial number for the special keyring.
    pub fn serial(self) -> KeyringSerial {
        match self {
            SpecialKeyring::ThreadKeyring       => KEY_SPEC_THREAD_KEYRING,
            SpecialKeyring::ProcessKeyring      => KEY_SPEC_PROCESS_KEYRING,
            SpecialKeyring::SessionKeyring      => KEY_SPEC_SESSION_KEYRING,
            SpecialKeyring::UserKeyring         => KEY_SPEC_USER_KEYRING,
            SpecialKeyring::UserSessionKeyring  => KEY_SPEC_USER_SESSION_KEYRING,
            SpecialKeyring::GroupKeyring        => KEY_SPEC_GROUP_KEYRING,
        }
    }
}

/// An enumeration for the keyrings which may be set as the default.
pub enum DefaultKeyring {
    /// TODO
    NoChange,
    /// TODO
    ThreadKeyring,
    /// TODO
    ProcessKeyring,
    /// TODO
    SessionKeyring,
    /// TODO
    UserKeyring,
    /// TODO
    UserSessionKeyring,
    /// TODO
    GroupKeyring,
    /// TODO
    DefaultKeyring,
}

/// The kernel type for representing a default keyring.
pub type KeyringDefaultSerial = i32;

impl DefaultKeyring {
    /// Retrieve the serial number for the default keyring.
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

impl From<i32> for DefaultKeyring {
    fn from(id: i32) -> DefaultKeyring {
        match id {
            KEY_REQKEY_DEFL_NO_CHANGE               => DefaultKeyring::NoChange,
            KEY_REQKEY_DEFL_THREAD_KEYRING          => DefaultKeyring::ThreadKeyring,
            KEY_REQKEY_DEFL_PROCESS_KEYRING         => DefaultKeyring::ProcessKeyring,
            KEY_REQKEY_DEFL_SESSION_KEYRING         => DefaultKeyring::SessionKeyring,
            KEY_REQKEY_DEFL_USER_KEYRING            => DefaultKeyring::UserKeyring,
            KEY_REQKEY_DEFL_USER_SESSION_KEYRING    => DefaultKeyring::UserSessionKeyring,
            KEY_REQKEY_DEFL_GROUP_KEYRING           => DefaultKeyring::GroupKeyring,
            KEY_REQKEY_DEFL_DEFAULT                 => DefaultKeyring::DefaultKeyring,
            _                                       => panic!("Invalid value for a default keyring: {}", id),
        }
    }
}

/// The kernel type for representing a keyring's (or key's) permission.
///
/// TODO: explain more
pub type KeyPermissions = u32;

bitflags! {
    flags KeyringPermission: key_perm_t {
        const POSSESSOR_VIEW            = KEY_POS_VIEW,
        const POSSESSOR_READ            = KEY_POS_READ,
        const POSSESSOR_WRITE           = KEY_POS_WRITE,
        const POSSESSOR_SEARCH          = KEY_POS_SEARCH,
        const POSSESSOR_LINK            = KEY_POS_LINK,
        const POSSESSOR_SET_ATTRIBUTE   = KEY_POS_SETATTR,
        const POSSESSOR_ALL             = KEY_POS_ALL,

        const USER_VIEW             = KEY_USR_VIEW,
        const USER_READ             = KEY_USR_READ,
        const USER_WRITE            = KEY_USR_WRITE,
        const USER_SEARCH           = KEY_USR_SEARCH,
        const USER_LINK             = KEY_USR_LINK,
        const USER_SET_ATTRIBUTE    = KEY_USR_SETATTR,
        const USER_ALL              = KEY_USR_ALL,

        const GROUP_VIEW            = KEY_GRP_VIEW,
        const GROUP_READ            = KEY_GRP_READ,
        const GROUP_WRITE           = KEY_GRP_WRITE,
        const GROUP_SEARCH          = KEY_GRP_SEARCH,
        const GROUP_LINK            = KEY_GRP_LINK,
        const GROUP_SET_ATTRIBUTE   = KEY_GRP_SETATTR,
        const GROUP_ALL             = KEY_GRP_ALL,

        const OTHER_VIEW            = KEY_OTH_VIEW,
        const OTHER_READ            = KEY_OTH_READ,
        const OTHER_WRITE           = KEY_OTH_WRITE,
        const OTHER_SEARCH          = KEY_OTH_SEARCH,
        const OTHER_LINK            = KEY_OTH_LINK,
        const OTHER_SET_ATTRIBUTE   = KEY_OTH_SETATTR,
        const OTHER_ALL             = KEY_OTH_ALL,
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
