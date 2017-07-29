// Copyright (c) 2015, Ben Boeckel
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright notice,
//       this list of conditions and the following disclaimer in the documentation
//       and/or other materials provided with the distribution.
//     * Neither the name of this project nor the names of its contributors
//       may be used to endorse or promote products derived from this software
//       without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crates::libkeyutils_sys::*;

/// Special key types
pub enum KeyType {
    /// Keys which can be created, updated, and read from userspace but are not intended for use by
    /// the kernel.
    User,
    /// Keys which can only be created and updated from userspace but not read back.
    ///
    /// These are intended to be only accessible from kernel space.
    Logon,
}

impl KeyType {
    /// Retrieve the constant value for the key type.
    pub fn value(self) -> &str {
        match self {
            KeyType::User => KEY_TYPE_USER,
            KeyType::Logon => KEY_TYPE_LOGON,
        }
    }
}

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
            SpecialKeyring::ThreadKeyring => KEY_SPEC_THREAD_KEYRING,
            SpecialKeyring::ProcessKeyring => KEY_SPEC_PROCESS_KEYRING,
            SpecialKeyring::SessionKeyring => KEY_SPEC_SESSION_KEYRING,
            SpecialKeyring::UserKeyring => KEY_SPEC_USER_KEYRING,
            SpecialKeyring::UserSessionKeyring => KEY_SPEC_USER_SESSION_KEYRING,
            SpecialKeyring::GroupKeyring => KEY_SPEC_GROUP_KEYRING,
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
            DefaultKeyring::NoChange => KEY_REQKEY_DEFL_NO_CHANGE,
            DefaultKeyring::ThreadKeyring => KEY_REQKEY_DEFL_THREAD_KEYRING,
            DefaultKeyring::ProcessKeyring => KEY_REQKEY_DEFL_PROCESS_KEYRING,
            DefaultKeyring::SessionKeyring => KEY_REQKEY_DEFL_SESSION_KEYRING,
            DefaultKeyring::UserKeyring => KEY_REQKEY_DEFL_USER_KEYRING,
            DefaultKeyring::UserSessionKeyring => KEY_REQKEY_DEFL_USER_SESSION_KEYRING,
            DefaultKeyring::GroupKeyring => KEY_REQKEY_DEFL_GROUP_KEYRING,
            DefaultKeyring::DefaultKeyring => KEY_REQKEY_DEFL_DEFAULT,
        }
    }
}

impl From<i32> for DefaultKeyring {
    fn from(id: i32) -> DefaultKeyring {
        match id {
            KEY_REQKEY_DEFL_NO_CHANGE => DefaultKeyring::NoChange,
            KEY_REQKEY_DEFL_THREAD_KEYRING => DefaultKeyring::ThreadKeyring,
            KEY_REQKEY_DEFL_PROCESS_KEYRING => DefaultKeyring::ProcessKeyring,
            KEY_REQKEY_DEFL_SESSION_KEYRING => DefaultKeyring::SessionKeyring,
            KEY_REQKEY_DEFL_USER_KEYRING => DefaultKeyring::UserKeyring,
            KEY_REQKEY_DEFL_USER_SESSION_KEYRING => DefaultKeyring::UserSessionKeyring,
            KEY_REQKEY_DEFL_GROUP_KEYRING => DefaultKeyring::GroupKeyring,
            KEY_REQKEY_DEFL_DEFAULT => DefaultKeyring::DefaultKeyring,
            _ => panic!("Invalid value for a default keyring: {}", id),
        }
    }
}

/// The kernel type for representing a keyring's (or key's) permission.
///
/// TODO: explain more
pub type KeyPermissions = u32;

bitflags! {
    /// Permission bits for keyring objects.
    ///
    /// Keyrings and keys contain four sets of permissions. First, there are three permission sets
    /// used is based on which of the owning user's ID, the group ID associated with the key or
    /// keyring, and a third set which is used when neither of the other two match.
    ///
    /// The fourth set is combined with the permission set used above (priority to user, then
    /// group, finaly other) where either set granting a permission allows it. This set is,
    /// however, only used if the caller is a "possessor" of they key or keyring. Generally,
    /// "possession" requires the `search` permission, association from the calling thread
    /// (the session, process, and thread keyrings), or is linked to from a possessed keyring. See
    /// `keyrings(7)` for complete details.
    struct KeyringPermission: key_perm_t {
        /// Possession allows viewing attributes about the key or keyring.
        const POSSESSOR_VIEW            = KEY_POS_VIEW;
        /// Possession allows reading a key's contents or a keyring's subkeys.
        const POSSESSOR_READ            = KEY_POS_READ;
        /// Possession allows writing a key's content, revoking a key, or adding and removing a
        /// keyring's links.
        const POSSESSOR_WRITE           = KEY_POS_WRITE;
        /// Possession allows searching within a keyring and the key or keyring may be discovered
        /// during a search.
        const POSSESSOR_SEARCH          = KEY_POS_SEARCH;
        /// Possession allows linking to the key from a keyring.
        const POSSESSOR_LINK            = KEY_POS_LINK;
        /// Possession allows changing ownership details, security labels, and the expiration
        /// time of a key.
        const POSSESSOR_SET_ATTRIBUTE   = KEY_POS_SETATTR;
        /// Possession grants all permissions.
        const POSSESSOR_ALL             = KEY_POS_ALL;

        /// A user ID match allows viewing attributes about the key or keyring.
        const USER_VIEW             = KEY_USR_VIEW;
        /// A user ID match allows reading a key's contents or a keyring's subkeys.
        const USER_READ             = KEY_USR_READ;
        /// A user ID match allows writing a key's content, revoking a key, or adding and removing
        /// a keyring's links.
        const USER_WRITE            = KEY_USR_WRITE;
        /// A user ID match allows searching within a keyring and the key or keyring may be
        /// discovered during a search.
        const USER_SEARCH           = KEY_USR_SEARCH;
        /// A user ID match allows linking to the key from a keyring.
        const USER_LINK             = KEY_USR_LINK;
        /// A user ID match allows changing ownership details, security labels, and the expiration
        /// time of a key.
        const USER_SET_ATTRIBUTE    = KEY_USR_SETATTR;
        /// The user is granted all permissions.
        const USER_ALL              = KEY_USR_ALL;

        /// A group ID match allows viewing attributes about the key or keyring.
        const GROUP_VIEW            = KEY_GRP_VIEW;
        /// A group ID match allows reading a key's contents or a keyring's subkeys.
        const GROUP_READ            = KEY_GRP_READ;
        /// A group ID match allows writing a key's content, revoking a key, or adding and removing
        /// a keyring's links.
        const GROUP_WRITE           = KEY_GRP_WRITE;
        /// A group ID match allows searching within a keyring and the key or keyring may be
        /// discovered during a search.
        const GROUP_SEARCH          = KEY_GRP_SEARCH;
        /// A group ID match allows linking to the key from a keyring.
        const GROUP_LINK            = KEY_GRP_LINK;
        /// A group ID match allows changing ownership details, security labels, and the expiration
        /// time of a key.
        const GROUP_SET_ATTRIBUTE   = KEY_GRP_SETATTR;
        /// The group is granted all permissions.
        const GROUP_ALL             = KEY_GRP_ALL;

        /// Allows viewing attributes about the key or keyring.
        const OTHER_VIEW            = KEY_OTH_VIEW;
        /// Allows reading a key's contents or a keyring's subkeys.
        const OTHER_READ            = KEY_OTH_READ;
        /// Allows writing a key's content, revoking a key, or adding and removing a keyring's
        /// links.
        const OTHER_WRITE           = KEY_OTH_WRITE;
        /// Allows searching within a keyring and the key or keyring may be discovered during a
        /// search.
        const OTHER_SEARCH          = KEY_OTH_SEARCH;
        /// Allows linking to the key from a keyring.
        const OTHER_LINK            = KEY_OTH_LINK;
        /// Allows changing ownership details, security labels, and the expiration time of a key.
        const OTHER_SET_ATTRIBUTE   = KEY_OTH_SETATTR;
        /// All permissions.
        const OTHER_ALL             = KEY_OTH_ALL;
    }
}

#[test]
fn test_keyring_ids() {
    assert_eq!(SpecialKeyring::ThreadKeyring.serial(),
               KEY_SPEC_THREAD_KEYRING);
    assert_eq!(SpecialKeyring::ProcessKeyring.serial(),
               KEY_SPEC_PROCESS_KEYRING);
    assert_eq!(SpecialKeyring::SessionKeyring.serial(),
               KEY_SPEC_SESSION_KEYRING);
    assert_eq!(SpecialKeyring::UserKeyring.serial(), KEY_SPEC_USER_KEYRING);
    assert_eq!(SpecialKeyring::UserSessionKeyring.serial(),
               KEY_SPEC_USER_SESSION_KEYRING);
    assert_eq!(SpecialKeyring::GroupKeyring.serial(),
               KEY_SPEC_GROUP_KEYRING);
}

#[test]
fn test_default_keyring_ids() {
    assert_eq!(DefaultKeyring::NoChange.serial(), KEY_REQKEY_DEFL_NO_CHANGE);
    assert_eq!(DefaultKeyring::ThreadKeyring.serial(),
               KEY_REQKEY_DEFL_THREAD_KEYRING);
    assert_eq!(DefaultKeyring::ProcessKeyring.serial(),
               KEY_REQKEY_DEFL_PROCESS_KEYRING);
    assert_eq!(DefaultKeyring::SessionKeyring.serial(),
               KEY_REQKEY_DEFL_SESSION_KEYRING);
    assert_eq!(DefaultKeyring::UserKeyring.serial(),
               KEY_REQKEY_DEFL_USER_KEYRING);
    assert_eq!(DefaultKeyring::UserSessionKeyring.serial(),
               KEY_REQKEY_DEFL_USER_SESSION_KEYRING);
    assert_eq!(DefaultKeyring::GroupKeyring.serial(),
               KEY_REQKEY_DEFL_GROUP_KEYRING);
    assert_eq!(DefaultKeyring::DefaultKeyring.serial(),
               KEY_REQKEY_DEFL_DEFAULT);
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
