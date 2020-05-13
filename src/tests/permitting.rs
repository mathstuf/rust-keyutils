// Copyright (c) 2019, Ben Boeckel
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

use crate::keytypes::User;
use crate::{KeyPermissions, Permission};

use super::utils;
use super::utils::kernel::*;

#[test]
fn invalid_key_chown() {
    let mut key = utils::invalid_key();
    let err = key.chown(*UID).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn invalid_key_chgrp() {
    let mut key = utils::invalid_key();
    let err = key.chgrp(*GID).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn invalid_key_chmod() {
    let mut key = utils::invalid_key();
    let err = key.set_permissions(Permission::POSSESSOR_VIEW).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn invalid_keyring_chown() {
    let mut keyring = utils::invalid_key();
    let err = keyring.chown(*UID).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn invalid_keyring_chgrp() {
    let mut keyring = utils::invalid_key();
    let err = keyring.chgrp(*GID).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn invalid_keyring_chmod() {
    let mut keyring = utils::invalid_keyring();
    let err = keyring.set_permissions(Permission::empty()).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn invalid_key_permissions() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let mut key = keyring
        .add_key::<User, _, _>("invalid_key_permissions", payload)
        .unwrap();

    let err = key
        .set_permissions_raw(KeyPermissions::max_value())
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn invalid_keyring_permissions() {
    let mut keyring = utils::new_test_keyring();

    let err = keyring
        .set_permissions_raw(KeyPermissions::max_value())
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn unlinked_key_chown() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let mut key = keyring
        .add_key::<User, _, _>("unlinked_key_chown", payload)
        .unwrap();

    keyring.unlink_key(&key).unwrap();
    utils::wait_for_key_gc(&key);

    let err = key.chown(*UID).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn unlinked_key_chgrp() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let mut key = keyring
        .add_key::<User, _, _>("unlinked_key_chgrp", payload)
        .unwrap();

    keyring.unlink_key(&key).unwrap();
    utils::wait_for_key_gc(&key);

    let err = key.chgrp(*GID).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn unlinked_key_chmod() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let mut key = keyring
        .add_key::<User, _, _>("unlinked_key_chmod", payload)
        .unwrap();

    keyring.unlink_key(&key).unwrap();
    utils::wait_for_key_gc(&key);

    let err = key.set_permissions(Permission::POSSESSOR_VIEW).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn chown_keyring() {
    let mut keyring = utils::new_test_keyring();

    if *UID == 0 {
        match keyring.chown(1) {
            // If that worked, make sure we can move it back.
            Ok(_) => keyring.chown(0).unwrap(),
            // Otherwise, we got the right error.
            Err(err) => assert_eq!(err, errno::Errno(libc::EACCES)),
        }
    } else {
        let err = keyring.chown(1).unwrap_err();
        assert_eq!(err, errno::Errno(libc::EACCES));
    }
}

#[test]
fn chown_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let mut key = keyring.add_key::<User, _, _>("chown_key", payload).unwrap();

    if *UID == 0 {
        match key.chown(1) {
            // If that worked, make sure we can move it back.
            Ok(_) => key.chown(0).unwrap(),
            // Otherwise, we got the right error.
            Err(err) => assert_eq!(err, errno::Errno(libc::EACCES)),
        }
        let err = key.chown(1).unwrap_err();
        assert_eq!(err, errno::Errno(libc::EACCES));
    }
}

#[test]
fn set_each_permission_bit() {
    let permission_bits = [
        Permission::OTHER_VIEW,
        Permission::OTHER_READ,
        Permission::OTHER_WRITE,
        Permission::OTHER_SEARCH,
        Permission::OTHER_LINK,
        Permission::OTHER_SET_ATTRIBUTE,
        Permission::GROUP_VIEW,
        Permission::GROUP_READ,
        Permission::GROUP_WRITE,
        Permission::GROUP_SEARCH,
        Permission::GROUP_LINK,
        Permission::GROUP_SET_ATTRIBUTE,
        Permission::USER_VIEW,
        Permission::USER_READ,
        Permission::USER_WRITE,
        Permission::USER_SEARCH,
        Permission::USER_LINK,
        Permission::USER_SET_ATTRIBUTE,
        Permission::POSSESSOR_VIEW,
        Permission::POSSESSOR_READ,
        Permission::POSSESSOR_WRITE,
        Permission::POSSESSOR_SEARCH,
        Permission::POSSESSOR_LINK,
        Permission::POSSESSOR_SET_ATTRIBUTE,
    ];
    let required_permissions = Permission::USER_SET_ATTRIBUTE | Permission::USER_VIEW;

    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let mut key = keyring
        .add_key::<User, _, _>("set_each_permission_bit", payload)
        .unwrap();

    for permission_bit in &permission_bits {
        let perms = required_permissions | *permission_bit;
        key.set_permissions(perms).unwrap();
        let description = key.description().unwrap();
        assert_eq!(perms, description.perms);
    }
}

#[test]
fn cannot_view_via_group() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let mut key = keyring
        .add_key::<User, _, _>("cannot_view_via_group", payload)
        .unwrap();

    let perms = Permission::GROUP_ALL | Permission::USER_SET_ATTRIBUTE;
    key.set_permissions(perms).unwrap();

    let err = key.read().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EACCES));
}

#[test]
fn cannot_view_via_other() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let mut key = keyring
        .add_key::<User, _, _>("cannot_view_via_other", payload)
        .unwrap();

    let perms = Permission::OTHER_ALL | Permission::USER_SET_ATTRIBUTE;
    key.set_permissions(perms).unwrap();

    let err = key.read().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EACCES));
}

#[test]
fn remove_setattr() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let mut key = keyring
        .add_key::<User, _, _>("remove_setattr", payload)
        .unwrap();

    let perms = Permission::all()
        - (Permission::POSSESSOR_SET_ATTRIBUTE
            | Permission::USER_SET_ATTRIBUTE
            | Permission::GROUP_SET_ATTRIBUTE
            | Permission::OTHER_SET_ATTRIBUTE);
    key.set_permissions(perms).unwrap();

    let err = key.set_permissions(Permission::all()).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EACCES));
}
