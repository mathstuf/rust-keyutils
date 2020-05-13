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

use crate::keytypes::{Keyring, User};
use crate::{Key, KeyType, Permission};

use super::utils;
use super::utils::kernel::*;

#[test]
fn invalid_key() {
    let key = utils::invalid_key();
    let err = key.description().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn invalid_keyring() {
    let keyring = utils::invalid_keyring();
    let err = keyring.description().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn non_existent_key() {
    let mut keyring = utils::new_test_keyring();
    let key = keyring
        .add_key::<User, _, _>("non_existent_key", &b"payload"[..])
        .unwrap();

    keyring.unlink_key(&key).unwrap();
    utils::wait_for_key_gc(&key);
}

#[test]
fn describe_keyring() {
    let mut keyring = utils::new_test_keyring();
    let description = "describe_keyring";
    let keyring = keyring.add_keyring(description).unwrap();

    let perms = Permission::POSSESSOR_ALL | Permission::USER_VIEW;

    let desc = keyring.description().unwrap();
    assert_eq!(desc.type_, Keyring::name());
    assert_eq!(desc.uid, *UID);
    assert_eq!(desc.gid, *GID);
    assert_eq!(desc.perms, perms);
    assert_eq!(desc.description, description);

    keyring.invalidate().unwrap()
}

#[test]
fn describe_key() {
    let mut keyring = utils::new_test_keyring();
    let description = "describe_key";
    let key = keyring
        .add_key::<User, _, _>(description, &b"payload"[..])
        .unwrap();

    let perms = Permission::POSSESSOR_ALL | Permission::USER_VIEW;

    let desc = key.description().unwrap();
    assert_eq!(desc.type_, User::name());
    assert_eq!(desc.uid, *UID);
    assert_eq!(desc.gid, *GID);
    assert_eq!(desc.perms, perms);
    assert_eq!(desc.description, description);
}

#[test]
fn describe_key_no_perm() {
    let mut keyring = utils::new_test_keyring();
    let description = "describe_key_no_perm";
    let mut key = keyring
        .add_key::<User, _, _>(description, &b"payload"[..])
        .unwrap();

    let old_perms = key.description().unwrap().perms;
    let perms = {
        let mut perms = old_perms;
        let view_bits = Permission::POSSESSOR_VIEW | Permission::USER_VIEW;
        perms.remove(view_bits);
        perms
    };
    key.set_permissions(perms).unwrap();

    let err = key.description().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EACCES));
}

#[test]
fn describe_revoked_key() {
    let mut keyring = utils::new_test_keyring();
    let key = keyring
        .add_key::<User, _, _>("describe_revoked_key", &b"payload"[..])
        .unwrap();

    let key_mirror = unsafe { Key::new(key.serial()) };
    key.revoke().unwrap();

    let err = key_mirror.description().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYREVOKED));
}
