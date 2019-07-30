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
use crate::Permission;

use super::utils;

#[test]
fn invalid_key() {
    let key = utils::invalid_key();
    let err = key.read().unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn invalid_keyring() {
    let keyring = utils::invalid_keyring();
    let err = keyring.read().unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn unlinked_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let key = keyring
        .add_key::<User, _, _>("unlinked_key", payload)
        .unwrap();

    keyring.unlink_key(&key).unwrap();
    utils::wait_for_key_gc(&key);

    let err = key.read().unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));

    keyring.invalidate().unwrap()
}

#[test]
fn unlinked_keyring() {
    let mut keyring = utils::new_test_keyring();
    let new_keyring = keyring.add_keyring("unlinked_keyring").unwrap();

    keyring.unlink_keyring(&new_keyring).unwrap();
    utils::wait_for_keyring_gc(&new_keyring);

    let err = new_keyring.read().unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));

    keyring.invalidate().unwrap()
}

#[test]
fn read_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let key = keyring.add_key::<User, _, _>("read_key", payload).unwrap();

    let actual_payload = key.read().unwrap();
    assert_eq!(payload, actual_payload.as_slice());

    keyring.invalidate().unwrap()
}

#[test]
fn read_keyring() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let key = keyring
        .add_key::<User, _, _>("read_keyring", payload)
        .unwrap();

    let (keys, keyrings) = keyring.read().unwrap();
    assert_eq!(1, keys.len());
    assert_eq!(key, keys[0]);
    assert!(keyrings.is_empty());

    keyring.invalidate().unwrap()
}

#[test]
fn read_no_read_perm_with_search() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let mut key = keyring
        .add_key::<User, _, _>("read_no_read_perm_with_search", payload)
        .unwrap();

    // Remove the "read" permission from the key.
    let no_read_search_perms = Permission::USER_ALL - Permission::USER_READ;
    key.set_permissions(no_read_search_perms).unwrap();

    // This should still work because we have "search" permission on its keyring.
    let actual_payload = key.read().unwrap();
    assert_eq!(payload, actual_payload.as_slice());

    keyring.invalidate().unwrap()
}

#[test]
fn read_no_read_search_perm_with_search() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let mut key = keyring
        .add_key::<User, _, _>("read_no_read_search_perm_with_search", payload)
        .unwrap();

    // Remove the "read" and "search" permissions from the key.
    let no_read_perms = Permission::USER_ALL - Permission::USER_READ - Permission::USER_SEARCH;
    key.set_permissions(no_read_perms).unwrap();

    let err = key.read().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EACCES));

    keyring.invalidate().unwrap()
}

#[test]
fn read_rely_on_possessor() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let mut key = keyring
        .add_key::<User, _, _>("read_rely_on_possessor", payload)
        .unwrap();

    // Remove the "read" and "search" permissions from the key.
    let no_read_perms = Permission::POSSESSOR_ALL - Permission::POSSESSOR_READ;
    key.set_permissions(no_read_perms).unwrap();

    let actual_payload = key.read().unwrap();
    assert_eq!(payload, actual_payload.as_slice());

    keyring.invalidate().unwrap()
}

#[test]
fn reinstated_read_perm() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let mut key = keyring
        .add_key::<User, _, _>("reinstated_read_perm", payload)
        .unwrap();

    // Remove the "read" and "search" permissions from the key.
    let no_read_perms = Permission::USER_ALL - Permission::USER_READ - Permission::USER_SEARCH;
    key.set_permissions(no_read_perms).unwrap();

    let err = key.read().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EACCES));

    // Reinstate "read" permissions.
    let no_read_perms = Permission::USER_ALL - Permission::USER_SEARCH;
    key.set_permissions(no_read_perms).unwrap();

    let actual_payload = key.read().unwrap();
    assert_eq!(payload, actual_payload.as_slice());

    keyring.invalidate().unwrap()
}
