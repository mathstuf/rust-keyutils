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

use super::utils;

#[test]
fn invalid_target_key() {
    let mut invalid_keyring = utils::invalid_keyring();
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("invalid_target_key", payload)
        .unwrap();

    let err = invalid_keyring.unlink_key(&key).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn invalid_target_keyring() {
    let mut invalid_keyring = utils::invalid_keyring();
    let keyring = utils::new_test_keyring();

    let err = invalid_keyring.unlink_keyring(&keyring).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn invalid_source_key() {
    let mut keyring = utils::new_test_keyring();
    let invalid_key = utils::invalid_key();

    let err = keyring.unlink_key(&invalid_key).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn invalid_source_keyring() {
    let mut keyring = utils::new_test_keyring();
    let invalid_keyring = utils::invalid_keyring();

    let err = keyring.unlink_keyring(&invalid_keyring).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn unlink_key_from_non_keyring() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("unlink_key_from_non_keyring", payload)
        .unwrap();
    let mut not_a_keyring = utils::key_as_keyring(&key);

    let err = not_a_keyring.unlink_key(&key).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOTDIR));
}

#[test]
fn unlink_keyring_from_non_keyring() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("unlink_keyring_from_non_keyring", payload)
        .unwrap();
    let mut not_a_keyring = utils::key_as_keyring(&key);

    let err = not_a_keyring.unlink_keyring(&keyring).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOTDIR));
}

#[test]
fn unlink_key_as_keyring() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("unlink_keyring_from_non_keyring", payload)
        .unwrap();
    let not_a_keyring = utils::key_as_keyring(&key);

    // This is OK because the kernel doesn't have the type knowledge that our API does.
    keyring.unlink_keyring(&not_a_keyring).unwrap();
}

#[test]
fn unlink_keyring_as_key() {
    let mut keyring = utils::new_test_keyring();
    let new_keyring = keyring.add_keyring("unlink_keyring_as_key").unwrap();
    let not_a_key = utils::keyring_as_key(&new_keyring);

    // This is OK because the kernel doesn't have the type knowledge that our API does.
    keyring.unlink_key(&not_a_key).unwrap();
}

#[test]
fn unlink_unlinked_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("unlink_unlinked_key", payload)
        .unwrap();

    keyring.unlink_key(&key).unwrap();
    utils::wait_for_key_gc(&key);

    let err = keyring.unlink_key(&key).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn unlink_unlinked_keyring() {
    let mut keyring = utils::new_test_keyring();
    let new_keyring = keyring.add_keyring("unlink_unlinked_keyring").unwrap();

    keyring.unlink_keyring(&new_keyring).unwrap();
    utils::wait_for_keyring_gc(&new_keyring);

    let err = keyring.unlink_keyring(&new_keyring).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn unlink_key_from_unlinked_keyring() {
    let mut keyring = utils::new_test_keyring_manual();
    let mut keyring_observer = keyring.clone();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("unlink_key_from_unlinked_keyring", payload)
        .unwrap();

    keyring.invalidate().unwrap();
    utils::wait_for_keyring_gc(&keyring_observer);

    let err = keyring_observer.unlink_key(&key).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn unlink_keyring_from_unlinked_keyring() {
    let mut keyring = utils::new_test_keyring_manual();
    let mut keyring_observer = keyring.clone();
    let new_keyring = keyring.add_keyring("unlink_from_unlinked_keyring").unwrap();

    keyring.invalidate().unwrap();
    utils::wait_for_keyring_gc(&keyring_observer);

    let err = keyring_observer.unlink_keyring(&new_keyring).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn unlink_unassociated_key() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring.add_keyring("unlink_unassociated_key").unwrap();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("unlink_unassociated_key", payload)
        .unwrap();

    let err = new_keyring.unlink_key(&key).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOENT));
}

#[test]
fn unlink_unassociated_keyring() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring.add_keyring("unlink_unassociated_keyring").unwrap();
    let inner_keyring = keyring
        .add_keyring("unlink_unassociated_keyring_keyring")
        .unwrap();

    let err = new_keyring.unlink_keyring(&inner_keyring).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOENT));
}

#[test]
fn unlink_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("unlink_unlinked_key", payload)
        .unwrap();

    keyring.unlink_key(&key).unwrap();
    utils::wait_for_key_gc(&key);

    let (keys, keyrings) = keyring.read().unwrap();
    assert!(keys.is_empty());
    assert!(keyrings.is_empty());
}

#[test]
fn unlink_keyring() {
    let mut keyring = utils::new_test_keyring();
    let new_keyring = keyring.add_keyring("unlink_keyring").unwrap();

    keyring.unlink_keyring(&new_keyring).unwrap();
    utils::wait_for_keyring_gc(&new_keyring);

    let (keys, keyrings) = keyring.read().unwrap();
    assert!(keys.is_empty());
    assert!(keyrings.is_empty());
}
