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

use std::time::Duration;

use crate::keytypes::User;
use crate::KeyManager;

use super::utils;

#[test]
fn instantiate_invalid_key() {
    let key = utils::invalid_key();
    let manager = KeyManager::test_new(key);

    let payload = "payload".as_bytes();
    let err = manager.instantiate(None, payload).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EPERM));
}

#[test]
fn reject_invalid_key() {
    let key = utils::invalid_key();
    let manager = KeyManager::test_new(key);

    let duration = Duration::from_secs(1);
    let errno = errno::Errno(libc::EKEYREJECTED);
    let err = manager.reject(None, duration, errno).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EPERM));
}

#[test]
fn negate_invalid_key() {
    let key = utils::invalid_key();
    let manager = KeyManager::test_new(key);

    let duration = Duration::from_secs(1);
    let err = manager.negate(None, duration).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EPERM));
}

#[test]
fn instantiate_into_not_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let key = keyring
        .add_key::<User, _, _>("instantiate_into_not_key", payload)
        .unwrap();
    let mut not_a_keyring = utils::key_as_keyring(&key);
    let manager = KeyManager::test_new(key);

    let payload = "payload".as_bytes();
    let err = manager
        .instantiate(&mut not_a_keyring, payload)
        .unwrap_err();
    // Should be ENOTDIR, but the kernel doesn't have an authorization key for us to use.
    assert_eq!(err, errno::Errno(libc::EPERM));
}

#[test]
fn reject_into_not_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let key = keyring
        .add_key::<User, _, _>("reject_into_not_key", payload)
        .unwrap();
    let mut not_a_keyring = utils::key_as_keyring(&key);
    let manager = KeyManager::test_new(key);

    let duration = Duration::from_secs(1);
    let errno = errno::Errno(libc::EKEYREJECTED);
    let err = manager
        .reject(&mut not_a_keyring, duration, errno)
        .unwrap_err();
    // Should be ENOTDIR, but the kernel doesn't have an authorization key for us to use.
    assert_eq!(err, errno::Errno(libc::EPERM));
}

#[test]
fn negate_into_not_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let key = keyring
        .add_key::<User, _, _>("negate_into_not_key", payload)
        .unwrap();
    let mut not_a_keyring = utils::key_as_keyring(&key);
    let manager = KeyManager::test_new(key);

    let duration = Duration::from_secs(1);
    let err = manager.negate(&mut not_a_keyring, duration).unwrap_err();
    // Should be ENOTDIR, but the kernel doesn't have an authorization key for us to use.
    assert_eq!(err, errno::Errno(libc::EPERM));
}

#[test]
fn instantiate_already_instantiated() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let key = keyring
        .add_key::<User, _, _>("instantiate_already_instantiated", payload)
        .unwrap();
    let manager = KeyManager::test_new(key);

    let err = manager.instantiate(None, payload).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EPERM));
}

#[test]
fn reject_already_instantiated() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let key = keyring
        .add_key::<User, _, _>("reject_already_instantiated", payload)
        .unwrap();
    let manager = KeyManager::test_new(key);

    let duration = Duration::from_secs(1);
    let errno = errno::Errno(libc::EKEYREJECTED);
    let err = manager.reject(None, duration, errno).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EPERM));
}

#[test]
fn negate_already_instantiated() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let key = keyring
        .add_key::<User, _, _>("negate_already_instantiated", payload)
        .unwrap();
    let manager = KeyManager::test_new(key);

    let duration = Duration::from_secs(1);
    let err = manager.negate(None, duration).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EPERM));
}

#[test]
fn instantiate_unlinked_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let key = keyring
        .add_key::<User, _, _>("instantiate_unlinked_key", payload)
        .unwrap();

    keyring.unlink_key(&key).unwrap();
    utils::wait_for_key_gc(&key);

    let manager = KeyManager::test_new(key);

    let err = manager.instantiate(None, payload).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EPERM));
}

#[test]
fn reject_unlinked_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let key = keyring
        .add_key::<User, _, _>("reject_unlinked_key", payload)
        .unwrap();

    keyring.unlink_key(&key).unwrap();
    utils::wait_for_key_gc(&key);

    let manager = KeyManager::test_new(key);

    let duration = Duration::from_secs(1);
    let errno = errno::Errno(libc::EKEYREJECTED);
    let err = manager.reject(None, duration, errno).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EPERM));
}

#[test]
fn negate_unlinked_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let key = keyring
        .add_key::<User, _, _>("negate_unlinked_key", payload)
        .unwrap();

    keyring.unlink_key(&key).unwrap();
    utils::wait_for_key_gc(&key);

    let manager = KeyManager::test_new(key);

    let duration = Duration::from_secs(1);
    let err = manager.negate(None, duration).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EPERM));
}
