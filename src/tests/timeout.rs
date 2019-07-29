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

use std::thread;
use std::time::Duration;

use crate::keytypes::User;

use super::utils;

#[test]
fn invalid_key() {
    let mut key = utils::invalid_key();
    let duration = Duration::from_secs(1);
    let err = key.set_timeout(duration).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn invalid_keyring() {
    let mut keyring = utils::invalid_keyring();
    let duration = Duration::from_secs(1);
    let err = keyring.set_timeout(duration).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn unlinked_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let mut key = keyring
        .add_key::<User, _, _>("unlinked_key", payload)
        .unwrap();

    keyring.unlink_key(&key).unwrap();
    utils::wait_for_key_gc(&key);

    let duration = Duration::from_secs(1);
    let err = key.set_timeout(duration).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));

    keyring.invalidate().unwrap()
}

#[test]
fn big_timeout_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let mut key = keyring
        .add_key::<User, _, _>("unlinked_key", payload)
        .unwrap();

    let duration = Duration::from_secs(1024);
    key.set_timeout(duration).unwrap();

    let actual_payload = key.read().unwrap();
    assert_eq!(payload, actual_payload.as_slice());

    keyring.invalidate().unwrap()
}

#[test]
fn big_timeout_keyring() {
    let mut keyring = utils::new_test_keyring();

    let duration = Duration::from_secs(1024);
    keyring.set_timeout(duration).unwrap();

    let (keys, keyrings) = keyring.read().unwrap();
    assert!(keys.is_empty());
    assert!(keyrings.is_empty());

    keyring.invalidate().unwrap()
}

#[test]
fn expired_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let mut key = keyring
        .add_key::<User, _, _>("expired_key", payload)
        .unwrap();
    let key_observer1 = key.clone();
    let key_observer2 = key.clone();

    let duration = Duration::from_secs(1);
    key.set_timeout(duration).unwrap();

    thread::sleep(duration);
    thread::sleep(duration);

    let err = key.read().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYEXPIRED));

    let err = key.set_timeout(duration).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYEXPIRED));

    let err = key.invalidate().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYEXPIRED));

    let err = key_observer1.revoke().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYEXPIRED));

    keyring.unlink_key(&key_observer2).unwrap();

    keyring.invalidate().unwrap()
}

#[test]
fn expired_keyring() {
    let mut keyring = utils::new_test_keyring();
    let keyring_observer = keyring.clone();

    let duration = Duration::from_secs(1);
    keyring.set_timeout(duration).unwrap();

    thread::sleep(duration);
    thread::sleep(duration);

    let err = keyring.read().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYEXPIRED));

    let err = keyring.set_timeout(duration).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYEXPIRED));

    let err = keyring.invalidate().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYEXPIRED));

    let err = keyring_observer.revoke().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYEXPIRED));
}
