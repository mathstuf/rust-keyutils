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

use super::utils;

#[test]
fn invalid_key() {
    let key = utils::invalid_key();
    let err = key.revoke().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn invalid_keyring() {
    let keyring = utils::invalid_keyring();
    let err = keyring.revoke().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn unlinked_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("unlinked_key", payload)
        .unwrap();

    keyring.unlink_key(&key).unwrap();
    utils::wait_for_key_gc(&key);

    let err = key.revoke().unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn revoked_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("revoked_key", payload)
        .unwrap();
    let mut key_observer = key.clone();

    key.revoke().unwrap();

    let err = key_observer.description().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYREVOKED));

    let err = key_observer.read().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYREVOKED));

    let duration = Duration::from_secs(1);
    let err = key_observer.set_timeout(duration).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYREVOKED));

    let err = key_observer.invalidate().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYREVOKED));
}

#[test]
fn revoked_keyring() {
    let mut keyring = utils::new_test_keyring();
    let new_keyring = keyring.add_keyring("revoked_keyring").unwrap();
    let mut keyring_observer = new_keyring.clone();

    new_keyring.revoke().unwrap();

    let err = keyring_observer.read().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYREVOKED));

    let err = keyring_observer.description().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYREVOKED));

    let duration = Duration::from_secs(1);
    let err = keyring_observer.set_timeout(duration).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYREVOKED));

    let err = keyring_observer.invalidate().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EKEYREVOKED));
}
