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
fn keyring() {
    let keyring = utils::new_test_keyring();
    let mut key = utils::keyring_as_key(&keyring);

    let payload = "payload".as_bytes();
    let err = key.update(payload).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EOPNOTSUPP));
}

#[test]
fn invalid_key() {
    let mut key = utils::invalid_key();

    let payload = "payload".as_bytes();
    let err = key.update(payload).unwrap_err();
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

    let payload = "payload".as_bytes();
    let err = key.update(payload).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn user_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let mut key = keyring.add_key::<User, _, _>("user_key", payload).unwrap();

    let actual_payload = key.read().unwrap();
    assert_eq!(payload, actual_payload.as_slice());

    let payload = "updated_payload".as_bytes();
    key.update(payload).unwrap();

    let actual_payload = key.read().unwrap();
    assert_eq!(payload, actual_payload.as_slice());
}
