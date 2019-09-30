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

use std::iter;

use crate::keytypes::User;

use super::utils;
use super::utils::kernel::*;
use super::utils::keys::*;

#[test]
fn empty_key_type() {
    let mut keyring = utils::new_test_keyring();
    let err = keyring.add_key::<EmptyKey, _, _>("", ()).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));

    keyring.invalidate().unwrap()
}

#[test]
fn unsupported_key_type() {
    let mut keyring = utils::new_test_keyring();
    let err = keyring.add_key::<UnsupportedKey, _, _>("", ()).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENODEV));

    keyring.invalidate().unwrap()
}

#[test]
fn invalid_key_type() {
    let mut keyring = utils::new_test_keyring();
    let err = keyring.add_key::<InvalidKey, _, _>("", ()).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EPERM));

    keyring.invalidate().unwrap()
}

#[test]
fn maxlen_key_type() {
    let mut keyring = utils::new_test_keyring();
    let err = keyring.add_key::<MaxLenKey, _, _>("", ()).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENODEV));

    keyring.invalidate().unwrap()
}

#[test]
fn overlong_key_type() {
    let mut keyring = utils::new_test_keyring();
    let err = keyring.add_key::<OverlongKey, _, _>("", ()).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));

    keyring.invalidate().unwrap()
}

#[test]
fn keyring_with_payload() {
    let mut keyring = utils::new_test_keyring();
    let err = keyring
        .add_key::<KeyringShadow, _, _>("", "payload")
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));

    keyring.invalidate().unwrap()
}

#[test]
fn max_user_description() {
    let mut keyring = utils::new_test_keyring();
    // Subtract one because the NUL is added in the kernel API.
    let maxdesc: String = iter::repeat('a').take(*PAGE_SIZE - 1).collect();
    let res = keyring.add_key::<User, _, _>(maxdesc.as_ref(), "payload".as_bytes());
    // If the user's quota is smaller than this, it's an error.
    if KEY_INFO.maxbytes < *PAGE_SIZE {
        assert_eq!(res.unwrap_err(), errno::Errno(libc::EDQUOT));
    } else {
        let key = res.unwrap();
        assert_eq!(key.description().unwrap().description, maxdesc);
        key.invalidate().unwrap();
    }

    keyring.invalidate().unwrap()
}

#[test]
fn overlong_user_description() {
    let mut keyring = utils::new_test_keyring();
    // On MIPS with < 3.19, there is a bug where this is allowed. 3.19 was released in Feb 2015,
    // so this is being ignored here.
    let toolarge: String = iter::repeat('a').take(*PAGE_SIZE).collect();
    let err = keyring
        .add_key::<User, _, _>(toolarge.as_ref(), "payload".as_bytes())
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));

    keyring.invalidate().unwrap()
}

#[test]
fn invalid_keyring() {
    let mut keyring = utils::invalid_keyring();
    let err = keyring
        .add_key::<User, _, _>("invalid_keyring", "payload".as_bytes())
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn add_key_to_non_keyring() {
    let mut keyring = utils::new_test_keyring();
    let expected = "stuff".as_bytes();
    let key = keyring
        .add_key::<User, _, _>("add_key_to_non_keyring", expected)
        .unwrap();

    let mut not_a_keyring = utils::key_as_keyring(&key);
    let err = not_a_keyring
        .add_key::<User, _, _>("add_key_to_non_keyring", expected)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOTDIR));

    keyring.invalidate().unwrap()
}

#[test]
fn add_keyring_to_non_keyring() {
    let mut keyring = utils::new_test_keyring();
    let expected = "stuff".as_bytes();
    let key = keyring
        .add_key::<User, _, _>("add_keyring_to_non_keyring", expected)
        .unwrap();

    let mut not_a_keyring = utils::key_as_keyring(&key);
    let err = not_a_keyring
        .add_keyring("add_keyring_to_non_keyring")
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOTDIR));

    keyring.invalidate().unwrap()
}

#[test]
fn add_key() {
    let mut keyring = utils::new_test_keyring();

    let payload = "payload".as_bytes();
    let key = keyring.add_key::<User, _, _>("add_key", payload).unwrap();
    assert_eq!(key.read().unwrap(), payload);

    keyring.invalidate().unwrap()
}

#[test]
fn add_keyring() {
    let mut keyring = utils::new_test_keyring();
    let new_keyring = keyring.add_keyring("add_keyring").unwrap();

    let (keys, keyrings) = new_keyring.read().unwrap();
    assert!(keys.is_empty());
    assert!(keyrings.is_empty());

    keyring.invalidate().unwrap()
}

#[test]
fn add_key_replace() {
    let mut keyring = utils::new_test_keyring();

    let description = "add_key_replace";

    let payload = "payload".as_bytes();
    let key = keyring.add_key::<User, _, _>(description, payload).unwrap();
    assert_eq!(key.read().unwrap(), payload);

    let payload = "updated_payload".as_bytes();
    let key_updated = keyring.add_key::<User, _, _>(description, payload).unwrap();
    assert_eq!(key, key_updated);
    assert_eq!(key.read().unwrap(), payload);
    assert_eq!(key_updated.read().unwrap(), payload);

    keyring.invalidate().unwrap()
}

#[test]
fn add_keyring_replace() {
    let mut keyring = utils::new_test_keyring();

    let description = "add_keyring_replace";
    let new_keyring = keyring.add_keyring(description).unwrap();

    let (keys, keyrings) = new_keyring.read().unwrap();
    assert!(keys.is_empty());
    assert!(keyrings.is_empty());

    let updated_keyring = keyring.add_keyring(description).unwrap();
    assert_ne!(new_keyring, updated_keyring);

    let (keys, keyrings) = updated_keyring.read().unwrap();
    assert!(keys.is_empty());
    assert!(keyrings.is_empty());

    keyring.invalidate().unwrap()
}
