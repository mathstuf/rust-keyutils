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
use crate::Keyring;

use super::utils;

#[test]
fn invalid_keyring() {
    let mut keyring = utils::invalid_keyring();
    let err = keyring.clear().unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn clear_non_keyring() {
    let mut keyring = utils::new_test_keyring();
    let key = keyring
        .add_key::<User, _, _>("clear_non_keyring", "payload".as_bytes())
        .unwrap();

    // Try clearing a non-keyring.
    let mut not_a_keyring = unsafe { Keyring::new(key.serial()) };
    let err = not_a_keyring.clear().unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOTDIR));

    keyring.unlink_key(&key).unwrap();
}

#[test]
fn clear_deleted_keyring() {
    let mut keyring = utils::new_test_keyring();
    let mut sub_keyring = keyring.add_keyring("clear_deleted_keyring").unwrap();

    keyring.unlink_keyring(&sub_keyring).unwrap();

    // Keys are deleted asynchronously; permissions are revoked until it is actually deleted.
    loop {
        let err = sub_keyring.clear().unwrap_err();
        if err == errno::Errno(libc::EACCES) {
            continue;
        }
        assert_eq!(err, errno::Errno(libc::ENOKEY));
        break;
    }
}

#[test]
fn clear_empty_keyring() {
    let mut keyring = utils::new_test_keyring();

    let (keys, keyrings) = keyring.read().unwrap();
    assert_eq!(keys.len(), 0);
    assert_eq!(keyrings.len(), 0);

    // Clear the keyring.
    keyring.clear().unwrap();

    let (keys, keyrings) = keyring.read().unwrap();
    assert_eq!(keys.len(), 0);
    assert_eq!(keyrings.len(), 0);
}

#[test]
fn clear_keyring_one_key() {
    let mut keyring = utils::new_test_keyring();

    let (keys, keyrings) = keyring.read().unwrap();
    assert_eq!(keys.len(), 0);
    assert_eq!(keyrings.len(), 0);

    let key_desc = "clear_keyring:key";

    // Create a key.
    let payload = "payload".as_bytes();
    keyring.add_key::<User, _, _>(key_desc, payload).unwrap();

    let (keys, keyrings) = keyring.read().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keyrings.len(), 0);

    assert_eq!(keys[0].description().unwrap().description, key_desc);

    // Clear the keyring.
    keyring.clear().unwrap();

    let (keys, keyrings) = keyring.read().unwrap();
    assert_eq!(keys.len(), 0);
    assert_eq!(keyrings.len(), 0);
}

#[test]
fn clear_keyring_many_keys() {
    let mut keyring = utils::new_test_keyring();

    let (keys, keyrings) = keyring.read().unwrap();
    assert_eq!(keys.len(), 0);
    assert_eq!(keyrings.len(), 0);

    let count = 40;
    let payload = "payload".as_bytes();
    let mut descs = Vec::with_capacity(count);
    for i in 0..count {
        let key_desc = format!("clear_keyring:key{:02}", i);

        // Create a key.
        keyring
            .add_key::<User, _, _>(key_desc.as_ref(), payload)
            .unwrap();
        descs.push(key_desc);
    }

    let (keys, keyrings) = keyring.read().unwrap();
    assert_eq!(keys.len(), count);
    assert_eq!(keyrings.len(), 0);

    let mut actual_descs = keys
        .iter()
        .map(|key| key.description().unwrap().description)
        .collect::<Vec<_>>();
    actual_descs.sort();
    assert_eq!(actual_descs, descs);

    // Clear the keyring.
    keyring.clear().unwrap();

    let (keys, keyrings) = keyring.read().unwrap();
    assert_eq!(keys.len(), 0);
    assert_eq!(keyrings.len(), 0);
}

#[test]
fn clear_keyring_keyring() {
    let mut keyring = utils::new_test_keyring();

    let (keys, keyrings) = keyring.read().unwrap();
    assert_eq!(keys.len(), 0);
    assert_eq!(keyrings.len(), 0);

    let keyring_desc = "clear_keyring:keyring";

    // Create a key.
    keyring.add_keyring(keyring_desc).unwrap();

    let (keys, keyrings) = keyring.read().unwrap();
    assert_eq!(keys.len(), 0);
    assert_eq!(keyrings.len(), 1);

    assert_eq!(keyrings[0].description().unwrap().description, keyring_desc);

    // Clear the keyring.
    keyring.clear().unwrap();

    let (keys, keyrings) = keyring.read().unwrap();
    assert_eq!(keys.len(), 0);
    assert_eq!(keyrings.len(), 0);
}
