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

#[test]
fn invalid_keyring() {
    let mut keyring = utils::invalid_keyring();
    let err = keyring.add_keyring("invalid_keyring").unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn unlinked_keyring() {
    let mut keyring = utils::new_test_keyring();
    let mut unlinked_keyring = keyring.add_keyring("unlinked_keyring_unlinked").unwrap();

    keyring.unlink_keyring(&unlinked_keyring).unwrap();
    utils::wait_for_keyring_gc(&unlinked_keyring);

    let err = unlinked_keyring
        .add_keyring("unlinked_keyring")
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn not_a_keyring() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("not_a_keyring_key", payload)
        .unwrap();
    let mut not_a_keyring = utils::key_as_keyring(&key);

    let err = not_a_keyring.add_keyring("not_a_keyring").unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOTDIR));
}

#[test]
fn empty_keyring_description() {
    let mut keyring = utils::new_test_keyring();
    let err = keyring.add_keyring("").unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn max_keyring_description() {
    let mut keyring = utils::new_test_keyring();
    // Subtract one because the NUL is added in the kernel API.
    let maxdesc: String = iter::repeat('a').take(*PAGE_SIZE - 1).collect();
    let res = keyring.add_keyring(maxdesc.as_ref());
    // If the user's quota is smaller than this, it's an error.
    if KEY_INFO.maxbytes < *PAGE_SIZE {
        assert_eq!(res.unwrap_err(), errno::Errno(libc::EDQUOT));
    } else {
        let keyring = res.unwrap();
        assert_eq!(keyring.description().unwrap().description, maxdesc);
        keyring.invalidate().unwrap();
    }
}

#[test]
fn overlong_keyring_description() {
    let mut keyring = utils::new_test_keyring();
    // On MIPS with < 3.19, there is a bug where this is allowed. 3.19 was released in Feb 2015,
    // so this is being ignored here.
    let maxdesc: String = iter::repeat('a').take(*PAGE_SIZE).collect();
    let err = keyring.add_keyring(maxdesc.as_ref()).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn new_keyring() {
    let mut keyring = utils::new_test_keyring();
    let new_keyring = keyring.add_keyring("new_keyring").unwrap();

    let (keys, keyrings) = keyring.read().unwrap();
    assert_eq!(keys.len(), 0);
    assert_eq!(keyrings.len(), 1);
    assert_eq!(keyrings[0], new_keyring);
}

#[test]
fn duplicate_keyring_names() {
    let mut keyring = utils::new_test_keyring();
    let new_keyring1 = keyring.add_keyring("duplicate_keyring_names").unwrap();
    let new_keyring2 = keyring.add_keyring("duplicate_keyring_names").unwrap();

    // The keyring should have been displaced.
    assert_ne!(new_keyring1, new_keyring2);

    // The original keyring should not be in the parent keyring.
    let (keys, keyrings) = keyring.read().unwrap();
    assert!(keys.is_empty());
    assert_eq!(1, keyrings.len());
    assert_eq!(new_keyring2, keyrings[0]);

    utils::wait_for_keyring_gc(&new_keyring1);

    // It should be inaccessible.
    let err = new_keyring1.description().unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}
