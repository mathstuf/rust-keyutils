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
fn invalid_target() {
    let mut invalid_keyring = utils::invalid_keyring();
    let keyring = utils::new_test_keyring();

    let err = invalid_keyring.link_keyring(&keyring).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn invalid_source() {
    let invalid_keyring = utils::invalid_keyring();
    let mut keyring = utils::new_test_keyring();

    let err = keyring.link_keyring(&invalid_keyring).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn link_to_non_keyring() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let key = keyring
        .add_key::<User, _, _>("link_to_non_keyring", payload)
        .unwrap();
    let linked_key = keyring
        .add_key::<User, _, _>("link_to_non_keyring_linked", payload)
        .unwrap();
    let mut not_a_keyring = utils::key_as_keyring(&key);

    let err = not_a_keyring.link_key(&linked_key).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOTDIR));
}

#[test]
fn link_unlinked_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let key = keyring
        .add_key::<User, _, _>("link_unlinked_key", payload)
        .unwrap();
    let mut target_keyring = keyring.add_keyring("link_unlinked_key_target").unwrap();

    keyring.unlink_key(&key).unwrap();
    utils::wait_for_key_gc(&key);

    let err = target_keyring.link_key(&key).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn link_into_unlinked_keyring() {
    let mut keyring = utils::new_test_keyring();
    let payload = "payload".as_bytes();
    let key = keyring
        .add_key::<User, _, _>("link_into_unlinked_keyring", payload)
        .unwrap();
    let mut target_keyring = keyring
        .add_keyring("link_into_unlinked_keyring_target")
        .unwrap();

    keyring.unlink_keyring(&target_keyring).unwrap();
    utils::wait_for_keyring_gc(&target_keyring);

    let err = target_keyring.link_key(&key).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn link_self() {
    let mut keyring = utils::new_test_keyring();
    let keyring_observer = keyring.clone();

    let err = keyring.link_keyring(&keyring_observer).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EDEADLK));
}

#[test]
fn link_self_via_child() {
    let mut keyring = utils::new_test_keyring();
    let mut target_keyring = keyring.add_keyring("link_self_via_child").unwrap();

    let err = target_keyring.link_keyring(&keyring).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EDEADLK));
}

#[test]
fn link_self_via_child_chains() {
    let mut keyring = utils::new_test_keyring();
    let mut target_keyring = keyring.clone();
    let perms = Permission::POSSESSOR_ALL | Permission::USER_ALL;
    target_keyring.set_permissions(perms).unwrap();

    let maxdepth = 8;
    for depth in 1..maxdepth {
        let mut new_keyring = keyring
            .add_keyring(format!("link_self_via_child_chains{}", depth))
            .unwrap();
        new_keyring.set_permissions(perms).unwrap();

        target_keyring.link_keyring(&new_keyring).unwrap();
        target_keyring = new_keyring;

        let err = target_keyring.link_keyring(&keyring).unwrap_err();
        assert_eq!(err, errno::Errno(libc::EDEADLK));
    }

    let mut new_keyring = keyring
        .add_keyring(format!("link_self_via_child_chains{}", maxdepth))
        .unwrap();
    new_keyring.set_permissions(perms).unwrap();

    target_keyring.link_keyring(&new_keyring).unwrap();
    keyring.unlink_keyring(&new_keyring).unwrap();
    target_keyring = new_keyring;

    let err = target_keyring.link_keyring(&keyring).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ELOOP));
}

#[test]
fn link_self_via_keyring_stacks() {
    let mut keyring = utils::new_test_keyring();
    let keyring_a_root = keyring
        .add_keyring("link_self_via_keyring_stacks_a")
        .unwrap();
    let keyring_b_root = keyring
        .add_keyring("link_self_via_keyring_stacks_b")
        .unwrap();
    let mut keyring_a = keyring_a_root.clone();
    let mut keyring_b = keyring_b_root.clone();

    let maxdepth = 4;
    for depth in 1..maxdepth {
        keyring_a = keyring_a
            .add_keyring(format!("link_self_via_keyring_stacks_a{}", depth))
            .unwrap();
        keyring_b = keyring_b
            .add_keyring(format!("link_self_via_keyring_stacks_b{}", depth))
            .unwrap();
    }

    keyring_b.link_keyring(&keyring_a_root).unwrap();

    let err = keyring_a.link_keyring(&keyring_b_root).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EDEADLK));

    keyring_b.unlink_keyring(&keyring_a_root).unwrap();

    keyring_a.link_keyring(&keyring_b_root).unwrap();

    let err = keyring_b.link_keyring(&keyring_a_root).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EDEADLK));
}

#[test]
fn link_self_via_keyring_deep_stacks() {
    let mut keyring = utils::new_test_keyring();
    let keyring_a_root = keyring
        .add_keyring("link_self_via_keyring_deep_stacks_a")
        .unwrap();
    let keyring_b_root = keyring
        .add_keyring("link_self_via_keyring_deep_stacks_b")
        .unwrap();
    let mut keyring_a = keyring_a_root.clone();
    let mut keyring_b = keyring_b_root.clone();

    let maxdepth = 5;
    for depth in 1..maxdepth {
        keyring_a = keyring_a
            .add_keyring(format!("link_self_via_keyring_deep_stacks_a{}", depth))
            .unwrap();
        keyring_b = keyring_b
            .add_keyring(format!("link_self_via_keyring_deep_stacks_b{}", depth))
            .unwrap();
    }

    keyring_b.link_keyring(&keyring_a_root).unwrap();

    let err = keyring_a.link_keyring(&keyring_b_root).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ELOOP));

    keyring_b.unlink_keyring(&keyring_a_root).unwrap();

    keyring_a.link_keyring(&keyring_b_root).unwrap();

    let err = keyring_b.link_keyring(&keyring_a_root).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ELOOP));
}

#[test]
fn multiply_link_key_into_keyring() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("multiply_link_key_into_keyring")
        .unwrap();

    let (keys, keyrings) = keyring.read().unwrap();
    assert!(keys.is_empty());
    assert_eq!(keyrings.len(), 1);
    assert_eq!(keyrings[0], new_keyring);

    let payload = "payload".as_bytes();
    let key = new_keyring
        .add_key::<User, _, _>("multiply_link_key_into_keyring_key", payload)
        .unwrap();

    let (keys, keyrings) = new_keyring.read().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], key);
    assert!(keyrings.is_empty());

    keyring.link_key(&key).unwrap();

    let (keys, keyrings) = keyring.read().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], key);
    assert_eq!(keyrings.len(), 1);
    assert_eq!(keyrings[0], new_keyring);

    // Linking the same key should not change the result.
    keyring.link_key(&key).unwrap();

    let (keys, keyrings) = keyring.read().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], key);
    assert_eq!(keyrings.len(), 1);
    assert_eq!(keyrings[0], new_keyring);
}

#[test]
fn multiply_link_keyring_into_keyring() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("multiply_link_keyring_into_keyring")
        .unwrap();

    let (keys, keyrings) = keyring.read().unwrap();
    assert!(keys.is_empty());
    assert_eq!(keyrings.len(), 1);
    assert_eq!(keyrings[0], new_keyring);

    let inner_keyring = new_keyring
        .add_keyring("multiply_link_keyring_into_keyring_keyring_inner")
        .unwrap();

    let (keys, keyrings) = new_keyring.read().unwrap();
    assert!(keys.is_empty());
    assert_eq!(keyrings.len(), 1);
    assert_eq!(keyrings[0], inner_keyring);

    keyring.link_keyring(&inner_keyring).unwrap();

    let (keys, keyrings) = keyring.read().unwrap();
    assert!(keys.is_empty());
    assert_eq!(keyrings.len(), 2);
    assert_eq!(keyrings[0], new_keyring);
    assert_eq!(keyrings[1], inner_keyring);

    // Linking the same keyring should not change the result.
    keyring.link_keyring(&inner_keyring).unwrap();

    let (keys, keyrings) = keyring.read().unwrap();
    assert!(keys.is_empty());
    assert_eq!(keyrings.len(), 2);
    assert_eq!(keyrings[0], new_keyring);
    assert_eq!(keyrings[1], inner_keyring);
}
