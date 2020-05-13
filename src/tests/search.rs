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
use crate::Permission;

use super::utils;
use super::utils::kernel::*;
use super::utils::keys::*;

#[test]
fn empty_key_type() {
    let keyring = utils::new_test_keyring();

    let err = keyring
        .search_for_key::<EmptyKey, _, _>("empty_key_type", None)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn unsupported_key_type() {
    let keyring = utils::new_test_keyring();

    let err = keyring
        .search_for_key::<UnsupportedKey, _, _>("unsupported_key_type", None)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn invalid_key_type() {
    let keyring = utils::new_test_keyring();

    let err = keyring
        .search_for_key::<InvalidKey, _, _>("invalid_key_type", None)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::EPERM));
}

#[test]
fn max_key_type() {
    let keyring = utils::new_test_keyring();

    let err = keyring
        .search_for_key::<MaxLenKey, _, _>("invalid_key_type", None)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn overlong_key_type() {
    let keyring = utils::new_test_keyring();

    let err = keyring
        .search_for_key::<OverlongKey, _, _>("overlong_key_type", None)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn max_user_description() {
    let keyring = utils::new_test_keyring();

    // Subtract one because the NUL is added in the kernel API.
    let maxdesc: String = iter::repeat('a').take(*PAGE_SIZE - 1).collect();
    let err = keyring
        .search_for_key::<User, _, _>(maxdesc, None)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn overlong_user_description() {
    let keyring = utils::new_test_keyring();

    // On MIPS with < 3.19, there is a bug where this is allowed. 3.19 was released in Feb 2015,
    // so this is being ignored here.
    let maxdesc: String = iter::repeat('a').take(*PAGE_SIZE).collect();
    let err = keyring
        .search_for_key::<User, _, _>(maxdesc, None)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn invalid_keyring() {
    let keyring = utils::invalid_keyring();

    let err = keyring
        .search_for_key::<User, _, _>("invalid_keyring", None)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn search_key() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("search_key", payload)
        .unwrap();
    let not_a_keyring = utils::key_as_keyring(&key);

    let err = not_a_keyring
        .search_for_key::<User, _, _>("search_key", None)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOTDIR));
}

#[test]
fn search_key_no_result() {
    let keyring = utils::new_test_keyring();

    let err = keyring
        .search_for_key::<User, _, _>("search_key_no_result", None)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn search_keyring_no_result() {
    let keyring = utils::new_test_keyring();

    let err = keyring
        .search_for_keyring("search_keyring_no_result", None)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn search_key_mismatched_type() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring.add_keyring("search_key_mismatched_type").unwrap();
    let description = "search_key_mismatched_type_keyring";
    let _ = new_keyring.add_keyring(description).unwrap();

    let err = keyring
        .search_for_key::<User, _, _>(description, None)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn search_keyring_mismatched_type() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("search_keyring_mismatched_type")
        .unwrap();
    let description = "search_keyring_mismatched_type_key";
    let payload = &b"payload"[..];
    let _ = new_keyring
        .add_key::<User, _, _>(description, payload)
        .unwrap();

    let err = keyring.search_for_keyring(description, None).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn search_and_find_key() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring.add_keyring("search_and_find_key").unwrap();
    let description = "search_and_find_key_key";
    let payload = &b"payload"[..];
    let key = new_keyring
        .add_key::<User, _, _>(description, payload)
        .unwrap();

    let found_key = keyring
        .search_for_key::<User, _, _>(description, None)
        .unwrap();
    assert_eq!(found_key, key);

    let actual_payload = key.read().unwrap();
    assert_eq!(payload, actual_payload.as_slice());
}

#[test]
fn search_and_find_keyring() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring.add_keyring("search_and_find_keyring").unwrap();
    let description = "search_and_find_keyring_keyring";
    let target_keyring = new_keyring.add_keyring(description).unwrap();

    let found_keyring = keyring.search_for_keyring(description, None).unwrap();
    assert_eq!(found_keyring, target_keyring);
}

#[test]
fn search_and_find_key_no_search_perm_interm() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("search_and_find_key_no_search_perm_interm")
        .unwrap();
    let description = "search_and_find_key_no_search_perm_interm_key";
    let payload = &b"payload"[..];
    let _ = new_keyring
        .add_key::<User, _, _>(description, payload)
        .unwrap();

    let perms = {
        let mut orig_perms = new_keyring.description().unwrap().perms;
        orig_perms.remove(Permission::POSSESSOR_SEARCH);
        orig_perms.remove(Permission::USER_SEARCH);
        orig_perms.remove(Permission::GROUP_SEARCH);
        orig_perms.remove(Permission::OTHER_SEARCH);
        orig_perms
    };
    new_keyring.set_permissions(perms).unwrap();

    let err = keyring
        .search_for_key::<User, _, _>(description, None)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn search_and_find_keyring_no_search_perm_interm() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("search_and_find_keyring_no_search_perm_interm")
        .unwrap();
    let description = "search_and_find_keyring_no_search_perm_interm_keyring";
    let _ = new_keyring.add_keyring(description).unwrap();

    let perms = {
        let mut orig_perms = new_keyring.description().unwrap().perms;
        orig_perms.remove(Permission::POSSESSOR_SEARCH);
        orig_perms.remove(Permission::USER_SEARCH);
        orig_perms.remove(Permission::GROUP_SEARCH);
        orig_perms.remove(Permission::OTHER_SEARCH);
        orig_perms
    };
    new_keyring.set_permissions(perms).unwrap();

    let err = keyring.search_for_keyring(description, None).unwrap_err();
    assert_eq!(err, errno::Errno(libc::ENOKEY));
}

#[test]
fn search_and_find_key_no_search_perm_direct() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("search_and_find_key_no_search_perm_direct")
        .unwrap();
    let description = "search_and_find_key_no_search_perm_direct_key";
    let payload = &b"payload"[..];
    let mut key = new_keyring
        .add_key::<User, _, _>(description, payload)
        .unwrap();

    let perms = {
        let mut orig_perms = key.description().unwrap().perms;
        orig_perms.remove(Permission::POSSESSOR_SEARCH);
        orig_perms.remove(Permission::USER_SEARCH);
        orig_perms.remove(Permission::GROUP_SEARCH);
        orig_perms.remove(Permission::OTHER_SEARCH);
        orig_perms
    };
    key.set_permissions(perms).unwrap();

    let err = keyring
        .search_for_key::<User, _, _>(description, None)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::EACCES));
}

#[test]
fn search_and_find_keyring_no_search_perm_direct() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("search_and_find_keyring_no_search_perm_direct")
        .unwrap();
    let description = "search_and_find_keyring_no_search_perm_direct_keyring";
    let mut target_keyring = new_keyring.add_keyring(description).unwrap();

    let perms = {
        let mut orig_perms = target_keyring.description().unwrap().perms;
        orig_perms.remove(Permission::POSSESSOR_SEARCH);
        orig_perms.remove(Permission::USER_SEARCH);
        orig_perms.remove(Permission::GROUP_SEARCH);
        orig_perms.remove(Permission::OTHER_SEARCH);
        orig_perms
    };
    target_keyring.set_permissions(perms).unwrap();

    let err = keyring.search_for_keyring(description, None).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EACCES));
}

#[test]
fn search_and_find_key_link() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring.add_keyring("search_and_find_key_link").unwrap();
    let mut destination_keyring = keyring
        .add_keyring("search_and_find_key_link_destination")
        .unwrap();
    let description = "search_and_find_key_link_key";
    let payload = &b"payload"[..];
    let key = new_keyring
        .add_key::<User, _, _>(description, payload)
        .unwrap();

    let (keys, keyrings) = destination_keyring.read().unwrap();
    assert!(keys.is_empty());
    assert!(keyrings.is_empty());

    let found_key = keyring
        .search_for_key::<User, _, _>(description, &mut destination_keyring)
        .unwrap();
    assert_eq!(found_key, key);

    let actual_payload = key.read().unwrap();
    assert_eq!(payload, actual_payload.as_slice());

    let (keys, keyrings) = destination_keyring.read().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], key);
    assert!(keyrings.is_empty());
}

#[test]
fn search_and_find_keyring_link() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring.add_keyring("search_and_find_keyring_link").unwrap();
    let mut destination_keyring = keyring
        .add_keyring("search_and_find_keyring_link_destination")
        .unwrap();
    let description = "search_and_find_keyring_link_keyring";
    let target_keyring = new_keyring.add_keyring(description).unwrap();

    let (keys, keyrings) = destination_keyring.read().unwrap();
    assert!(keys.is_empty());
    assert!(keyrings.is_empty());

    let found_keyring = keyring
        .search_for_keyring(description, &mut destination_keyring)
        .unwrap();
    assert_eq!(found_keyring, target_keyring);

    let (keys, keyrings) = destination_keyring.read().unwrap();
    assert!(keys.is_empty());
    assert_eq!(keyrings.len(), 1);
    assert_eq!(keyrings[0], target_keyring);
}

#[test]
fn search_and_find_key_link_replace() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("search_and_find_key_link_replace")
        .unwrap();
    let mut destination_keyring = keyring
        .add_keyring("search_and_find_key_link_replace_destination")
        .unwrap();
    let description = "search_and_find_key_link_replace_key";
    let payload = &b"payload"[..];
    let key = new_keyring
        .add_key::<User, _, _>(description, payload)
        .unwrap();
    let other_payload = &b"payload"[..];
    let orig_key = destination_keyring
        .add_key::<User, _, _>(description, other_payload)
        .unwrap();

    let (keys, keyrings) = destination_keyring.read().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], orig_key);
    assert!(keyrings.is_empty());

    let found_key = keyring
        .search_for_key::<User, _, _>(description, &mut destination_keyring)
        .unwrap();
    assert_eq!(found_key, key);

    let actual_payload = key.read().unwrap();
    assert_eq!(payload, actual_payload.as_slice());

    // The original key should have been replaced.
    let (keys, keyrings) = destination_keyring.read().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], key);
    assert!(keyrings.is_empty());
}

#[test]
fn search_and_find_key_link_replace_keyring() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("search_and_find_key_link_replace_keyring")
        .unwrap();
    let mut destination_keyring = keyring
        .add_keyring("search_and_find_key_link_replace_keyring_destination")
        .unwrap();
    let description = "search_and_find_key_link_replace_keyring_key";
    let payload = &b"payload"[..];
    let key = new_keyring
        .add_key::<User, _, _>(description, payload)
        .unwrap();
    let orig_keyring = destination_keyring.add_keyring(description).unwrap();

    let (keys, keyrings) = destination_keyring.read().unwrap();
    assert!(keys.is_empty());
    assert_eq!(keyrings.len(), 1);
    assert_eq!(keyrings[0], orig_keyring);

    let found_key = keyring
        .search_for_key::<User, _, _>(description, &mut destination_keyring)
        .unwrap();
    assert_eq!(found_key, key);

    let actual_payload = key.read().unwrap();
    assert_eq!(payload, actual_payload.as_slice());

    // The original keyring should not have been replaced.
    let (keys, keyrings) = destination_keyring.read().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], key);
    assert_eq!(keyrings.len(), 1);
    assert_eq!(keyrings[0], orig_keyring);
}

#[test]
fn search_and_find_keyring_link_replace() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("search_and_find_keyring_link_replace")
        .unwrap();
    let mut destination_keyring = keyring
        .add_keyring("search_and_find_keyring_link_replace_destination")
        .unwrap();
    let description = "search_and_find_keyring_link_replace_keyring";
    let target_keyring = new_keyring.add_keyring(description).unwrap();
    let orig_keyring = destination_keyring.add_keyring(description).unwrap();

    let (keys, keyrings) = destination_keyring.read().unwrap();
    assert!(keys.is_empty());
    assert_eq!(keyrings.len(), 1);
    assert_eq!(keyrings[0], orig_keyring);

    let found_keyring = keyring
        .search_for_keyring(description, &mut destination_keyring)
        .unwrap();
    assert_eq!(found_keyring, target_keyring);

    // The original keyring should have been replaced.
    let (keys, keyrings) = destination_keyring.read().unwrap();
    assert!(keys.is_empty());
    assert_eq!(keyrings.len(), 1);
    assert_eq!(keyrings[0], target_keyring);
}

#[test]
fn search_and_find_keyring_link_replace_key() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("search_and_find_keyring_link_replace_key")
        .unwrap();
    let mut destination_keyring = keyring
        .add_keyring("search_and_find_keyring_link_replace_key_destination")
        .unwrap();
    let description = "search_and_find_keyring_link_replace_key_keyring";
    let target_keyring = new_keyring.add_keyring(description).unwrap();
    let payload = &b"payload"[..];
    let orig_key = destination_keyring
        .add_key::<User, _, _>(description, payload)
        .unwrap();

    let (keys, keyrings) = destination_keyring.read().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], orig_key);
    assert!(keyrings.is_empty());

    let found_keyring = keyring
        .search_for_keyring(description, &mut destination_keyring)
        .unwrap();
    assert_eq!(found_keyring, target_keyring);

    // The original keyring should not have been replaced.
    let (keys, keyrings) = destination_keyring.read().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0], orig_key);
    assert_eq!(keyrings.len(), 1);
    assert_eq!(keyrings[0], target_keyring);
}

#[test]
fn search_and_find_key_no_link_perm_no_dest() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("search_and_find_key_no_link_perm_no_dest")
        .unwrap();
    let description = "search_and_find_key_no_link_perm_no_dest_key";
    let payload = &b"payload"[..];
    let mut key = new_keyring
        .add_key::<User, _, _>(description, payload)
        .unwrap();

    let perms = {
        let mut orig_perms = key.description().unwrap().perms;
        orig_perms.remove(Permission::POSSESSOR_LINK);
        orig_perms.remove(Permission::USER_LINK);
        orig_perms.remove(Permission::GROUP_LINK);
        orig_perms.remove(Permission::OTHER_LINK);
        orig_perms
    };
    key.set_permissions(perms).unwrap();

    let found_key = keyring
        .search_for_key::<User, _, _>(description, None)
        .unwrap();
    assert_eq!(found_key, key);

    let actual_payload = key.read().unwrap();
    assert_eq!(payload, actual_payload.as_slice());
}

#[test]
fn search_and_find_keyring_no_link_perm_no_dest() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("search_and_find_keyring_no_link_perm_no_dest")
        .unwrap();
    let description = "search_and_find_keyring_no_link_perm_no_dest_keyring";
    let mut target_keyring = new_keyring.add_keyring(description).unwrap();

    let perms = {
        let mut orig_perms = target_keyring.description().unwrap().perms;
        orig_perms.remove(Permission::POSSESSOR_LINK);
        orig_perms.remove(Permission::USER_LINK);
        orig_perms.remove(Permission::GROUP_LINK);
        orig_perms.remove(Permission::OTHER_LINK);
        orig_perms
    };
    target_keyring.set_permissions(perms).unwrap();

    let found_keyring = keyring.search_for_keyring(description, None).unwrap();
    assert_eq!(found_keyring, target_keyring);
}

#[test]
fn search_and_find_key_no_link_perm() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("search_and_find_key_no_link_perm")
        .unwrap();
    let mut destination_keyring = keyring
        .add_keyring("search_and_find_key_no_link_perm_destination")
        .unwrap();
    let description = "search_and_find_key_no_link_perm_key";
    let payload = &b"payload"[..];
    let mut key = new_keyring
        .add_key::<User, _, _>(description, payload)
        .unwrap();

    let perms = {
        let mut orig_perms = key.description().unwrap().perms;
        orig_perms.remove(Permission::POSSESSOR_LINK);
        orig_perms.remove(Permission::USER_LINK);
        orig_perms.remove(Permission::GROUP_LINK);
        orig_perms.remove(Permission::OTHER_LINK);
        orig_perms
    };
    key.set_permissions(perms).unwrap();

    let err = keyring
        .search_for_key::<User, _, _>(description, &mut destination_keyring)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::EACCES));

    // Assert that it was not linked to the destination keyring.
    let (keys, keyrings) = destination_keyring.read().unwrap();
    assert!(keys.is_empty());
    assert!(keyrings.is_empty());
}

#[test]
fn search_and_find_keyring_no_link_perm() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("search_and_find_keyring_no_link_perm")
        .unwrap();
    let mut destination_keyring = keyring
        .add_keyring("search_and_find_keyring_no_link_perm_destination")
        .unwrap();
    let description = "search_and_find_keyring_no_link_perm_keyring";
    let mut target_keyring = new_keyring.add_keyring(description).unwrap();

    let perms = {
        let mut orig_perms = target_keyring.description().unwrap().perms;
        orig_perms.remove(Permission::POSSESSOR_LINK);
        orig_perms.remove(Permission::USER_LINK);
        orig_perms.remove(Permission::GROUP_LINK);
        orig_perms.remove(Permission::OTHER_LINK);
        orig_perms
    };
    target_keyring.set_permissions(perms).unwrap();

    let err = keyring
        .search_for_keyring(description, &mut destination_keyring)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::EACCES));

    // Assert that it was not linked to the destination keyring.
    let (keys, keyrings) = destination_keyring.read().unwrap();
    assert!(keys.is_empty());
    assert!(keyrings.is_empty());
}

#[test]
fn search_and_find_key_no_write_perm() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("search_and_find_key_no_write_perm")
        .unwrap();
    let mut destination_keyring = keyring
        .add_keyring("search_and_find_key_no_write_perm_destination")
        .unwrap();
    let description = "search_and_find_key_no_write_perm_key";
    let payload = &b"payload"[..];
    let _ = new_keyring
        .add_key::<User, _, _>(description, payload)
        .unwrap();

    let perms = {
        let mut orig_perms = destination_keyring.description().unwrap().perms;
        orig_perms.remove(Permission::POSSESSOR_WRITE);
        orig_perms.remove(Permission::USER_WRITE);
        orig_perms.remove(Permission::GROUP_WRITE);
        orig_perms.remove(Permission::OTHER_WRITE);
        orig_perms
    };
    destination_keyring.set_permissions(perms).unwrap();

    let err = keyring
        .search_for_key::<User, _, _>(description, &mut destination_keyring)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::EACCES));

    // Assert that it was not linked to the destination keyring.
    let (keys, keyrings) = destination_keyring.read().unwrap();
    assert!(keys.is_empty());
    assert!(keyrings.is_empty());
}

#[test]
fn search_and_find_keyring_no_write_perm() {
    let mut keyring = utils::new_test_keyring();
    let mut new_keyring = keyring
        .add_keyring("search_and_find_keyring_no_write_perm")
        .unwrap();
    let mut destination_keyring = keyring
        .add_keyring("search_and_find_keyring_no_write_perm_destination")
        .unwrap();
    let description = "search_and_find_keyring_no_write_perm_keyring";
    let _ = new_keyring.add_keyring(description).unwrap();

    let perms = {
        let mut orig_perms = destination_keyring.description().unwrap().perms;
        orig_perms.remove(Permission::POSSESSOR_WRITE);
        orig_perms.remove(Permission::USER_WRITE);
        orig_perms.remove(Permission::GROUP_WRITE);
        orig_perms.remove(Permission::OTHER_WRITE);
        orig_perms
    };
    destination_keyring.set_permissions(perms).unwrap();

    let err = keyring
        .search_for_keyring(description, &mut destination_keyring)
        .unwrap_err();
    assert_eq!(err, errno::Errno(libc::EACCES));

    // Assert that it was not linked to the destination keyring.
    let (keys, keyrings) = destination_keyring.read().unwrap();
    assert!(keys.is_empty());
    assert!(keyrings.is_empty());
}
