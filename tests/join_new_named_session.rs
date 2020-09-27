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

use keyutils::keytypes;
use keyutils::{KeyType, Keyring, Permission, SpecialKeyring};

fn getuid() -> libc::uid_t {
    unsafe { libc::getuid() }
}

fn getgid() -> libc::gid_t {
    unsafe { libc::getgid() }
}

#[test]
fn join_new_named_session() {
    let session_before = Keyring::attach_or_create(SpecialKeyring::Session).unwrap();
    let name = "join_new_named_session";
    let keyring = Keyring::join_session(name).unwrap();
    let session_after = Keyring::attach_or_create(SpecialKeyring::Session).unwrap();

    assert_ne!(session_before, keyring);
    assert_eq!(session_after, keyring);

    let desc = keyring.description().unwrap();
    assert_eq!(desc.type_, keytypes::Keyring::name());
    assert_eq!(desc.uid, getuid());
    assert_eq!(desc.gid, getgid());
    assert_eq!(
        desc.perms,
        Permission::POSSESSOR_ALL
            | Permission::USER_VIEW
            | Permission::USER_READ
            | Permission::USER_LINK
    );
    assert_eq!(desc.description, name);

    keyring.invalidate().unwrap()
}
