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

use std::sync::atomic;

use crate::{Key, Keyring, KeyringSerial, SpecialKeyring};

pub mod kernel;
pub mod keys;

// For testing, each test gets a new keyring attached to the Thread keyring. This makes sure tests
// don't interfere with each other, and keys are not prematurely garbage collected.
pub fn new_test_keyring() -> Keyring {
    let mut thread_keyring = Keyring::attach_or_create(SpecialKeyring::Thread).unwrap();

    static KEYRING_COUNT: atomic::AtomicUsize = atomic::AtomicUsize::new(0);
    let num = KEYRING_COUNT.fetch_add(1, atomic::Ordering::SeqCst);
    thread_keyring
        .add_keyring(format!("test:rust-keyutils{}", num))
        .unwrap()
}

unsafe fn invalid_serial() -> KeyringSerial {
    // Yes, we're explicitly breaking the NonZeroI32 rules here. However, it is not passing through
    // any bits which care (e.g., `Option`), so this is purely to test that using an invalid
    // keyring ID gives back `EINVAL` as expected.
    KeyringSerial::new_unchecked(0)
}

pub fn invalid_keyring() -> Keyring {
    unsafe { Keyring::new(invalid_serial()) }
}

pub fn invalid_key() -> Key {
    unsafe { Key::new(invalid_serial()) }
}

pub fn keyring_as_key(keyring: &Keyring) -> Key {
    unsafe { Key::new(keyring.serial()) }
}

pub fn key_as_keyring(key: &Key) -> Keyring {
    unsafe { Keyring::new(key.serial()) }
}

/// Keys are deleted asynchronously; describing the key succeeds until it has been garbage
/// collected.
pub fn wait_for_key_gc(key: &Key) {
    loop {
        match key.description() {
            Ok(_) => (),
            Err(errno::Errno(libc::ENOKEY)) => break,
            e @ Err(_) => {
                e.unwrap();
                unreachable!()
            },
        }
    }
}

/// Keys are deleted asynchronously; describing the key succeeds until it has been garbage
/// collected.
pub fn wait_for_keyring_gc(keyring: &Keyring) {
    loop {
        match keyring.read() {
            Ok(_) | Err(errno::Errno(libc::EACCES)) => (),
            Err(errno::Errno(libc::ENOKEY)) => break,
            e @ Err(_) => {
                e.unwrap();
                unreachable!()
            },
        }
    }
}
