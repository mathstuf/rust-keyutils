// Copyright (c) 2018, Ben Boeckel
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

//! Keytypes
//!
//! The Linux kernel supports many types of keys. They may be compiled out or available as
//! modules. The types provided here try to make it easier to use these keys.

use std::char;

pub mod asymmetric;
pub use self::asymmetric::Asymmetric;

pub mod big_key;
pub use self::big_key::BigKey;

pub mod blacklist;
pub use self::blacklist::Blacklist;

pub mod dns_resolver;
pub use self::dns_resolver::DnsResolver;

pub mod encrypted;
pub use self::encrypted::Encrypted;

pub mod keyring;
pub use self::keyring::Keyring;

pub mod logon;
pub use self::logon::Logon;

pub mod rxrpc;
pub use self::rxrpc::RxRPC;

pub mod rxrpc_s;
pub use self::rxrpc_s::RxRPCServer;

pub mod trusted;
pub use self::trusted::Trusted;

pub mod user;
pub use self::user::User;

/// A structure for assisting in coverting binary data into hexadecimal.
///
/// Many key types take in ASCII hexadecimal input instead of raw binary.
pub struct AsciiHex;

/// The mask for a nibble.
const NIBBLE_MASK: u8 = 0x0f;

impl AsciiHex {
    /// Convert binary data into an ASCII hexadecimal string.
    pub fn convert(data: &[u8]) -> String {
        data.iter()
            .fold(String::with_capacity(data.len() * 2), |mut string, byte| {
                let hi = (byte >> 4) & NIBBLE_MASK;
                let lo = byte & NIBBLE_MASK;

                string.push(char::from_digit(u32::from(hi), 16).unwrap());
                string.push(char::from_digit(u32::from(lo), 16).unwrap());

                string
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(input: &[u8], expected: &str) {
        assert_eq!(AsciiHex::convert(input), expected);
    }

    #[test]
    fn test_ascii_hex_convert() {
        check(&[0], "00");
        check(&[0, 1], "0001");
        check(&[222, 173, 190, 239], "deadbeef");
    }
}
