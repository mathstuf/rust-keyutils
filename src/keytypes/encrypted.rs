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

//! Encrypted keys

use std::borrow::Cow;

use keytype::*;
use keytypes::AsciiHex;

/// Encrypted keys.
///
/// Encrypted keys are very similar to `Trusted` keys, however they do not require a TPM to
/// be used.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Encrypted;

impl KeyType for Encrypted {
    /// The format of the description depends on the format.
    ///
    /// For `ecryptfs`-format keys, the description must be a 16-character hexadecimal string.
    type Description = str;
    type Payload = Payload;

    fn name() -> &'static str {
        "encrypted"
    }
}

/// The format of the encrypted payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A free-form encrypted key.
    Default,
    /// A key for use with eCryptfs.
    ///
    /// Keys of this format must have a description of exactly 16 hexadecimal characters. The
    /// keylength must also be 64.
    Ecryptfs,
}

impl Format {
    /// The name of the key format.
    fn name(&self) -> &str {
        match *self {
            Format::Default => "default",
            Format::Ecryptfs => "ecryptfs",
        }
    }
}

impl Default for Format {
    fn default() -> Self {
        Format::Default
    }
}

/// The master key type.
///
/// This indicates the key type to use for encryting the generatetd key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasterKeyType {
    /// A trusted key.
    ///
    /// Trusted keys require a TPM.
    Trusted,
    /// A user key.
    ///
    /// Note that user keys are only as trustworthy as the code which loaded the key.
    User,
}

impl MasterKeyType {
    /// The name of the master key type.
    fn name(&self) -> &str {
        match *self {
            MasterKeyType::Trusted => "trusted",
            MasterKeyType::User => "user",
        }
    }
}

/// The payload for an encrypted key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// Create a new key.
    ///
    /// Use this with `add_key`.
    New {
        /// The format of the new key.
        format: Option<Format>,
        /// The type of key to use for encrypting the new key.
        keytype: MasterKeyType,
        /// The description of the key to use for encrypting the new key.
        description: Cow<'static, str>,
        /// The size of the key to generate.
        keylen: usize,
    },
    /// Load a blob into the key.
    ///
    /// Use this with `add_key`.
    Load {
        /// The blob to load into the key.
        blob: Vec<u8>,
    },
    /// Update a key.
    ///
    /// Use this with `update`. Note that `keytype` must be the same as the `keytype` when
    /// creating the key.
    Update {
        /// The type of key to use to encrypt the new key.
        ///
        /// Must be the same type as when the key was created.
        keytype: MasterKeyType,
        /// The description of the key to use for encrypting the new key.
        description: Cow<'static, str>,
    },
}

impl KeyPayload for Payload {
    fn payload(&self) -> Cow<[u8]> {
        let payload = match *self {
            Payload::New {
                ref format,
                ref keytype,
                ref description,
                ref keylen,
            } => {
                format!(
                    "new {} {}:{} {}",
                    format.unwrap_or_default().name(),
                    keytype.name(),
                    description,
                    keylen,
                )
            },
            Payload::Load {
                ref blob,
            } => format!("load {}", AsciiHex::convert(&blob)),
            Payload::Update {
                ref keytype,
                ref description,
            } => format!("update {}:{}", keytype.name(), description),
        };

        payload.bytes().collect()
    }
}
