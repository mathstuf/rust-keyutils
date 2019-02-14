// Copyright (c) 2015, Ben Boeckel
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

//! Trusted keys

use std::borrow::Cow;

use crates::itertools::Itertools;

use keytype::*;
use keytypes::AsciiHex;

/// Trusted keys are rooted in the TPM.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Trusted;

impl KeyType for Trusted {
    /// Trusted key descriptions are free-form.
    type Description = str;
    type Payload = Payload;

    fn name() -> &'static str {
        "trusted"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmHash {
    /// SHA-1
    Sha1,
    /// SHA-256
    ///
    /// Requires TPM2.
    Sha256,
    /// SHA-384
    ///
    /// Requires TPM2.
    Sha384,
    /// SHA-512
    ///
    /// Requires TPM2.
    Sha512,
    /// sm3-256
    ///
    /// Requires TPM2.
    Sm3_256,
}

impl TpmHash {
    fn name(self) -> &'static str {
        match self {
            TpmHash::Sha1 => "sha1",
            TpmHash::Sha256 => "sha256",
            TpmHash::Sha384 => "sha384",
            TpmHash::Sha512 => "sha512",
            TpmHash::Sm3_256 => "sm3-256",
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TrustedOptions {
    /// The ID of the sealing key to use.
    pub keyhandle: Option<u32>,
    /// The authorization for sealing keys.
    pub keyauth: Option<[u8; 20]>,
    /// The authorization for sealing data.
    pub blobauth: Option<[u8; 20]>,
    /// Platform Configuration Register (PCR) data.
    pub pcrinfo: Option<Vec<u8>>,
    /// The PCR number in the TPM to extend and lock the key.
    ///
    /// Only makes sense during a `Load` operation.
    pub pcrlock: Option<u32>,
    /// Whether the key may be resealed using new PCR value.
    ///
    /// Defaults to `true` if unspecified.
    pub migratable: Option<bool>,
    /// The hash algorithm to use.
    pub hash: Option<TpmHash>,
    /// The hash digest for the authorization policy.
    ///
    /// The digest must have been generated using the specified `TpmHash`.
    pub policydigest: Option<Vec<u8>>,
    /// The session handle for the policy.
    pub policyhandle: Option<u32>,
}

impl TrustedOptions {
    fn payload_string(&self) -> String {
        let parts = [
            // keyhandle=    ascii hex value of sealing key; default 40000000 (SRK)
            (
                "keyhandle",
                self.keyhandle
                    .as_ref()
                    .map(|v| AsciiHex::convert(&v.to_be().to_be_bytes())),
            ),
            // keyauth=      ascii hex auth for sealing key; default 00...
            //               (40 ascii zeros)
            (
                "keyauth",
                self.keyauth.as_ref().map(|v| AsciiHex::convert(v)),
            ),
            // blobauth=     ascii hex auth for sealed data; default 00...
            //               (40 ascii zeros)
            (
                "blobauth",
                self.blobauth.as_ref().map(|v| AsciiHex::convert(v)),
            ),
            // pcrinfo=      ascii hex of PCR_INFO or PCR_INFO_LONG (no default)
            (
                "pcrinfo",
                self.pcrinfo.as_ref().map(|v| AsciiHex::convert(&v)),
            ),
            // pcrlock=      pcr number to be extended to "lock" blob
            ("pcrlock", self.pcrlock.as_ref().map(|v| format!("{}", v))),
            // migratable=   0|1 indicating permission to reseal to new PCR values,
            //               default 1 (resealing allowed)
            (
                "migratable",
                self.migratable
                    .as_ref()
                    .map(|&v| if v { "1" } else { "0" }.to_string()),
            ),
            // hash=         hash algorithm name as a string. For TPM 1.x the only
            //               allowed value is sha1. For TPM 2.x the allowed values
            //               are sha1, sha256, sha384, sha512 and sm3-256.
            ("hash", self.hash.as_ref().map(|v| v.name().to_string())),
            // policydigest= digest for the authorization policy. must be calculated
            //               with the same hash algorithm as specified by the 'hash='
            //               option.
            (
                "policydigest",
                self.policydigest.as_ref().map(|v| AsciiHex::convert(&v)),
            ),
            // policyhandle= handle to an authorization policy session that defines the
            //               same policy and with the same hash algorithm as was used to
            //               seal the key.
            (
                "policyhandle",
                self.policyhandle
                    .as_ref()
                    .map(|v| AsciiHex::convert(&v.to_be().to_be_bytes())),
            ),
        ];

        let options = parts
            .iter()
            .filter_map(|(key, value)| value.as_ref().map(|value| format!("{}={}", key, value)))
            .format(" ");

        format!("{}", options)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// Create a new key.
    ///
    /// Use this with `add_key`.
    New {
        /// The size of the key to generate.
        keylen: usize,
        /// Options for the new key.
        options: TrustedOptions,
    },
    /// Load a blob into the TPM.
    ///
    /// Use this with `add_key`.
    Load {
        /// The blob to load into the TPM.
        blob: Vec<u8>,
        /// Options for loading.
        options: TrustedOptions,
    },
    /// Update a key.
    ///
    /// Use this with `update`.
    Update { options: TrustedOptions },
}

impl KeyPayload for Payload {
    fn payload(&self) -> Cow<[u8]> {
        let (command, blob, options) = match *self {
            Payload::New {
                ref keylen,
                ref options,
            } => ("new", format!("{}", keylen), options),
            Payload::Load {
                ref blob,
                ref options,
            } => ("load", AsciiHex::convert(&blob), options),
            Payload::Update {
                ref options,
            } => ("update", String::new(), options),
        };

        format!("{} {} {}", command, blob, options.payload_string())
            .bytes()
            .collect()
    }
}
