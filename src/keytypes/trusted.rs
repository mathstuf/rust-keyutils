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
use std::fmt;

use super::ByteBuf;
use crate::keytype::*;

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

/// Hashes supported by TPM devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// #[non_exhaustive]
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

/// Options for trusted keys.
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

impl fmt::Display for TrustedOptions {
    /// Formats the options that are present. Starts with a leading space.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(keyhandle) = self.keyhandle {
            // keyhandle=    ascii hex value of sealing key; default 40000000 (SRK)
            write!(f, " keyhandle={:x}", keyhandle)?;
        }
        if let Some(keyauth) = self.keyauth.as_ref() {
            // keyauth=      ascii hex auth for sealing key; default 00...
            //               (40 ascii zeros)
            write!(f, " keyauth={:x}", ByteBuf(keyauth))?;
        }
        if let Some(blobauth) = self.blobauth.as_ref() {
            // blobauth=     ascii hex auth for sealed data; default 00...
            //               (40 ascii zeros)
            write!(f, " blobauth={:x}", ByteBuf(blobauth))?;
        }
        if let Some(pcrinfo) = self.pcrinfo.as_ref() {
            // pcrinfo=      ascii hex of PCR_INFO or PCR_INFO_LONG (no default)
            write!(f, " pcrinfo={:x}", ByteBuf(pcrinfo))?;
        }
        if let Some(pcrlock) = self.pcrlock {
            // pcrlock=      pcr number to be extended to "lock" blob
            write!(f, " pcrlock={}", pcrlock)?;
        }
        if let Some(migratable) = self.migratable {
            // migratable=   0|1 indicating permission to reseal to new PCR values,
            //               default 1 (resealing allowed)
            write!(f, " migratable={}", migratable as u8)?;
        }
        if let Some(hash) = self.hash {
            // hash=         hash algorithm name as a string. For TPM 1.x the only
            //               allowed value is sha1. For TPM 2.x the allowed values
            //               are sha1, sha256, sha384, sha512 and sm3-256.
            write!(f, " hash={}", hash.name())?;
        }
        if let Some(policydigest) = self.policydigest.as_ref() {
            // policydigest= digest for the authorization policy. must be calculated
            //               with the same hash algorithm as specified by the 'hash='
            //               option.
            write!(f, " policydigest={:x}", ByteBuf(policydigest))?;
        }
        if let Some(policyhandle) = self.policyhandle {
            // policyhandle= handle to an authorization policy session that defines the
            //               same policy and with the same hash algorithm as was used to
            //               seal the key.
            write!(f, " policyhandle={:x}", policyhandle)?;
        }
        Ok(())
    }
}

/// The payload for trusted keys.
#[derive(Debug, Clone, PartialEq, Eq)]
// #[non_exhaustive]
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
    Update {
        /// Options to apply to the key.
        options: TrustedOptions,
    },
}

impl KeyPayload for Payload {
    fn payload(&self) -> Cow<[u8]> {
        match self {
            Payload::New {
                keylen,
                options,
            } => format!("new {}{}", keylen, options),
            Payload::Load {
                blob,
                options,
            } => format!("load {:x}{}", ByteBuf(blob), options),
            Payload::Update {
                options,
            } => format!("update{}", options),
        }
        .into_bytes()
        .into()
    }
}
