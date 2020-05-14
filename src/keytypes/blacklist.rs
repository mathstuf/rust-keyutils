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

//! Certificate blacklist keys

use std::borrow::Cow;

use super::ByteBuf;
use crate::keytype::*;

/// Blacklist hashes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Blacklist;

impl KeyType for Blacklist {
    /// Login key descriptions are free-form.
    type Description = Description;
    /// Login payloads are free-form.
    type Payload = ();

    fn name() -> &'static str {
        "keyring"
    }
}

/// The hash type to blacklist.
#[derive(Debug, Clone, Eq)]
// #[non_exhaustive]
pub enum HashType {
    /// x509 data
    Tbs,
    /// Custom hash type
    Other(Cow<'static, str>),
}

impl HashType {
    /// The name of the hash type.
    fn name(&self) -> &str {
        match *self {
            HashType::Tbs => "tbs",
            HashType::Other(ref s) => s,
        }
    }
}

impl PartialEq for HashType {
    fn eq(&self, rhs: &Self) -> bool {
        self.name() == rhs.name()
    }
}

/// The description of a blacklist key.
pub struct Description {
    /// The hash type to blacklist.
    pub hash_type: HashType,
    /// The hash to blacklist.
    pub hash: Vec<u8>,
}

impl KeyDescription for Description {
    fn description(&self) -> Cow<str> {
        format!("{}:{:x}", self.hash_type.name(), ByteBuf(&self.hash)).into()
    }
}
