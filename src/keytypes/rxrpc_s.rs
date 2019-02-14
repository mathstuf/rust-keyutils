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

//! RxRPC server keys

use std::borrow::Cow;

use keytype::*;

/// An RxRPC server key.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RxRPCServer;

impl KeyType for RxRPCServer {
    type Description = Description;
    type Payload = Payload;

    fn name() -> &'static str {
        "rxrpc_s"
    }
}

/// The description of an RxRPC server key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description {
    /// The ID of the service.
    pub service_id: u16,
    /// The security index.
    pub security_index: u8,
}

impl KeyDescription for Description {
    fn description(&self) -> Cow<str> {
        Cow::Owned(format!("{}:{}", self.service_id, self.security_index))
    }
}

/// The payload for an RxRPC server key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payload {
    key: [u8; 8],
}

impl KeyPayload for Payload {
    fn payload(&self) -> Cow<[u8]> {
        Cow::Borrowed(&self.key)
    }
}
