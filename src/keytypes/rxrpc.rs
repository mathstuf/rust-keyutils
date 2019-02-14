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

use std::borrow::Cow;

use keytype::*;

/// An RxRPC client key.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RxRPC;

impl KeyType for RxRPC {
    /// RxRPC client key descriptions are free-form.
    type Description = str;
    type Payload = Payload;

    fn name() -> &'static str {
        "rxrpc"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    expiry: u32,
    version: u8,
    session_key: [u8; 8],
    ticket: Vec<u8>,
}

impl KeyPayload for Payload {
    fn payload(&self) -> Cow<[u8]> {
        let mut payload = Vec::new();

        // struct rxrpc_key_sec2_v1 {
        //     uint16_t    security_index; /* 2 */
        //     uint16_t    ticket_length;  /* length of ticket[] */
        //     uint32_t    expiry;         /* time at which expires */
        //     uint8_t     kvno;           /* key version number */
        //     uint8_t     __pad[3];
        //     uint8_t     session_key[8]; /* DES session key */
        //     uint8_t     ticket[0];      /* the encrypted ticket */
        // };

        payload.extend((2 as u16).to_ne_bytes().iter());
        payload.extend((self.ticket.len() as u16).to_ne_bytes().iter());
        payload.extend(self.expiry.to_ne_bytes().iter());
        payload.extend(self.version.to_ne_bytes().iter());
        payload.extend([0u8; 3].iter());
        payload.extend(self.session_key.iter());
        payload.extend(self.ticket.iter());

        Cow::Owned(payload)
    }
}
