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

use crate::KeyType;

pub struct EmptyKey;

impl KeyType for EmptyKey {
    type Description = str;
    type Payload = ();

    fn name() -> &'static str {
        ""
    }
}

pub struct UnsupportedKey;

impl KeyType for UnsupportedKey {
    type Description = str;
    type Payload = ();

    fn name() -> &'static str {
        "unsupported_key_type"
    }
}

pub struct InvalidKey;

impl KeyType for InvalidKey {
    type Description = str;
    type Payload = ();

    fn name() -> &'static str {
        ".invalid_key_type"
    }
}

pub struct MaxLenKey;

impl KeyType for MaxLenKey {
    type Description = str;
    type Payload = ();

    fn name() -> &'static str {
        "1234567890123456789012345678901"
    }
}

pub struct OverlongKey;

impl KeyType for OverlongKey {
    type Description = str;
    type Payload = ();

    fn name() -> &'static str {
        "12345678901234567890123456789012"
    }
}

pub struct KeyringShadow;

impl KeyType for KeyringShadow {
    type Description = str;
    type Payload = str;

    fn name() -> &'static str {
        "keyring"
    }
}
