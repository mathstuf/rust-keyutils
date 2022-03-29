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

/// A trait for representing a type of key in the Linux keyring subsystem.
pub trait KeyType {
    /// The type for describing the key.
    type Description: KeyDescription + ?Sized;
    /// The type for representing a payload for the key.
    type Payload: KeyPayload + ?Sized;

    /// The name of the keytype.
    fn name() -> &'static str;
}

/// A description for a key.
pub trait KeyDescription {
    /// The description of the key.
    fn description(&self) -> Cow<str>;
}

impl KeyDescription for str {
    fn description(&self) -> Cow<str> {
        Cow::Borrowed(self)
    }
}

impl KeyDescription for String {
    fn description(&self) -> Cow<str> {
        Cow::Borrowed(self)
    }
}

/// A payload for a key.
pub trait KeyPayload {
    /// The payload for the key.
    fn payload(&self) -> Cow<[u8]>;
}

impl KeyPayload for () {
    fn payload(&self) -> Cow<[u8]> {
        Cow::Borrowed(&[])
    }
}

impl KeyPayload for str {
    fn payload(&self) -> Cow<[u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

impl KeyPayload for String {
    fn payload(&self) -> Cow<[u8]> {
        Cow::Borrowed(self.as_bytes())
    }
}

impl KeyPayload for [u8] {
    fn payload(&self) -> Cow<[u8]> {
        Cow::Borrowed(self)
    }
}

impl KeyPayload for Vec<u8> {
    fn payload(&self) -> Cow<[u8]> {
        Cow::Borrowed(self)
    }
}

/// A key which may be restricted into being added to a keyring.
pub trait RestrictableKeyType: KeyType {
    /// The type for representing a restriction for adding keys of this type.
    type Restriction: KeyRestriction + ?Sized;
}

/// A restriction for a key.
pub trait KeyRestriction {
    /// The restriction string of the key.
    fn restriction(&self) -> Cow<str>;
}

impl KeyRestriction for str {
    fn restriction(&self) -> Cow<str> {
        Cow::Borrowed(self)
    }
}

impl KeyRestriction for String {
    fn restriction(&self) -> Cow<str> {
        Cow::Borrowed(self)
    }
}
