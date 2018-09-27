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

//! DNS resolution keys

use keytype::*;

use std::borrow::Cow;

/// A DNS resolver key.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DnsResolver;

impl KeyType for DnsResolver {
    type Description = Description;
    type Payload = ();

    fn name() -> &'static str {
        "dns_resolver"
    }
}

/// The DNS record to lookup.
#[derive(Debug, Clone, Eq)]
pub enum QueryType {
    /// An IPv4 address.
    A,
    /// An IPv6 address.
    AAAA,
    /// An AFS database address.
    AFSDB,
    /// A custom DNS record.
    Other(String),
}

impl QueryType {
    /// The name of the DNS record.
    fn name(&self) -> &str {
        match *self {
            QueryType::A => "a",
            QueryType::AAAA => "aaaa",
            QueryType::AFSDB => "afsdb",
            QueryType::Other(ref s) => s,
        }
    }
}

impl PartialEq for QueryType {
    fn eq(&self, rhs: &Self) -> bool {
        self.name() == rhs.name()
    }
}

/// The description of a DNS resolver key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description {
    /// The type of query to perform.
    ///
    /// If not specified, `A` and `AAAA` entries will be found.
    pub query_type: Option<QueryType>,
    /// The name to resolve.
    pub name: String,
}

impl KeyDescription for Description {
    fn description(&self) -> Cow<str> {
        Cow::Owned(if let Some(ref query_type) = self.query_type {
            format!("{}:{}", query_type.name(), self.name)
        } else {
            self.name.clone()
        })
    }
}
