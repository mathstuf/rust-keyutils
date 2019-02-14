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

#![allow(non_camel_case_types)]

use crates::libc;

pub type key_serial_t = libc::int32_t;
pub type key_perm_t = libc::uint32_t;

// No actual type in the API, but create one for simplicity.
pub type _keyctl_support_t = libc::uint32_t;

#[rustfmt::skip]
#[repr(C)]
pub struct keyctl_pkey_query {
    pub supported_ops:  libc::uint32_t,
    pub key_size:       libc::uint32_t,
    pub max_data_size:  libc::uint16_t,
    pub max_sig_size:   libc::uint16_t,
    pub max_enc_size:   libc::uint16_t,
    pub max_dec_size:   libc::uint16_t,
    __spare:            [libc::uint32_t; 10],
}

impl keyctl_pkey_query {
    pub fn new() -> Self {
        keyctl_pkey_query {
            supported_ops: 0,
            key_size: 0,
            max_data_size: 0,
            max_sig_size: 0,
            max_enc_size: 0,
            max_dec_size: 0,
            __spare: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }
}
