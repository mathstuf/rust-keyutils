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

use crate::types::{key_perm_t, key_serial_t};

#[rustfmt::skip]
extern "C" {
    pub fn add_key(
        type_:          *const libc::c_char,
        description:    *const libc::c_char,
        payload:        *const libc::c_void,
        plen:           libc::size_t,
        keyring:        key_serial_t)
        -> key_serial_t;
    pub fn request_key(
        type_:          *const libc::c_char,
        description:    *const libc::c_char,
        callout_info:   *const libc::c_char,
        keyring:        key_serial_t)
        -> key_serial_t;

    pub fn keyctl_get_keyring_ID(
        id:     key_serial_t,
        create: libc::c_int)
        -> key_serial_t;
    pub fn keyctl_join_session_keyring(
        name:   *const libc::c_char)
        -> key_serial_t;
    pub fn keyctl_update(
        id:         key_serial_t,
        payload:    *const libc::c_void,
        plen:       libc::size_t)
        -> libc::c_long;
    pub fn keyctl_revoke(
        id: key_serial_t)
        -> libc::c_long;
    pub fn keyctl_chown(
        id:     key_serial_t,
        uid:    libc::uid_t,
        gid:    libc::gid_t)
        -> libc::c_long;
    pub fn keyctl_setperm(
        id:     key_serial_t,
        perm:   key_perm_t)
        -> libc::c_long;
    pub fn keyctl_describe(
        id:     key_serial_t,
        buffer: *mut libc::c_char,
        buflen: libc::size_t)
        -> libc::c_long;
    pub fn keyctl_clear(
        ringid: key_serial_t)
        -> libc::c_long;
    pub fn keyctl_link(
        id:     key_serial_t,
        ringid: key_serial_t)
        -> libc::c_long;
    pub fn keyctl_unlink(
        id:     key_serial_t,
        ringid: key_serial_t)
        -> libc::c_long;
    pub fn keyctl_search(
        ringid:         key_serial_t,
        type_:          *const libc::c_char,
        description:    *const libc::c_char,
        destringid:     key_serial_t)
        -> libc::c_long;
    pub fn keyctl_read(
        id:     key_serial_t,
        buffer: *mut libc::c_char,
        buflen: libc::size_t)
        -> libc::c_long;
    pub fn keyctl_instantiate(
        id:         key_serial_t,
        payload:    *const libc::c_void,
        plen:       libc::size_t,
        ringid:     key_serial_t)
        -> libc::c_long;
    pub fn keyctl_negate(
        id:         key_serial_t,
        timeout:    libc::c_uint,
        ringid:     key_serial_t)
        -> libc::c_long;
    pub fn keyctl_set_reqkey_keyring(
        reqkey_defl:    libc::c_int)
        -> libc::c_long;
    pub fn keyctl_set_timeout(
        key:        key_serial_t,
        timeout:    libc::c_uint)
        -> libc::c_long;
    pub fn keyctl_assume_authority(
        key:    key_serial_t)
        -> libc::c_long;
    pub fn keyctl_get_security(
        key:    key_serial_t,
        buffer: *mut libc::c_char,
        buflen: libc::size_t)
        -> libc::c_long;
    //pub fn keyctl_session_to_parent()
    //    -> libc::c_long;
    pub fn keyctl_reject(
        id:         key_serial_t,
        timeout:    libc::c_uint,
        error:      libc::c_uint,
        ringid:     key_serial_t)
        -> libc::c_long;
    pub fn keyctl_invalidate(
        id: key_serial_t)
        -> libc::c_long;
    pub fn keyctl_get_persistent(
        uid:    libc::uid_t,
        id:     key_serial_t)
        -> libc::c_long;
    pub fn keyctl_dh_compute(
        private:    key_serial_t,
        prime:      key_serial_t,
        base:       key_serial_t,
        buffer:     *mut libc::c_char,
        buflen:     libc::size_t)
        -> libc::c_long;
}
