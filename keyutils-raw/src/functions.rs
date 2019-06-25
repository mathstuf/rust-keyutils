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

use crate::{KeyPermissions, KeyringSerial, TimeoutSeconds};

#[rustfmt::skip]
extern "C" {
    pub fn add_key(
        type_:          *const libc::c_char,
        description:    *const libc::c_char,
        payload:        *const libc::c_void,
        plen:           libc::size_t,
        keyring:        KeyringSerial)
        -> KeyringSerial;
    pub fn request_key(
        type_:          *const libc::c_char,
        description:    *const libc::c_char,
        callout_info:   *const libc::c_char,
        keyring:        Option<KeyringSerial>)
        -> KeyringSerial;

    pub fn keyctl_get_keyring_ID(
        id:     KeyringSerial,
        create: libc::c_int)
        -> KeyringSerial;
    pub fn keyctl_join_session_keyring(
        name:   *const libc::c_char)
        -> KeyringSerial;
    pub fn keyctl_update(
        id:         KeyringSerial,
        payload:    *const libc::c_void,
        plen:       libc::size_t)
        -> libc::c_long;
    pub fn keyctl_revoke(
        id: KeyringSerial)
        -> libc::c_long;
    pub fn keyctl_chown(
        id:     KeyringSerial,
        uid:    libc::uid_t,
        gid:    libc::gid_t)
        -> libc::c_long;
    pub fn keyctl_setperm(
        id:     KeyringSerial,
        perm:   KeyPermissions)
        -> libc::c_long;
    pub fn keyctl_describe(
        id:     KeyringSerial,
        buffer: *mut libc::c_char,
        buflen: libc::size_t)
        -> libc::c_long;
    pub fn keyctl_clear(
        ringid: KeyringSerial)
        -> libc::c_long;
    pub fn keyctl_link(
        id:     KeyringSerial,
        ringid: KeyringSerial)
        -> libc::c_long;
    pub fn keyctl_unlink(
        id:     KeyringSerial,
        ringid: KeyringSerial)
        -> libc::c_long;
    pub fn keyctl_search(
        ringid:         KeyringSerial,
        type_:          *const libc::c_char,
        description:    *const libc::c_char,
        destringid:     KeyringSerial)
        -> libc::c_long;
    pub fn keyctl_read(
        id:     KeyringSerial,
        buffer: *mut libc::c_char,
        buflen: libc::size_t)
        -> libc::c_long;
    pub fn keyctl_instantiate(
        id:         KeyringSerial,
        payload:    *const libc::c_void,
        plen:       libc::size_t,
        ringid:     KeyringSerial)
        -> libc::c_long;
    pub fn keyctl_negate(
        id:         KeyringSerial,
        timeout:    TimeoutSeconds,
        ringid:     KeyringSerial)
        -> libc::c_long;
    pub fn keyctl_set_reqkey_keyring(
        reqkey_defl:    libc::c_int)
        -> libc::c_long;
    pub fn keyctl_set_timeout(
        key:        KeyringSerial,
        timeout:    TimeoutSeconds)
        -> libc::c_long;
    pub fn keyctl_assume_authority(
        key:    Option<KeyringSerial>)
        -> libc::c_long;
    pub fn keyctl_get_security(
        key:    KeyringSerial,
        buffer: *mut libc::c_char,
        buflen: libc::size_t)
        -> libc::c_long;
    //pub fn keyctl_session_to_parent()
    //    -> libc::c_long;
    pub fn keyctl_reject(
        id:         KeyringSerial,
        timeout:    TimeoutSeconds,
        error:      libc::c_uint,
        ringid:     KeyringSerial)
        -> libc::c_long;
    pub fn keyctl_invalidate(
        id: KeyringSerial)
        -> libc::c_long;
    pub fn keyctl_get_persistent(
        uid:    libc::uid_t,
        id:     KeyringSerial)
        -> libc::c_long;
    pub fn keyctl_dh_compute(
        private:    KeyringSerial,
        prime:      KeyringSerial,
        base:       KeyringSerial,
        buffer:     *mut libc::c_char,
        buflen:     libc::size_t)
        -> libc::c_long;
}
