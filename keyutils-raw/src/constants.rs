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

// Ignore rustfmt changes in here. The horizontal alignment is too useful to give up.
#![cfg_attr(rustfmt, rustfmt_skip)]

use crate::{KeyPermissions, KeyringSerial};

// TODO: change these to &CStr when const fns get unblocked.
pub const KEY_TYPE_KEYRING:                 &str = "keyring";
pub const KEY_TYPE_USER:                    &str = "user";
pub const KEY_TYPE_LOGON:                   &str = "logon";
pub const KEY_TYPE_BIG_KEY:                 &str = "big_key";

pub const KEY_SPEC_THREAD_KEYRING:          KeyringSerial = unsafe { KeyringSerial::new_unchecked(-1) };
pub const KEY_SPEC_PROCESS_KEYRING:         KeyringSerial = unsafe { KeyringSerial::new_unchecked(-2) };
pub const KEY_SPEC_SESSION_KEYRING:         KeyringSerial = unsafe { KeyringSerial::new_unchecked(-3) };
pub const KEY_SPEC_USER_KEYRING:            KeyringSerial = unsafe { KeyringSerial::new_unchecked(-4) };
pub const KEY_SPEC_USER_SESSION_KEYRING:    KeyringSerial = unsafe { KeyringSerial::new_unchecked(-5) };
pub const KEY_SPEC_GROUP_KEYRING:           KeyringSerial = unsafe { KeyringSerial::new_unchecked(-6) };
pub const KEY_SPEC_REQKEY_AUTH_KEY:         KeyringSerial = unsafe { KeyringSerial::new_unchecked(-7) };

pub const KEY_POS_VIEW:    KeyPermissions = 0x0100_0000;     /* possessor can view a key's attributes */
pub const KEY_POS_READ:    KeyPermissions = 0x0200_0000;     /* possessor can read key payload / view keyring */
pub const KEY_POS_WRITE:   KeyPermissions = 0x0400_0000;     /* possessor can update key payload / add link to keyring */
pub const KEY_POS_SEARCH:  KeyPermissions = 0x0800_0000;     /* possessor can find a key in search / search a keyring */
pub const KEY_POS_LINK:    KeyPermissions = 0x1000_0000;     /* possessor can create a link to a key/keyring */
pub const KEY_POS_SETATTR: KeyPermissions = 0x2000_0000;     /* possessor can set key attributes */
pub const KEY_POS_ALL:     KeyPermissions = 0x3f00_0000;

pub const KEY_USR_VIEW:    KeyPermissions = 0x0001_0000;     /* user permissions... */
pub const KEY_USR_READ:    KeyPermissions = 0x0002_0000;
pub const KEY_USR_WRITE:   KeyPermissions = 0x0004_0000;
pub const KEY_USR_SEARCH:  KeyPermissions = 0x0008_0000;
pub const KEY_USR_LINK:    KeyPermissions = 0x0010_0000;
pub const KEY_USR_SETATTR: KeyPermissions = 0x0020_0000;
pub const KEY_USR_ALL:     KeyPermissions = 0x003f_0000;

pub const KEY_GRP_VIEW:    KeyPermissions = 0x0000_0100;     /* group permissions... */
pub const KEY_GRP_READ:    KeyPermissions = 0x0000_0200;
pub const KEY_GRP_WRITE:   KeyPermissions = 0x0000_0400;
pub const KEY_GRP_SEARCH:  KeyPermissions = 0x0000_0800;
pub const KEY_GRP_LINK:    KeyPermissions = 0x0000_1000;
pub const KEY_GRP_SETATTR: KeyPermissions = 0x0000_2000;
pub const KEY_GRP_ALL:     KeyPermissions = 0x0000_3f00;

pub const KEY_OTH_VIEW:    KeyPermissions = 0x0000_0001;     /* third party permissions... */
pub const KEY_OTH_READ:    KeyPermissions = 0x0000_0002;
pub const KEY_OTH_WRITE:   KeyPermissions = 0x0000_0004;
pub const KEY_OTH_SEARCH:  KeyPermissions = 0x0000_0008;
pub const KEY_OTH_LINK:    KeyPermissions = 0x0000_0010;
pub const KEY_OTH_SETATTR: KeyPermissions = 0x0000_0020;
pub const KEY_OTH_ALL:     KeyPermissions = 0x0000_003f;
