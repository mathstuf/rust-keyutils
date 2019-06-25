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

/// Alias for the key_serial_t kernel type, representing a keyring (or key).
pub type KeyringSerial = std::num::NonZeroI32;

/// Alias for the key_perm_t kernel type, representing a keyring's (or key's)
/// permission bits.
///
/// See `Permission`.
pub type KeyPermissions = u32;

pub type TimeoutSeconds = libc::c_uint;

/// An enumeration for the keyrings which may be set as the default.
///
/// Keys which are implicitly required via syscalls and other operations are
/// placed in the default keyring.
#[derive(Debug, PartialEq, Eq)]
pub enum DefaultKeyring {
    /// Do not change the default keyring.
    ///
    /// This may be used to get the current default keyring.
    NoChange = -1,
    /// Set the thread-specific keyring as the default.
    ThreadKeyring = 1,
    /// Set the process-specific keyring as the default.
    ProcessKeyring = 2,
    /// Set the session-specific keyring as the default.
    SessionKeyring = 3,
    /// Set the user-specific keyring as the default.
    UserKeyring = 4,
    /// Set the user session-specific keyring as the default.
    UserSessionKeyring = 5,
    /// Set the user session-specific keyring as the default.
    GroupKeyring = 6,
    /// Set the default keyring to the default logic.
    ///
    /// Keys will be placed in the first available keyring of:
    ///
    ///   - thread-specific
    ///   - process-specific
    ///   - session-specific
    ///   - user-specific
    DefaultKeyring = 0,
}

impl From<libc::c_long> for DefaultKeyring {
    fn from(id: libc::c_long) -> DefaultKeyring {
        use self::DefaultKeyring::*;
        match id {
            x if x == NoChange as libc::c_long => NoChange,
            x if x == ThreadKeyring as libc::c_long => ThreadKeyring,
            x if x == ProcessKeyring as libc::c_long => ProcessKeyring,
            x if x == SessionKeyring as libc::c_long => SessionKeyring,
            x if x == UserKeyring as libc::c_long => UserKeyring,
            x if x == UserSessionKeyring as libc::c_long => UserSessionKeyring,
            x if x == GroupKeyring as libc::c_long => GroupKeyring,
            x if x == DefaultKeyring as libc::c_long => DefaultKeyring,
            _ => panic!("Invalid value for a default keyring: {}", id),
        }
    }
}
