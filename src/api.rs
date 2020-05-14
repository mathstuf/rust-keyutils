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

use std::borrow::Borrow;
use std::convert::TryInto;
use std::mem;
use std::result;
use std::str;
use std::time::Duration;

use keyutils_raw::*;
use log::error;
use uninit::extension_traits::VecCapacity;

use crate::constants::{Permission, SpecialKeyring};
use crate::keytype::*;
use crate::keytypes;

/// Reexport of `Errno` as `Error`.
pub type Error = errno::Errno;
/// Simpler `Result` type with the error already set.
pub type Result<T> = result::Result<T, Error>;

/// Request a key from the kernel.
fn request_impl<K: KeyType>(
    description: &str,
    info: Option<&str>,
    id: Option<KeyringSerial>,
) -> Result<KeyringSerial> {
    request_key(K::name(), description, info, id)
}

fn read_impl(id: KeyringSerial) -> Result<Vec<u8>> {
    // Get the size of the description.
    let mut sz = keyctl_read(id, None)?;
    // Allocate this description.
    let mut buffer = vec![0; sz];
    loop {
        let write_buffer = buffer.get_backing_buffer();
        // Fetch the description.
        sz = keyctl_read(id, Some(write_buffer))?;

        // If we got everything, exit.
        if sz <= buffer.capacity() {
            break;
        }

        // Resize for the additional capacity we need.
        buffer.resize(sz, 0);
    }
    buffer.truncate(sz);
    Ok(buffer)
}

/// Representation of a kernel keyring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keyring {
    id: KeyringSerial,
}

impl Keyring {
    /// Instantiate a keyring from an ID.
    ///
    /// This is unsafe because no keyring is known to exist with the given ID.
    ///
    /// # Safety
    ///
    /// This method assumes that the given serial is a valid keyring ID at the kernel level.
    pub unsafe fn new(id: KeyringSerial) -> Self {
        Keyring {
            id,
        }
    }

    fn new_impl(id: KeyringSerial) -> Self {
        Keyring {
            id,
        }
    }

    pub(crate) fn serial(&self) -> KeyringSerial {
        self.id
    }

    /// Set the default keyring to use when implicit requests on the current thread.
    ///
    /// Returns the old default keyring.
    ///
    /// # Panics
    ///
    /// If the kernel returns a keyring value which the library does not understand, the conversion
    /// from the return value into a `DefaultKeyring` will panic.
    pub fn set_default(keyring: DefaultKeyring) -> Result<DefaultKeyring> {
        keyctl_set_reqkey_keyring(keyring)
    }

    /// Requests a keyring with the given description by searching the thread, process, and session
    /// keyrings.
    ///
    /// If it is not found, the `info` string (if provided) will be handed off to
    /// `/sbin/request-key` to generate the key.
    ///
    /// If `target` is given, the found keyring will be linked into it. If `target` is not given
    /// and a new key is constructed due to the request, it will be linked into the default
    /// keyring (see `Keyring::set_default`).
    pub fn request<'s, 'a, D, I, T>(description: D, info: I, target: T) -> Result<Self>
    where
        D: AsRef<str>,
        I: Into<Option<&'s str>>,
        T: Into<Option<TargetKeyring<'a>>>,
    {
        request_impl::<keytypes::Keyring>(
            description.as_ref(),
            info.into().as_ref().copied(),
            target.into().map(TargetKeyring::serial),
        )
        .map(Self::new_impl)
    }

    fn get_keyring(id: SpecialKeyring, create: bool) -> Result<Keyring> {
        keyctl_get_keyring_id(id.serial(), create).map(Self::new_impl)
    }

    /// Attach to a special keyring. Fails if the keyring does not already exist.
    pub fn attach(id: SpecialKeyring) -> Result<Self> {
        Self::get_keyring(id, false)
    }

    /// Attach to a special keyring or create it if it does not exist.
    pub fn attach_or_create(id: SpecialKeyring) -> Result<Self> {
        Self::get_keyring(id, true)
    }

    /// Create a new anonymous keyring and set it as the session keyring.
    pub fn join_anonymous_session() -> Result<Self> {
        keyctl_join_session_keyring(None).map(Self::new_impl)
    }

    /// Attached to a named session keyring.
    ///
    /// If a keyring named `name` exists, attach it as the session keyring (requires the `search`
    /// permission). If a keyring does not exist, create it and attach it as the session keyring.
    pub fn join_session<N>(name: N) -> Result<Self>
    where
        N: AsRef<str>,
    {
        keyctl_join_session_keyring(Some(name.as_ref())).map(Self::new_impl)
    }

    /// Clears the contents of the keyring.
    ///
    /// Requires `write` permission on the keyring.
    pub fn clear(&mut self) -> Result<()> {
        keyctl_clear(self.id)
    }

    /// Adds a link to `key` to the keyring.
    ///
    /// Any link to an existing key with the same description is removed. Requires `write`
    /// permission on the keyring and `link` permission on the key.
    pub fn link_key(&mut self, key: &Key) -> Result<()> {
        keyctl_link(key.id, self.id)
    }

    /// Removes the link to `key` from the keyring.
    ///
    /// Requires `write` permission on the keyring.
    pub fn unlink_key(&mut self, key: &Key) -> Result<()> {
        keyctl_unlink(key.id, self.id)
    }

    /// Adds a link to `keyring` to the keyring.
    ///
    /// Any link to an existing keyring with the same description is removed. Requires `write`
    /// permission on the current keyring and `link` permission on the linked keyring.
    pub fn link_keyring(&mut self, keyring: &Keyring) -> Result<()> {
        keyctl_link(keyring.id, self.id)
    }

    /// Removes the link to `keyring` from the keyring.
    ///
    /// Requires `write` permission on the keyring.
    pub fn unlink_keyring(&mut self, keyring: &Keyring) -> Result<()> {
        keyctl_unlink(keyring.id, self.id)
    }

    fn search_impl<K>(
        &self,
        description: &str,
        destination: Option<&mut Keyring>,
    ) -> Result<KeyringSerial>
    where
        K: KeyType,
    {
        keyctl_search(
            self.id,
            K::name(),
            description,
            destination.map(|dest| dest.id),
        )
    }

    /// Recursively search the keyring for a key with the matching description.
    ///
    /// If it is found, it is attached to the keyring (if `write` permission to the keyring and
    /// `link` permission on the key exist) and return it. Requires the `search` permission on the
    /// keyring. Any children keyrings without the `search` permission are ignored.
    pub fn search_for_key<'a, K, D, DK>(&self, description: D, destination: DK) -> Result<Key>
    where
        K: KeyType,
        D: Borrow<K::Description>,
        DK: Into<Option<&'a mut Keyring>>,
    {
        self.search_impl::<K>(&description.borrow().description(), destination.into())
            .map(Key::new_impl)
    }

    /// Recursively search the keyring for a keyring with the matching description.
    ///
    /// If it is found, it is attached to the keyring (if `write` permission to the keyring and
    /// `link` permission on the found keyring exist) and return it. Requires the `search`
    /// permission on the keyring. Any children keyrings without the `search` permission are
    /// ignored.
    pub fn search_for_keyring<'a, D, DK>(&self, description: D, destination: DK) -> Result<Self>
    where
        D: Borrow<<keytypes::Keyring as KeyType>::Description>,
        DK: Into<Option<&'a mut Keyring>>,
    {
        self.search_impl::<keytypes::Keyring>(
            &description.borrow().description(),
            destination.into(),
        )
        .map(Self::new_impl)
    }

    /// Return all immediate children of the keyring.
    ///
    /// Requires `read` permission on the keyring.
    pub fn read(&self) -> Result<(Vec<Key>, Vec<Keyring>)> {
        // The `description` check below hides this error code from the kernel.
        if self.id.get() == 0 {
            return Err(errno::Errno(libc::ENOKEY));
        }

        // Avoid a panic in the code below be ensuring that we actually have a keyring. Parsing
        // a key's payload as a keyring payload.
        let desc = self.description()?;
        if desc.type_ != keytypes::Keyring::name() {
            return Err(errno::Errno(libc::ENOTDIR));
        }

        let buffer = read_impl(self.id)?;
        let keyring_children = {
            let chunk_size = mem::size_of::<KeyringSerial>();
            let chunks = buffer.chunks(chunk_size);
            chunks.map(|chunk| {
                let bytes = chunk.try_into().map_err(|err| {
                    error!(
                        "A keyring did not have the right number of bytes for a child key or \
                         keyring ID: {}",
                        err,
                    );
                    errno::Errno(libc::EINVAL)
                })?;
                let id = i32::from_ne_bytes(bytes);
                let serial = KeyringSerial::new(id).ok_or_else(|| {
                    error!("A keyring had a child key or keyring ID of 0");
                    errno::Errno(libc::EINVAL)
                })?;
                Ok(Key::new_impl(serial))
            })
        };

        let mut keys = Vec::new();
        let mut keyrings = Vec::new();
        for key in keyring_children {
            let key = key?;
            match key.description() {
                Ok(description) => {
                    if description.type_ == keytypes::Keyring::name() {
                        keyrings.push(Keyring::new_impl(key.id))
                    } else {
                        keys.push(key)
                    }
                },
                // Keys can be invalidated between reading the keyring and
                // reading the child key's description. If this happens, we get
                // ENOKEY and just skip that key.
                Err(errno::Errno(libc::ENOKEY)) => {},
                Err(e) => return Err(e),
            }
        }
        Ok((keys, keyrings))
    }

    /// Attach the persistent keyring for the current user to the current keyring.
    ///
    /// If one does not exist, it will be created. Requires `write` permission on the keyring.
    pub fn attach_persistent(&mut self) -> Result<Self> {
        keyctl_get_persistent(!0, self.id).map(Self::new_impl)
    }

    /// Adds a key of a specific type to the keyring.
    ///
    /// If a key with the same description already exists and has the `update` permission, it will
    /// be updated, otherwise the link to the old key will be removed. Requires `write` permission.
    pub fn add_key<K, D, P>(&mut self, description: D, payload: P) -> Result<Key>
    where
        K: KeyType,
        D: Borrow<K::Description>,
        P: Borrow<K::Payload>,
    {
        self.add_key_impl::<K>(description.borrow(), payload.borrow())
            .map(Key::new_impl)
    }

    /// Monomorphization of adding a key.
    fn add_key_impl<K>(
        &mut self,
        description: &K::Description,
        payload: &K::Payload,
    ) -> Result<KeyringSerial>
    where
        K: KeyType,
    {
        add_key(
            K::name(),
            &description.description(),
            &payload.payload(),
            self.id,
        )
    }

    /// Adds a keyring to the current keyring.
    ///
    /// If a keyring with the same description already, the link to the old keyring will be
    /// removed. Requires `write` permission on the keyring.
    pub fn add_keyring<D>(&mut self, description: D) -> Result<Self>
    where
        D: Borrow<<keytypes::Keyring as KeyType>::Description>,
    {
        self.add_key_impl::<keytypes::Keyring>(description.borrow(), &())
            .map(Self::new_impl)
    }

    /// Revokes the keyring.
    ///
    /// Requires `write` permission on the keyring.
    pub fn revoke(self) -> Result<()> {
        keyctl_revoke(self.id)
    }

    /// Change the user which owns the keyring.
    ///
    /// Requires the `setattr` permission on the keyring and the SysAdmin capability to change it
    /// to anything other than the current user.
    pub fn chown(&mut self, uid: libc::uid_t) -> Result<()> {
        keyctl_chown(self.id, Some(uid), None)
    }

    /// Change the group which owns the keyring.
    ///
    /// Requires the `setattr` permission on the keyring and the SysAdmin capability to change it
    /// to anything other than a group of which the current user is a member.
    pub fn chgrp(&mut self, gid: libc::gid_t) -> Result<()> {
        keyctl_chown(self.id, None, Some(gid))
    }

    /// Set the permissions on the keyring.
    ///
    /// Requires the `setattr` permission on the keyring and the SysAdmin capability if the current
    /// user does not own the keyring.
    pub fn set_permissions(&mut self, perms: Permission) -> Result<()> {
        keyctl_setperm(self.id, perms.bits())
    }

    #[cfg(test)]
    pub(crate) fn set_permissions_raw(&mut self, perms: KeyPermissions) -> Result<()> {
        keyctl_setperm(self.id, perms)
    }

    /// Restrict all links into the keyring.
    ///
    /// Requires the `setattr` permission on the keyring and the SysAdmin capability to change it to
    /// anything other than the current user.
    pub fn restrict_all(&mut self) -> Result<()> {
        keyctl_restrict_keyring(self.id, Restriction::AllLinks)
    }

    /// Restrict links into the keyring.
    ///
    /// Requires the `setattr` permission on the keyring and the SysAdmin capability to change it to
    /// anything other than the current user.
    pub fn restrict_by_type<K, R>(&mut self, restriction: R) -> Result<()>
    where
        K: RestrictableKeyType,
        R: Borrow<K::Restriction>,
    {
        keyctl_restrict_keyring(
            self.id,
            Restriction::ByType {
                type_: K::name(),
                restriction: &restriction.borrow().restriction(),
            },
        )
    }

    fn description_raw(&self) -> Result<String> {
        // Get the size of the description.
        let mut sz = keyctl_describe(self.id, None)?;
        // Allocate this description.
        let mut buffer = vec![0; sz];
        loop {
            let write_buffer = buffer.get_backing_buffer();
            // Fetch the description.
            sz = keyctl_describe(self.id, Some(write_buffer))?;

            // If we got everything, exit.
            if sz <= buffer.capacity() {
                break;
            }

            // Resize for the additional capacity we need.
            buffer.resize(sz, 0);
        }
        // Remove 1 from the size for the trailing NUL the kernel adds.
        buffer.truncate(sz.saturating_sub(1));
        // The kernel guarantees that we get ASCII data from this.
        let str_slice = str::from_utf8(&buffer[..]).unwrap();
        Ok(str_slice.to_owned())
    }

    /// Retrieve metadata about the keyring.
    ///
    /// # Panics
    ///
    /// If the kernel returns malformed data, the the parser will panic.
    pub fn description(&self) -> Result<Description> {
        self.description_raw()
            .and_then(|desc| Description::parse(&desc).ok_or(errno::Errno(libc::EINVAL)))
    }

    /// Set an expiration timer on the keyring to `timeout`.
    ///
    /// Any partial seconds are ignored. A timeout of 0 means "no expiration". Requires the
    /// `setattr` permission on the keyring.
    pub fn set_timeout(&mut self, timeout: Duration) -> Result<()> {
        keyctl_set_timeout(self.id, timeout.as_secs() as TimeoutSeconds)
    }

    /// The security context of the keyring. Depends on the security manager loaded into the kernel
    /// (e.g., SELinux or AppArmor).
    pub fn security(&self) -> Result<String> {
        // Get the size of the description.
        let mut sz = keyctl_get_security(self.id, None)?;
        // Allocate this description.
        let mut buffer = vec![0; sz];
        loop {
            let write_buffer = buffer.get_backing_buffer();
            // Fetch the description.
            sz = keyctl_get_security(self.id, Some(write_buffer))?;

            // If we got everything, exit.
            if sz <= buffer.capacity() {
                break;
            }

            // Resize for the additional capacity we need.
            buffer.resize(sz, 0);
        }
        // Remove 1 from the size for the trailing NUL the kernel adds.
        buffer.truncate(sz.saturating_sub(1));
        // The kernel guarantees that we get ASCII data from this.
        let str_slice = str::from_utf8(&buffer[..]).unwrap();
        Ok(str_slice.to_owned())
    }

    /// Invalidates the keyring and schedules it for removal. Requires the `search` permission on
    /// the keyring.
    pub fn invalidate(self) -> Result<()> {
        keyctl_invalidate(self.id)
    }
}

/// Representation of a kernel key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    id: KeyringSerial,
}

impl Key {
    /// Instantiate a key from an ID.
    ///
    /// This is unsafe because no key is known to exist with the given ID.
    ///
    /// # Safety
    ///
    /// This method assumes that the given serial is a valid key ID at the kernel level.
    pub unsafe fn new(id: KeyringSerial) -> Self {
        Self::new_impl(id)
    }

    fn new_impl(id: KeyringSerial) -> Self {
        Key {
            id,
        }
    }

    pub(crate) fn serial(&self) -> KeyringSerial {
        self.id
    }

    /// Requests a key with the given type and description by searching the thread, process, and
    /// session keyrings.
    ///
    /// If it is not found, the `info` string (if provided) will be handed off to
    /// `/sbin/request-key` to generate the key.
    ///
    /// If `target` is given, the found keyring will be linked into it. If `target` is not given
    /// and a new key is constructed due to the request, it will be linked into the default
    /// keyring (see `Keyring::set_default`).
    pub fn request<'s, 'a, K, D, I, T>(description: D, info: I, target: T) -> Result<Self>
    where
        K: KeyType,
        D: Borrow<K::Description>,
        I: Into<Option<&'s str>>,
        T: Into<Option<TargetKeyring<'a>>>,
    {
        request_impl::<K>(
            &description.borrow().description(),
            info.into().as_ref().copied(),
            target.into().map(TargetKeyring::serial),
        )
        .map(Self::new_impl)
    }

    /// Determine whether the key is of a specific implementation or not.
    pub fn is_keytype<K>(&self) -> Result<bool>
    where
        K: KeyType,
    {
        let desc = self.description()?;
        Ok(desc.type_ == K::name())
    }

    /// Update the payload in the key.
    pub fn update<K, P>(&mut self, payload: P) -> Result<()>
    where
        K: KeyType,
        P: Borrow<K::Payload>,
    {
        keyctl_update(self.id, &payload.borrow().payload())
    }

    /// Revokes the key. Requires `write` permission on the key.
    pub fn revoke(self) -> Result<()> {
        Keyring::new_impl(self.id).revoke()
    }

    /// Change the user which owns the key.
    ///
    /// Requires the `setattr` permission on the key and the SysAdmin capability to change it to
    /// anything other than the current user.
    pub fn chown(&mut self, uid: libc::uid_t) -> Result<()> {
        Keyring::new_impl(self.id).chown(uid)
    }

    /// Change the group which owns the key.
    ///
    /// Requires the `setattr` permission on the key and the SysAdmin capability to change it to
    /// anything other than a group of which the current user is a member.
    pub fn chgrp(&mut self, gid: libc::gid_t) -> Result<()> {
        Keyring::new_impl(self.id).chgrp(gid)
    }

    /// Set the permissions on the key.
    ///
    /// Requires the `setattr` permission on the key and the SysAdmin capability if the current
    /// user does not own the key.
    pub fn set_permissions(&mut self, perms: Permission) -> Result<()> {
        Keyring::new_impl(self.id).set_permissions(perms)
    }

    #[cfg(test)]
    pub(crate) fn set_permissions_raw(&mut self, perms: KeyPermissions) -> Result<()> {
        Keyring::new_impl(self.id).set_permissions_raw(perms)
    }

    /// Retrieve metadata about the key.
    ///
    /// # Panics
    ///
    /// If the kernel returns malformed data, the parser will panic.
    pub fn description(&self) -> Result<Description> {
        Keyring::new_impl(self.id).description()
    }

    /// Read the payload of the key. Requires `read` permissions on the key.
    pub fn read(&self) -> Result<Vec<u8>> {
        read_impl(self.id)
    }

    /// Set an expiration timer on the keyring to `timeout`.
    ///
    /// Any partial seconds are ignored. A timeout of 0 means "no expiration". Requires the
    /// `setattr` permission on the key.
    pub fn set_timeout(&mut self, timeout: Duration) -> Result<()> {
        Keyring::new_impl(self.id).set_timeout(timeout)
    }

    /// The security context of the key.
    ///
    /// Depends on the security manager loaded into the kernel (e.g., SELinux or AppArmor).
    pub fn security(&self) -> Result<String> {
        Keyring::new_impl(self.id).security()
    }

    /// Invalidates the key and schedules it for removal.
    ///
    /// Requires the `search` permission on the key.
    pub fn invalidate(self) -> Result<()> {
        Keyring::new_impl(self.id).invalidate()
    }

    /// Create an object to manage a key request.
    ///
    /// Before a key may be managed on a thread, an authorization key must be attached to an
    /// available thread keyring.
    ///
    /// Only one key may be managed on a thread at a time. Managing a second key will
    /// invalidate any previous `KeyManager` constructions.
    ///
    /// See `KeyManager::request_key_auth_key`.
    pub fn manage(&mut self) -> Result<KeyManager> {
        keyctl_assume_authority(Some(self.id))?;
        Ok(KeyManager::new(Key::new_impl(self.id)))
    }

    /// Compute a Diffie-Hellman prime for use as a shared secret or public key.
    pub fn compute_dh(private: &Key, prime: &Key, base: &Key) -> Result<Vec<u8>> {
        // Get the size of the description.
        let mut sz = keyctl_dh_compute(private.id, prime.id, base.id, None)?;
        // Allocate this description.
        let mut buffer = vec![0; sz];
        loop {
            let write_buffer = buffer.get_backing_buffer();
            // Fetch the description.
            sz = keyctl_dh_compute(private.id, prime.id, base.id, Some(write_buffer))?;

            // If we got everything, exit.
            if sz <= buffer.capacity() {
                break;
            }

            // Resize for the additional capacity we need.
            buffer.resize(sz, 0);
        }
        buffer.truncate(sz);
        Ok(buffer)
    }
}

/// Structure representing the metadata about a key or keyring.
#[derive(Debug, Clone)]
pub struct Description {
    /// The type of the key.
    pub type_: String,
    /// The user owner of the key.
    pub uid: libc::uid_t,
    /// The group owner of the key.
    pub gid: libc::gid_t,
    /// The permissions of the key.
    pub perms: Permission,
    /// The plaintext description of the key.
    pub description: String,
}

impl Description {
    fn parse(desc: &str) -> Option<Description> {
        let mut pieces = desc.split(';').collect::<Vec<_>>();
        // Reverse the string because the kernel plans to extend it by adding fields to the
        // beginning of the string. By doing this, the fields are at a constant position in the
        // split string.
        pieces.reverse();
        let len = pieces.len();
        if len < 5 {
            None
        } else {
            if len > 5 {
                error!(
                    "New fields detected! Please report this upstream to \
                     https://github.com/mathstuf/rust-keyutils: {}",
                    desc,
                );
            }
            let bits = KeyPermissions::from_str_radix(pieces[1], 16).unwrap();
            if Permission::from_bits(bits).is_none() {
                error!(
                    "New permission bits detected! Please report this upstream to \
                     https://github.com/mathstuf/rust-keyutils: {}",
                    bits,
                );
            }
            Some(Description {
                type_: pieces[4].to_owned(),
                uid: pieces[3].parse::<libc::uid_t>().unwrap(),
                gid: pieces[2].parse::<libc::gid_t>().unwrap(),
                perms: Permission::from_bits_truncate(bits),
                description: pieces[0].to_owned(),
            })
        }
    }
}

/// The destination keyring of an instantiation request.
#[derive(Debug)]
pub enum TargetKeyring<'a> {
    /// A special keyring.
    Special(SpecialKeyring),
    /// A specific keyring.
    Keyring(&'a mut Keyring),
}

impl<'a> TargetKeyring<'a> {
    fn serial(self) -> KeyringSerial {
        match self {
            TargetKeyring::Special(special) => special.serial(),
            TargetKeyring::Keyring(keyring) => keyring.id,
        }
    }
}

impl<'a> From<SpecialKeyring> for TargetKeyring<'a> {
    fn from(special: SpecialKeyring) -> Self {
        TargetKeyring::Special(special)
    }
}

impl<'a> From<&'a mut Keyring> for TargetKeyring<'a> {
    fn from(keyring: &'a mut Keyring) -> Self {
        TargetKeyring::Keyring(keyring)
    }
}

impl<'a> From<SpecialKeyring> for Option<TargetKeyring<'a>> {
    fn from(special: SpecialKeyring) -> Self {
        Some(special.into())
    }
}

impl<'a> From<&'a mut Keyring> for Option<TargetKeyring<'a>> {
    fn from(keyring: &'a mut Keyring) -> Self {
        Some(keyring.into())
    }
}

/// A manager for a key to respond to instantiate a key request by the kernel.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyManager {
    key: Key,
}

impl KeyManager {
    fn new(key: Key) -> Self {
        KeyManager {
            key,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_new(key: Key) -> Self {
        Self::new(key)
    }

    /// Requests the authorization key created by `request_key`.
    ///
    /// This key must be present in an available keyring before `Key::manage` may be called.
    pub fn request_key_auth_key(create: bool) -> Result<Key> {
        keyctl_get_keyring_id(KEY_SPEC_REQKEY_AUTH_KEY, create).map(Key::new_impl)
    }

    /// Drop authority for the current thread.
    ///
    /// This invalidates
    pub fn drop_authority() -> Result<()> {
        keyctl_assume_authority(None)
    }

    /// Instantiate the key with the given payload.
    pub fn instantiate<'a, T, P>(self, keyring: T, payload: P) -> Result<()>
    where
        T: Into<Option<TargetKeyring<'a>>>,
        P: AsRef<[u8]>,
    {
        keyctl_instantiate(
            self.key.id,
            payload.as_ref(),
            keyring.into().map(TargetKeyring::serial),
        )
    }

    /// Reject the key with the given `error`.
    ///
    /// Requests for the key will fail until `timeout` has elapsed (partial
    /// seconds are ignored). This is to prevent a denial-of-service by
    /// requesting a non-existant key repeatedly. The requester must have
    /// `write` permission on the keyring.
    pub fn reject<'a, T>(self, keyring: T, timeout: Duration, error: errno::Errno) -> Result<()>
    where
        T: Into<Option<TargetKeyring<'a>>>,
    {
        keyctl_reject(
            self.key.id,
            timeout.as_secs() as TimeoutSeconds,
            error,
            keyring.into().map(TargetKeyring::serial),
        )
    }

    /// Reject the key with `ENOKEY`.
    ///
    /// Requests for the key will fail until `timeout` has elapsed (partial
    /// seconds are ignored). This is to prevent a denial-of-service by
    /// requesting a non-existant key repeatedly. The requester must have
    /// `write` permission on the keyring.
    pub fn negate<'a, T>(self, keyring: T, timeout: Duration) -> Result<()>
    where
        T: Into<Option<TargetKeyring<'a>>>,
    {
        keyctl_negate(
            self.key.id,
            timeout.as_secs() as TimeoutSeconds,
            keyring.into().map(TargetKeyring::serial),
        )
    }
}
