use crates::libkeyutils_sys::*;

extern crate errno;

extern crate libc;

use super::constants::*;

use std::ffi::CString;
use std::mem;
use std::ptr;
use std::result;
use std::str;

/// Reexport of `Errno` as `Error`.
pub type Error = errno::Errno;
/// Simpler `Result` type with the error already set.
pub type Result<T> = result::Result<T, Error>;

fn check_call<T>(res: libc::c_long, value: T) -> Result<T> {
    if res == -1 {
        Err(errno::errno())
    } else {
        Ok(value)
    }
}

fn check_call_ret(res: libc::c_long) -> Result<libc::c_long> {
    if res == -1 {
        Err(errno::errno())
    } else {
        Ok(res)
    }
}

fn check_call_ret_serial(res: KeyringSerial) -> Result<KeyringSerial> {
    if res == -1 {
        Err(errno::errno())
    } else {
        Ok(res)
    }
}

/// Representation of a kernel keyring.
pub struct Keyring {
    id: KeyringSerial,
}

impl Keyring {
    fn new(id: KeyringSerial) -> Self {
        Keyring {
            id: id,
        }
    }

    /// Set the default keyring to use when implicit requests on the current thread. Returns the
    /// old default keyring.
    ///
    /// # Panics
    ///
    /// If the kernel returns a keyring value which the library does not understand, the conversion
    /// from the return value into a `DefaultKeyring` will panic.
    pub fn set_default(keyring: DefaultKeyring) -> Result<DefaultKeyring> {
        let ret = try!(check_call_ret(unsafe { keyctl_set_reqkey_keyring(keyring.serial()) }));
        Ok(DefaultKeyring::from(ret as i32))
    }

    /// Requests a keyring with the given description by searching the thread, process, and session
    /// keyrings.
    pub fn request(description: &str) -> Result<Self> {
        Keyring::new(0).request_keyring(description)
    }

    /// Requests a keyring with the given description by searching the thread, process, and session
    /// keyrings. If it is not found, the `info` string will be handed off to `/sbin/request-key`
    /// to generate the key.
    pub fn request_with_fallback(description: &str, info: &str) -> Result<Self> {
        Keyring::new(0).request_keyring_with_fallback(description, info)
    }

    fn get_keyring(id: SpecialKeyring, create: bool) -> Result<Keyring> {
        let res = unsafe { keyctl_get_keyring_ID(id.serial(), create as libc::c_int) };
        check_call(res as libc::c_long, Keyring::new(res))
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
        let res = unsafe { keyctl_join_session_keyring(ptr::null()) };
        check_call(res as libc::c_long, Keyring::new(res))
    }

    /// If a keyring named `name` exists, attach it as the session keyring (requires the `search`
    /// permission). If a keyring does not exist, create it and attach it as the session keyring.
    pub fn join_session(name: &str) -> Result<Self> {
        let name_cstr = CString::new(name).unwrap();
        let res = unsafe { keyctl_join_session_keyring(name_cstr.as_ptr()) };
        check_call(res as libc::c_long, Keyring::new(res))
    }

    /// Clears the contents of the keyring. Requires `write` permission on the keyring.
    pub fn clear(&mut self) -> Result<()> {
        check_call(unsafe { keyctl_clear(self.id) }, ())
    }

    /// Adds a link to `key` to the keyring. Any link to an existing key with the same description
    /// is removed. Requires `write` permission on the keyring and `link` permission on the key.
    pub fn link_key(&mut self, key: &Key) -> Result<()> {
        check_call(unsafe { keyctl_link(key.id, self.id) }, ())
    }

    /// Removes the link to `key` from the keyring. Requires `write` permission on the keyring.
    pub fn unlink_key(&mut self, key: &Key) -> Result<()> {
        check_call(unsafe { keyctl_unlink(key.id, self.id) }, ())
    }

    /// Adds a link to `keyring` to the keyring. Any link to an existing keyring with the same
    /// description is removed. Requires `write` permission on the current keyring and `link`
    /// permission on the linked keyring.
    pub fn link_keyring(&mut self, keyring: &Keyring) -> Result<()> {
        check_call(unsafe { keyctl_link(keyring.id, self.id) }, ())
    }

    /// Removes the link to `keyring` from the keyring. Requires `write` permission on the keyring.
    pub fn unlink_keyring(&mut self, keyring: &Keyring) -> Result<()> {
        check_call(unsafe { keyctl_unlink(keyring.id, self.id) }, ())
    }

    fn _search(&self, type_: &str, description: &str) -> Result<libc::c_long> {
        let type_cstr = CString::new(type_).unwrap();
        let desc_cstr = CString::new(description).unwrap();
        check_call_ret(unsafe {
            keyctl_search(self.id, type_cstr.as_ptr(), desc_cstr.as_ptr(), self.id)
        })
    }

    /// Recursively search the keyring for a key with the matching description. If it is found, it
    /// is attached to the keyring (if `write` permission to the keyring and `link` permission on
    /// the key exist) and return it. Requires the `search` permission on the keyring. Any children
    /// keyrings without the `search` permission are ignored.
    pub fn search_for_key(&self, description: &str) -> Result<Key> {
        let res = try!(self._search("user", description));
        check_call(res, Key::new(res as key_serial_t))
    }

    /// Recursively search the keyring for a keyring with the matching description. If it is found,
    /// it is attached to the keyring (if `write` permission to the keyring and `link` permission
    /// on the found keyring exist) and return it. Requires the `search` permission on the keyring.
    /// Any children keyrings without the `search` permission are ignored.
    pub fn search_for_keyring(&self, description: &str) -> Result<Self> {
        let res = try!(self._search("keyring", description));
        check_call(res, Keyring::new(res as key_serial_t))
    }

    /// Return all immediate children of the keyring. Requires `read` permission on the keyring.
    pub fn read(&self) -> Result<(Vec<Key>, Vec<Keyring>)> {
        let sz = try!(check_call_ret(unsafe { keyctl_read(self.id, ptr::null_mut(), 0) }));
        let mut buffer = Vec::<key_serial_t>::with_capacity((sz as usize) /
                                                            mem::size_of::<KeyringSerial>());
        let actual_sz = try!(check_call_ret(unsafe {
            keyctl_read(self.id,
                        buffer.as_mut_ptr() as *mut libc::c_char,
                        sz as usize)
        }));
        unsafe { buffer.set_len((actual_sz as usize) / mem::size_of::<KeyringSerial>()) };
        let keys = buffer.iter()
            .map(|&id| Key::new(id))
            .partition(|key| key.description().unwrap().type_ == "keyring");
        Ok((keys.1,
            keys.0
            .iter()
            .map(|key| Keyring::new(key.id))
            .collect::<Vec<_>>()))
    }

    /// Attach the persistent keyring for the current user to the current keyring. If one does not
    /// exist, it will be created. Requires `write` permission on the keyring.
    pub fn attach_persistent(&mut self) -> Result<Self> {
        let res = unsafe { keyctl_get_persistent(!0, self.id) };
        check_call(res, Keyring::new(res as key_serial_t))
    }

    /// Adds a key of a specific type to the keyring. The type can be either KeyType::Logon or KeyType::User.
    /// If a key with the same description already exists and has the
    /// `update` permission, it will be updated, otherwise the link to the old key will be removed.
    /// Requires `write` permission.
    pub fn add_key(&mut self, keytype: KeyType, description: &str, payload: &[u8]) -> Result<Key> {
        let type_cstr = CString::new(keytype.value()).unwrap();
        let desc_cstr = CString::new(description).unwrap();
        let res = unsafe {
            add_key(type_cstr.as_ptr(),
                    desc_cstr.as_ptr(),
                    payload.as_ptr() as *const libc::c_void,
                    payload.len(),
                    self.id)
        };
        check_call(res as libc::c_long, Key::new(res))
    }

    /// Adds a keyring to the current keyring. If a keyring with the same description already, the
    /// link to the old keyring will be removed. Requires `write` permission on the keyring.
    pub fn add_keyring(&mut self, description: &str) -> Result<Self> {
        let type_cstr = CString::new("keyring").unwrap();
        let desc_cstr = CString::new(description).unwrap();
        let res = unsafe {
            add_key(type_cstr.as_ptr(),
                    desc_cstr.as_ptr(),
                    ptr::null(),
                    0,
                    self.id)
        };
        check_call(res as libc::c_long, Keyring::new(res))
    }

    fn _request(&self, type_: &str, description: &str) -> Result<KeyringSerial> {
        let type_cstr = CString::new(type_).unwrap();
        let desc_cstr = CString::new(description).unwrap();
        check_call_ret_serial(unsafe {
            request_key(type_cstr.as_ptr(), desc_cstr.as_ptr(), ptr::null(), self.id)
        })
    }

    /// Requests a keyring with the given description by searching the thread, process, and session
    /// keyrings. If it is found, it is attached to the keyring.
    pub fn request_key(&self, description: &str) -> Result<Key> {
        let res = try!(self._request("user", description));
        check_call(res as libc::c_long, Key::new(res))
    }

    /// Requests a keyring with the given description by searching the thread, process, and session
    /// keyrings. If it is found, it is attached to the keyring.
    pub fn request_keyring(&self, description: &str) -> Result<Self> {
        let res = try!(self._request("keyring", description));
        check_call(res as libc::c_long, Keyring::new(res))
    }

    fn _request_fallback(&self, type_: &str, description: &str, info: &str) -> Result<KeyringSerial> {
        let type_cstr = CString::new(type_).unwrap();
        let desc_cstr = CString::new(description).unwrap();
        let info_cstr = CString::new(info).unwrap();
        check_call_ret_serial(unsafe {
            request_key(type_cstr.as_ptr(),
                        desc_cstr.as_ptr(),
                        info_cstr.as_ptr(),
                        self.id)
        })
    }

    /// Requests a key with the given description by searching the thread, process, and session
    /// keyrings. If it is not found, the `info` string will be handed off to `/sbin/request-key`
    /// to generate the key. If found, it will be attached to the current keyring. Requires `write`
    /// permission to the keyring.
    pub fn request_key_with_fallback(&self, description: &str, info: &str) -> Result<Key> {
        let res = try!(self._request_fallback("user", description, info));
        check_call(res as libc::c_long, Key::new(res))
    }

    /// Requests a keyring with the given description by searching the thread, process, and session
    /// keyrings. If it is not found, the `info` string will be handed off to `/sbin/request-key`
    /// to generate the key. If found, it will be attached to the current keyring. Requires `write`
    /// permission to the keyring.
    pub fn request_keyring_with_fallback(&self, description: &str, info: &str) -> Result<Self> {
        let res = try!(self._request_fallback("keyring", description, info));
        check_call(res as libc::c_long, Keyring::new(res))
    }

    /// Revokes the keyring. Requires `write` permission on the keyring.
    pub fn revoke(self) -> Result<()> {
        check_call(unsafe { keyctl_revoke(self.id) }, ())
    }

    /// Change the user which owns the keyring. Requires the `setattr` permission on the keyring
    /// and the SysAdmin capability to change it to anything other than the current user.
    pub fn chown(&mut self, uid: libc::uid_t) -> Result<()> {
        check_call(unsafe { keyctl_chown(self.id, uid, !0) }, ())
    }

    /// Change the group which owns the keyring. Requires the `setattr` permission on the keyring
    /// and the SysAdmin capability to change it to anything other than a group of which the
    /// current user is a member.
    pub fn chgrp(&mut self, gid: libc::gid_t) -> Result<()> {
        check_call(unsafe { keyctl_chown(self.id, !0, gid) }, ())
    }

    /// Set the permissions on the keyring. Requires the `setattr` permission on the keyring and
    /// the SysAdmin capability if the current user does not own the keyring.
    pub fn set_permissions(&mut self, perms: KeyPermissions) -> Result<()> {
        check_call(unsafe { keyctl_setperm(self.id, perms) }, ())
    }

    fn description_raw(&self) -> Result<String> {
        let sz = try!(check_call_ret(unsafe { keyctl_describe(self.id, ptr::null_mut(), 0) }));
        let mut buffer = Vec::with_capacity(sz as usize);
        let actual_sz = try!(check_call_ret(unsafe {
            keyctl_describe(self.id,
                            buffer.as_mut_ptr() as *mut libc::c_char,
                            sz as usize)
        }));
        unsafe { buffer.set_len((actual_sz - 1) as usize) };
        let str_slice = str::from_utf8(&buffer[..]).unwrap();
        Ok(str_slice.to_owned())
    }

    /// Retrieve metadata about the keyring.
    ///
    /// # Panics
    ///
    /// If the kernel returns malformed data, the the parser will panic.
    pub fn description(&self) -> Result<KeyDescription> {
        self.description_raw()
            .and_then(|desc| KeyDescription::parse(desc).ok_or(errno::Errno(libc::EINVAL)))
    }

    /// Set an expiration timer on the keyring to `timeout` seconds in the future. A timeout of 0
    /// means "no expiration". Requires the `setattr` permission on the keyring.
    pub fn set_timeout(&mut self, timeout: u32) -> Result<()> {
        check_call(unsafe { keyctl_set_timeout(self.id, timeout) }, ())
    }

    /// The security context of the keyring. Depends on the security manager loaded into the kernel
    /// (e.g., SELinux or AppArmor).
    pub fn security(&self) -> Result<String> {
        let sz = try!(check_call_ret(unsafe { keyctl_get_security(self.id, ptr::null_mut(), 0) }));
        let mut buffer = Vec::with_capacity(sz as usize);
        let actual_sz = try!(check_call_ret(unsafe {
            keyctl_get_security(self.id,
                                buffer.as_mut_ptr() as *mut libc::c_char,
                                sz as usize)
        }));
        unsafe { buffer.set_len(actual_sz as usize) };
        let str_slice = str::from_utf8(&buffer[..]).unwrap();
        Ok(str_slice.to_owned())
    }

    /// Invalidates the keyring and schedules it for removal. Requires the `search` permission on
    /// the keyring.
    pub fn invalidate(self) -> Result<()> {
        check_call(unsafe { keyctl_invalidate(self.id) }, ())
    }
}

/// Representation of a kernel key.
pub struct Key {
    id: KeyringSerial,
}

impl Key {
    fn new(id: KeyringSerial) -> Self {
        Key {
            id: id,
        }
    }

    /// Requests a key with the given description by searching the thread, process, and session
    /// keyrings.
    pub fn request_key_auth_key(create: bool) -> Result<Self> {
        let res = unsafe { keyctl_get_keyring_ID(KEY_SPEC_REQKEY_AUTH_KEY, create as libc::c_int) };
        check_call(res as libc::c_long, Key::new(res))
    }

    /// Requests a key with the given description by searching the thread, process, and session
    /// keyrings.
    pub fn request(description: &str) -> Result<Self> {
        Keyring::new(0).request_key(description)
    }

    /// Requests a key with the given description by searching the thread, process, and session
    /// keyrings. If it is not found, the `info` string will be handed off to `/sbin/request-key`
    /// to generate the key.
    pub fn request_with_fallback(description: &str, info: &str) -> Result<Self> {
        Keyring::new(0).request_key_with_fallback(description, info)
    }

    /// Update the payload in the key.
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        check_call(unsafe {
                       keyctl_update(self.id, data.as_ptr() as *const libc::c_void, data.len())
                   },
                   ())
    }

    /// Revokes the key. Requires `write` permission on the key.
    pub fn revoke(self) -> Result<()> {
        Keyring::new(self.id).revoke()
    }

    /// Change the user which owns the key. Requires the `setattr` permission on the key and the
    /// SysAdmin capability to change it to anything other than the current user.
    pub fn chown(&mut self, uid: libc::uid_t) -> Result<()> {
        Keyring::new(self.id).chown(uid)
    }

    /// Change the group which owns the key. Requires the `setattr` permission on the key and the
    /// SysAdmin capability to change it to anything other than a group of which the current user
    /// is a member.
    pub fn chgrp(&mut self, gid: libc::gid_t) -> Result<()> {
        Keyring::new(self.id).chgrp(gid)
    }

    /// Set the permissions on the key. Requires the `setattr` permission on the key and the
    /// SysAdmin capability if the current user does not own the key.
    pub fn set_permissions(&mut self, perms: KeyPermissions) -> Result<()> {
        Keyring::new(self.id).set_permissions(perms)
    }

    /// Retrieve metadata about the key.
    ///
    /// # Panics
    ///
    /// If the kernel returns malformed data, the parser will panic.
    pub fn description(&self) -> Result<KeyDescription> {
        Keyring::new(self.id).description()
    }

    /// Read the payload of the key. Requires `read` permissions on the key.
    pub fn read(&self) -> Result<Vec<u8>> {
        let sz = try!(check_call_ret(unsafe { keyctl_read(self.id, ptr::null_mut(), 0) }));
        let mut buffer = Vec::with_capacity(sz as usize);
        let actual_sz = try!(check_call_ret(unsafe {
            keyctl_read(self.id,
                        buffer.as_mut_ptr() as *mut libc::c_char,
                        sz as usize)
        }));
        unsafe { buffer.set_len(actual_sz as usize) };
        Ok(buffer)
    }

    /// Set an expiration timer on the key to `timeout` seconds in the future. A timeout of 0 means
    /// "no expiration". Requires the `setattr` permission on the key.
    pub fn set_timeout(&mut self, timeout: u32) -> Result<()> {
        Keyring::new(self.id).set_timeout(timeout)
    }

    /// The security context of the key. Depends on the security manager loaded into the kernel
    /// (e.g., SELinux or AppArmor).
    pub fn security(&self) -> Result<String> {
        Keyring::new(self.id).security()
    }

    /// Invalidates the key and schedules it for removal. Requires the `search` permission on the
    /// key.
    pub fn invalidate(self) -> Result<()> {
        Keyring::new(self.id).invalidate()
    }

    /// Create an object to manage a key request.
    pub fn manage(&mut self) -> Result<KeyManager> {
        check_call(unsafe { keyctl_assume_authority(self.id) },
                   KeyManager::new(Key::new(self.id)))
    }
}

/// Structure representing the metadata about a key or keyring.
pub struct KeyDescription {
    /// The type of the key.
    pub type_: String,
    /// The user owner of the key.
    pub uid: libc::uid_t,
    /// The group owner of the key.
    pub gid: libc::gid_t,
    /// The permissions of the key.
    pub perms: KeyPermissions,
    /// The plaintext description of the key.
    pub description: String,
}

impl KeyDescription {
    fn parse(desc: String) -> Option<KeyDescription> {
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
                println!("New fields detected! Please report this upstream to \
                          https://github.com/mathstuf/rust-keyutils: {}",
                         desc);
            }
            Some(KeyDescription {
                type_: pieces[4].to_owned(),
                uid: pieces[3].parse::<libc::uid_t>().unwrap(),
                gid: pieces[2].parse::<libc::gid_t>().unwrap(),
                perms: KeyPermissions::from_str_radix(pieces[1], 16).unwrap(),
                description: pieces[0].to_owned(),
            })
        }
    }
}

/// A manager for a key to respond to instantiate a key request by the kernel.
pub struct KeyManager {
    key: Key,
}

impl KeyManager {
    fn new(key: Key) -> Self {
        KeyManager {
            key: key,
        }
    }

    /// Instantiate the key with the given payload.
    pub fn instantiate(self, keyring: &Keyring, payload: &[u8]) -> Result<()> {
        check_call(unsafe {
                       keyctl_instantiate(self.key.id,
                                          payload.as_ptr() as *const libc::c_void,
                                          payload.len(),
                                          keyring.id)
                   },
                   ())
    }

    /// Reject the key with the given `error`. Requests for the key will fail until `timeout`
    /// seconds have elapsed. This is to prevent a denial-of-service by requesting a non-existant
    /// key repeatedly. The requester must have `write` permission on the keyring.
    ///
    /// TODO: Accept `SpecialKeyring` values here. They are special in that they refer to the
    /// *requester's* special keyring and not this one.
    pub fn reject(self, keyring: &Keyring, timeout: u32, error: errno::Errno) -> Result<()> {
        let errno::Errno(errval) = error;
        check_call(unsafe { keyctl_reject(self.key.id, timeout, errval as u32, keyring.id) },
                   ())
    }

    /// Reject the key with `ENOKEY`.
    pub fn negate(self, keyring: &Keyring, timeout: u32) -> Result<()> {
        check_call(unsafe { keyctl_negate(self.key.id, timeout, keyring.id) },
                   ())
    }
}

#[test]
fn test_add_key() {
    let mut keyring = Keyring::attach_or_create(SpecialKeyring::ThreadKeyring).unwrap();

    // Create the key.
    let description = "test:ruskey:add_key";
    let payload = "payload";
    let key = keyring.add_key(KeyType::User, description, payload.as_bytes()).unwrap();
    assert_eq!(key.read().unwrap(),
               payload.as_bytes().iter().cloned().collect::<Vec<_>>());

    // Update the key.
    let new_payload = "new_payload";
    let updated_key = keyring.add_key(KeyType::User, description, new_payload.as_bytes()).unwrap();
    assert_eq!(key.read().unwrap(),
               new_payload.as_bytes().iter().cloned().collect::<Vec<_>>());
    assert_eq!(updated_key.read().unwrap(),
               new_payload.as_bytes().iter().cloned().collect::<Vec<_>>());

    // Clean up.
    keyring.unlink_key(&key).unwrap();
    keyring.invalidate().unwrap();
}

#[test]
fn test_clear_keyring() {
    let mut keyring = Keyring::attach_or_create(SpecialKeyring::ThreadKeyring).unwrap();

    {
        let (keys, keyrings) = keyring.read().unwrap();
        assert_eq!(keys.len(), 0);
        assert_eq!(keyrings.len(), 0);
    }

    // Create a key.
    keyring.add_key(KeyType::User, "test:ruskey:clear_keyring", "payload".as_bytes()).unwrap();
    keyring.add_keyring("description").unwrap();

    {
        let (keys, keyrings) = keyring.read().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keyrings.len(), 1);
    }

    // Clear the keyring.
    keyring.clear().unwrap();

    {
        let (keys, keyrings) = keyring.read().unwrap();
        assert_eq!(keys.len(), 0);
        assert_eq!(keyrings.len(), 0);
    }

    keyring.invalidate().unwrap();
}

#[test]
fn test_describe_key() {
    let mut keyring = Keyring::attach_or_create(SpecialKeyring::ThreadKeyring).unwrap();

    // Create the key.
    let desc = "test:ruskey:describe_key";
    let payload = "payload";
    let key = keyring.add_key(KeyType::User, desc, payload.as_bytes()).unwrap();

    // Check its description.
    assert_eq!(key.description().unwrap().description, desc);

    // Clean up.
    keyring.unlink_key(&key).unwrap();
    keyring.invalidate().unwrap();
}

#[test]
fn test_invalidate_key() {
    unimplemented!()
}

#[test]
fn test_link_keyring() {
    unimplemented!()
}

#[test]
fn test_read_keyring() {
    unimplemented!()
}

#[test]
fn test_read_key() {
    unimplemented!()
}

#[test]
fn test_create_keyring() {
    unimplemented!()
}

#[test]
fn test_chmod_keyring() {
    unimplemented!()
}

#[test]
fn test_request_key() {
    unimplemented!()
}

#[test]
fn test_revoke_key() {
    unimplemented!()
}

#[test]
fn test_search_key() {
    unimplemented!()
}

#[test]
fn test_key_timeout() {
    unimplemented!()
}

#[test]
fn test_unlink_key() {
    unimplemented!()
}

#[test]
fn test_update_key() {
    unimplemented!()
}
