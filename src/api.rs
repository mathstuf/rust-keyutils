extern crate errno;

extern crate libc;

use super::constants::*;
use super::ffi::*;

use std::ffi::CString;
use std::mem;
use std::os::unix::raw::{gid_t, uid_t};
use std::ptr;
use std::result;
use std::str;

pub type Error = errno::Errno;
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

pub struct Keyring {
    id: KeyringSerial,
}

impl Keyring {
    pub fn set_default(keyring: DefaultKeyring) -> Result<DefaultKeyring> {
        let ret = try!(check_call_ret(unsafe { keyctl_set_reqkey_keyring(keyring.serial()) }));
        Ok(DefaultKeyring::from(ret as i32))
    }

    pub fn request(description: &str) -> Result<Self> {
        Keyring { id: 0, }.request_keyring(description)
    }

    pub fn request_with_fallback(description: &str, info: &str) -> Result<Self> {
        Keyring { id: 0, }.request_keyring_with_fallback(description, info)
    }

    fn get_keyring(id: SpecialKeyring, create: bool) -> Result<Keyring> {
        let res = unsafe { keyctl_get_keyring_ID(id.serial(), create as libc::c_int) };
        check_call(res as libc::c_long, Keyring { id: res, })
    }

    pub fn attach(id: SpecialKeyring) -> Result<Self> {
        Self::get_keyring(id, false)
    }

    pub fn attach_or_create(id: SpecialKeyring) -> Result<Self> {
        Self::get_keyring(id, true)
    }

    pub fn join_anonymous_session() -> Result<Self> {
        let res = unsafe { keyctl_join_session_keyring(ptr::null()) };
        check_call(res as libc::c_long, Keyring { id: res })
    }

    pub fn join_session(name: &str) -> Result<Self> {
        let nameptr = CString::new(name).unwrap().as_ptr();
        let res = unsafe { keyctl_join_session_keyring(nameptr) };
        check_call(res as libc::c_long, Keyring { id: res })
    }

    pub fn clear(&mut self) -> Result<()> {
        check_call(unsafe { keyctl_clear(self.id) }, ())
    }

    pub fn link_key(&mut self, key: &Key) -> Result<()> {
        check_call(unsafe { keyctl_link(key.id, self.id) }, ())
    }

    pub fn unlink_key(&mut self, key: &Key) -> Result<()> {
        check_call(unsafe { keyctl_unlink(key.id, self.id) }, ())
    }

    pub fn link_keyring(&mut self, keyring: &Keyring) -> Result<()> {
        check_call(unsafe { keyctl_link(keyring.id, self.id) }, ())
    }

    pub fn unlink_keyring(&mut self, keyring: &Keyring) -> Result<()> {
        check_call(unsafe { keyctl_unlink(keyring.id, self.id) }, ())
    }

    fn _search(&self, type_: &str, description: &str) -> Result<libc::c_long> {
        let typeptr = CString::new(type_).unwrap().as_ptr();
        let descptr = CString::new(description).unwrap().as_ptr();
        check_call_ret(unsafe { keyctl_search(self.id, typeptr, descptr, self.id) })
    }

    pub fn search_for_key(&self, description: &str) -> Result<Key> {
        let res = try!(self._search("user", description));
        check_call(res, Key { id: res as key_serial_t, })
    }

    pub fn search_for_keyring(&self, description: &str) -> Result<Self> {
        let res = try!(self._search("keyring", description));
        check_call(res, Keyring { id: res as key_serial_t, })
    }

    pub fn read(&self) -> Result<(Vec<Key>, Vec<Keyring>)> {
        let sz = try!(check_call_ret(unsafe { keyctl_read(self.id, ptr::null_mut(), 0) }));
        let mut buffer = Vec::<key_serial_t>::with_capacity((sz as usize) / mem::size_of::<KeyringSerial>());
        let actual_sz = try!(check_call_ret(unsafe { keyctl_read(self.id, buffer.as_mut_ptr() as *mut libc::c_char, sz as usize) }));
        unsafe { buffer.set_len((actual_sz as usize) / mem::size_of::<KeyringSerial>()) };
        let keys = buffer.iter().map(|&id| { Key { id: id, } }).partition(|key| {
            key.description().unwrap().type_ == "user"
        });
        Ok((keys.0, keys.1.iter().map(|key| {
            Keyring {
                id: key.id,
            }
        }).collect::<Vec<Keyring>>()))
    }

    pub fn attach_persistent(&mut self) -> Result<Self> {
        let res = unsafe { keyctl_get_persistent(!0, self.id) };
        check_call(res, Keyring { id: res as key_serial_t, })
    }

    pub fn add_key(&mut self, description: &str, payload: &[u8]) -> Result<Key> {
        let typeptr = CString::new("user").unwrap().as_ptr();
        let descptr = CString::new(description).unwrap().as_ptr();
        let res = unsafe { add_key(typeptr, descptr, payload.as_ptr() as *const libc::c_void, payload.len(), self.id) };
        check_call(res as libc::c_long, Key { id: res, })
    }

    pub fn add_keyring(&mut self, description: &str) -> Result<Self> {
        let typeptr = CString::new("keyring").unwrap().as_ptr();
        let descptr = CString::new(description).unwrap().as_ptr();
        let res = unsafe { add_key(typeptr, descptr, ptr::null(), 0, self.id) };
        check_call(res as libc::c_long, Keyring { id: res, })
    }

    fn _request(&self, type_: &str, description: &str) -> Result<KeyringSerial> {
        let typeptr = CString::new(type_).unwrap().as_ptr();
        let descptr = CString::new(description).unwrap().as_ptr();
        check_call_ret_serial(unsafe { request_key(typeptr, descptr, ptr::null(), self.id) })
    }

    pub fn request_key(&self, description: &str) -> Result<Key> {
        let res = try!(self._request("user", description));
        check_call(res as libc::c_long, Key { id: res, })
    }

    pub fn request_keyring(&self, description: &str) -> Result<Self> {
        let res = try!(self._request("keyring", description));
        check_call(res as libc::c_long, Keyring { id: res, })
    }

    fn _request_fallback(&self, type_: &str, description: &str, info: &str) -> Result<KeyringSerial> {
        let typeptr = CString::new(type_).unwrap().as_ptr();
        let descptr = CString::new(description).unwrap().as_ptr();
        let infoptr = CString::new(info).unwrap().as_ptr();
        check_call_ret_serial(unsafe { request_key(typeptr, descptr, infoptr, self.id) })
    }

    pub fn request_key_with_fallback(&self, description: &str, info: &str) -> Result<Key> {
        let res = try!(self._request_fallback("user", description, info));
        check_call(res as libc::c_long, Key { id: res, })
    }

    pub fn request_keyring_with_fallback(&self, description: &str, info: &str) -> Result<Self> {
        let res = try!(self._request_fallback("keyring", description, info));
        check_call(res as libc::c_long, Keyring { id: res, })
    }

    pub fn revoke(self) -> Result<()> {
        check_call(unsafe { keyctl_revoke(self.id) }, ())
    }

    pub fn chown(&mut self, uid: uid_t) -> Result<()> {
        check_call(unsafe { keyctl_chown(self.id, uid, !0) }, ())
    }

    pub fn chgrp(&mut self, gid: gid_t) -> Result<()> {
        check_call(unsafe { keyctl_chown(self.id, !0, gid) }, ())
    }

    pub fn set_permissions(&mut self, perms: KeyPermissions) -> Result<()> {
        check_call(unsafe { keyctl_setperm(self.id, perms) }, ())
    }

    fn description_raw(&self) -> Result<String> {
        let sz = try!(check_call_ret(unsafe { keyctl_describe(self.id, ptr::null_mut(), 0) }));
        let mut buffer = Vec::with_capacity(sz as usize);
        let actual_sz = try!(check_call_ret(unsafe { keyctl_describe(self.id, buffer.as_mut_ptr() as *mut libc::c_char, sz as usize) }));
        unsafe { buffer.set_len((actual_sz - 1) as usize) };
        let str_slice = str::from_utf8(&buffer[..]).unwrap();
        Ok(str_slice.to_owned())
    }

    pub fn description(&self) -> Result<KeyDescription> {
        self.description_raw().and_then(|desc| {
            KeyDescription::parse(desc)
                .ok_or(errno::Errno(libc::EINVAL))
        })
    }

    pub fn set_timeout(&mut self, timeout: u32) -> Result<()> {
        check_call(unsafe { keyctl_set_timeout(self.id, timeout) }, ())
    }

    pub fn security(&self) -> Result<String> {
        let sz = try!(check_call_ret(unsafe { keyctl_get_security(self.id, ptr::null_mut(), 0) }));
        let mut buffer = Vec::with_capacity(sz as usize);
        let actual_sz = try!(check_call_ret(unsafe { keyctl_get_security(self.id, buffer.as_mut_ptr() as *mut libc::c_char, sz as usize) }));
        unsafe { buffer.set_len(actual_sz as usize) };
        let str_slice = str::from_utf8(&buffer[..]).unwrap();
        Ok(str_slice.to_owned())
    }

    pub fn invalidate(self) -> Result<()> {
        check_call(unsafe { keyctl_invalidate(self.id) }, ())
    }
}

pub struct Key {
    id: KeyringSerial,
}

impl Key {
    pub fn request_key_auth_key(create: bool) -> Result<Self> {
        let res = unsafe { keyctl_get_keyring_ID(KEY_SPEC_REQKEY_AUTH_KEY, create as libc::c_int) };
        check_call(res as libc::c_long, Key { id: res, })
    }

    pub fn request(description: &str) -> Result<Self> {
        Keyring { id: 0, }.request_key(description)
    }

    pub fn request_with_fallback(description: &str, info: &str) -> Result<Self> {
        Keyring { id: 0, }.request_key_with_fallback(description, info)
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        check_call(unsafe { keyctl_update(self.id, data.as_ptr() as *const libc::c_void, data.len()) }, ())
    }

    pub fn revoke(self) -> Result<()> {
        Keyring { id: self.id }.revoke()
    }

    pub fn chown(&mut self, uid: uid_t) -> Result<()> {
        Keyring { id: self.id }.chown(uid)
    }

    pub fn chgrp(&mut self, gid: gid_t) -> Result<()> {
        Keyring { id: self.id }.chgrp(gid)
    }

    pub fn set_permissions(&mut self, perms: KeyPermissions) -> Result<()> {
        Keyring { id: self.id }.set_permissions(perms)
    }

    pub fn description(&self) -> Result<KeyDescription> {
        Keyring { id: self.id }.description()
    }

    pub fn read(&self) -> Result<Vec<u8>> {
        let sz = try!(check_call_ret(unsafe { keyctl_read(self.id, ptr::null_mut(), 0) }));
        let mut buffer = Vec::with_capacity(sz as usize);
        let actual_sz = try!(check_call_ret(unsafe { keyctl_read(self.id, buffer.as_mut_ptr() as *mut libc::c_char, sz as usize) }));
        unsafe { buffer.set_len(actual_sz as usize) };
        Ok(buffer)
    }

    pub fn set_timeout(&mut self, timeout: u32) -> Result<()> {
        Keyring { id: self.id }.set_timeout(timeout)
    }

    pub fn security(&self) -> Result<String> {
        Keyring { id: self.id }.security()
    }

    pub fn invalidate(self) -> Result<()> {
        Keyring { id: self.id }.invalidate()
    }

    pub fn manage(&mut self) -> Result<KeyManager> {
        check_call(unsafe { keyctl_assume_authority(self.id) }, KeyManager {
            key: Key {
                id: self.id,
            },
        })
    }
}

pub struct KeyDescription {
    pub type_:          String,
    pub uid:            uid_t,
    pub gid:            gid_t,
    pub perms:          KeyPermissions,
    pub description:    String,
}

impl KeyDescription {
    fn parse(desc: String) -> Option<KeyDescription> {
        let mut pieces = desc.split(';').collect::<Vec<&str>>();
        // Reverse the string because the kernel plans to extend it by adding fields to the
        // beginning of the string. By doing this, the fields are at a constant position in the
        // split string.
        pieces.reverse();
        let len = pieces.len();
        if len < 5 {
            None
        } else {
            if len > 5 {
                println!("New fields detected! Please report this upstream to https://github.com/mathstuf/rust-keyutils: {}", desc);
            }
            Some(KeyDescription {
                type_:          pieces[4].to_owned(),
                uid:            pieces[3].parse::<uid_t>().unwrap(),
                gid:            pieces[2].parse::<gid_t>().unwrap(),
                perms:          KeyPermissions::from_str_radix(pieces[1], 16).unwrap(),
                description:    pieces[0].to_owned(),
            })
        }
    }
}

pub struct KeyManager {
    key: Key,
}

impl KeyManager {
    pub fn instantiate(self, keyring: &Keyring, payload: &[u8]) -> Result<()> {
        check_call(unsafe { keyctl_instantiate(self.key.id, payload.as_ptr() as *const libc::c_void, payload.len(), keyring.id) }, ())
    }

    pub fn reject(self, keyring: &Keyring, timeout: u32, error: errno::Errno) -> Result<()> {
        let errno::Errno(errval) = error;
        check_call(unsafe { keyctl_reject(self.key.id, timeout, errval as u32, keyring.id) }, ())
    }

    pub fn negate(self, keyring: &Keyring, timeout: u32) -> Result<()> {
        check_call(unsafe { keyctl_negate(self.key.id, timeout, keyring.id) }, ())
    }
}

#[test]
fn test_add_key() {
    let mut keyring = Keyring::attach_or_create(SpecialKeyring::SessionKeyring).unwrap();

    // Create the key.
    let payload = "payload";
    let key = keyring.add_key("description", payload.as_bytes()).unwrap();
    assert_eq!(key.read().unwrap(), payload.as_bytes().iter().cloned().collect::<Vec<u8>>());

    // Update the key.
    let new_payload = "payload";
    let updated_key = keyring.add_key("description", new_payload.as_bytes()).unwrap();
    assert_eq!(key.read().unwrap(), new_payload.as_bytes().iter().cloned().collect::<Vec<u8>>());
    assert_eq!(updated_key.read().unwrap(), new_payload.as_bytes().iter().cloned().collect::<Vec<u8>>());

    // Clean it up.
    keyring.unlink_key(&key).unwrap();
}

#[test]
fn test_clear_keyring() {
    unimplemented!()
}

#[test]
fn test_describe_key() {
    let mut keyring = Keyring::attach_or_create(SpecialKeyring::SessionKeyring).unwrap();

    // Create the key.
    let desc = "description for a key";
    let payload = "payload";
    let key = keyring.add_key(desc, payload.as_bytes()).unwrap();

    // Check its description.
    assert_eq!(key.description().unwrap().description, desc);

    // Clean it up.
    keyring.unlink_key(&key).unwrap();
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
