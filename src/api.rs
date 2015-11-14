extern crate errno;

extern crate libc;

use super::constants::*;
use super::ffi::*;

use std::ffi::CString;
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

fn get_keyring(id: KeyringSerial, create: bool) -> Result<Keyring> {
    let res = unsafe { keyctl_get_keyring_ID(id, create as libc::c_int) };
    check_call(res as libc::c_long, Keyring { id: res, })
}

pub struct Keyring {
    id: KeyringSerial,
}

impl Keyring {
    pub fn set_default(keyring: DefaultKeyring) -> Result<()> {
        check_call(unsafe { keyctl_set_reqkey_keyring(keyring.serial()) }, ())
    }

    pub fn attach(id: KeyringSerial) -> Result<Self> {
        get_keyring(id, false)
    }

    pub fn attach_or_create(id: KeyringSerial) -> Result<Self> {
        get_keyring(id, true)
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

    pub fn link(&mut self, key: &Key) -> Result<()> {
        check_call(unsafe { keyctl_link(key.id, self.id) }, ())
    }

    pub fn search(&mut self, type_: &str, description: &str) -> Result<Key> {
        let typeptr = CString::new(type_).unwrap().as_ptr();
        let descptr = CString::new(description).unwrap().as_ptr();
        let res = unsafe { keyctl_search(self.id, typeptr, descptr, self.id) };
        check_call(res, Key { id: res as key_serial_t, })
    }

    pub fn read(&self) -> Result<Vec<Key>> {
        let sz = try!(check_call_ret(unsafe { keyctl_read(self.id, ptr::null_mut(), 0) }));
        let mut buffer = Vec::with_capacity(sz as usize);
        try!(check_call_ret(unsafe { keyctl_read(self.id, buffer.as_mut_ptr() as *mut libc::c_char, sz as usize) }));
        // TODO: turn bytestream into vec of keys
        unimplemented!()
    }

    pub fn attach_persistent(&mut self) -> Result<Keyring> {
        let res = unsafe { keyctl_get_persistent(-1, self.id) };
        check_call(res, Keyring { id: res as key_serial_t, })
    }

    pub fn add_key(&mut self, description: &str, payload: &[u8]) -> Result<Key> {
        let typeptr = CString::new("user").unwrap().as_ptr();
        let descptr = CString::new(description).unwrap().as_ptr();
        let res = unsafe { add_key(typeptr, descptr, payload.as_ptr() as *const libc::c_void, payload.len(), self.id) };
        check_call(res as libc::c_long, Key { id: res, })
    }

    pub fn add_keyring(&mut self) -> Result<Keyring> {
        let typeptr = CString::new("keyring").unwrap().as_ptr();
        let res = unsafe { add_key(typeptr, ptr::null(), ptr::null(), 0, self.id) };
        check_call(res as libc::c_long, Keyring { id: res, })
    }

    pub fn find_key(&mut self, type_: &str, description: &str) -> Result<Key> {
        let typeptr = CString::new(type_).unwrap().as_ptr();
        let descptr = CString::new(description).unwrap().as_ptr();
        let res = unsafe { find_key_by_type_and_desc(typeptr, descptr, self.id) };
        check_call(res as libc::c_long, Key { id: res, })
    }

    pub fn request_key(&mut self, type_: &str, description: &str) -> Result<Key> {
        let typeptr = CString::new(type_).unwrap().as_ptr();
        let descptr = CString::new(description).unwrap().as_ptr();
        let res = unsafe { request_key(typeptr, descptr, ptr::null(), self.id) };
        check_call(res as libc::c_long, Key { id: res, })
    }

    pub fn request_key_with_fallback(&mut self, type_: &str, description: &str, info: &str) -> Result<Key> {
        let typeptr = CString::new(type_).unwrap().as_ptr();
        let descptr = CString::new(description).unwrap().as_ptr();
        let infoptr = CString::new(info).unwrap().as_ptr();
        let res = unsafe { request_key(typeptr, descptr, infoptr, self.id) };
        check_call(res as libc::c_long, Key { id: res, })
    }
}

pub struct Key {
    id: KeyringSerial,
}

extern fn unlink_cb(
    parent:     key_serial_t,
    key:        key_serial_t,
    desc:       *mut libc::c_char,
    desc_len:   libc::c_int,
    data:       *mut libc::c_void)
    -> libc::c_int {
    unimplemented!()
}

impl Key {
    pub fn request(type_: &str, description: &str) -> Result<Key> {
        let mut keyring = Keyring { id: 0, };
        keyring.request_key(type_, description)
    }

    pub fn request_with_fallback(type_: &str, description: &str, info: &str) -> Result<Key> {
        let mut keyring = Keyring { id: 0, };
        keyring.request_key_with_fallback(type_, description, info)
    }

    pub fn find(type_: &str, description: &str) -> Result<Key> {
        let mut keyring = Keyring { id: 0, };
        keyring.find_key(type_, description)
    }

    pub fn search(type_: &str, description: &str) -> Result<Key> {
        let mut keyring = Keyring { id: 0, };
        keyring.search(type_, description)
    }

    pub fn keyring(&self) -> Result<Keyring> {
        get_keyring(self.id, false)
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        check_call(unsafe { keyctl_update(self.id, data.as_ptr() as *const libc::c_void, data.len()) }, ())
    }

    pub fn unlink(self, keyring: &Keyring) -> Result<()> {
        check_call(unsafe { keyctl_unlink(self.id, keyring.id) }, ())
    }

    pub fn unlink_from_all(self, keyring: &mut Keyring) -> usize {
        let mut id_copy = self.id;
        let data: *mut KeyringSerial = &mut id_copy;
        let ret = unsafe { recursive_key_scan(keyring.id, unlink_cb, data as *mut libc::c_void) };
        ret as usize
    }

    pub fn unlink_from_session(self) -> usize {
        let mut id_copy = self.id;
        let data: *mut KeyringSerial = &mut id_copy;
        let ret = unsafe { recursive_session_key_scan(unlink_cb, data as *mut libc::c_void) };
        ret as usize
    }

    pub fn revoke(self) -> Result<()> {
        check_call(unsafe { keyctl_revoke(self.id) }, ())
    }

    pub fn chown(&mut self, uid: uid_t) -> Result<()> {
        check_call(unsafe { keyctl_chown(self.id, uid, -1) }, ())
    }

    pub fn chgrp(&mut self, gid: gid_t) -> Result<()> {
        check_call(unsafe { keyctl_chown(self.id, -1, gid) }, ())
    }

    pub fn set_permissions(&mut self, perms: KeyPermissions) -> Result<()> {
        check_call(unsafe { keyctl_setperm(self.id, perms) }, ())
    }

    pub fn description(&self) -> Result<KeyDescription> {
        self.description_raw().map(|desc| {
            KeyDescription::parse(desc)
        })
    }

    fn description_raw(&self) -> Result<String> {
        let sz = try!(check_call_ret(unsafe { keyctl_describe(self.id, ptr::null_mut(), 0) }));
        let mut buffer = Vec::with_capacity(sz as usize);
        let actual_sz = try!(check_call_ret(unsafe { keyctl_describe(self.id, buffer.as_mut_ptr() as *mut libc::c_char, sz as usize) }));
        unsafe { buffer.set_len(actual_sz as usize) };
        let str_slice = str::from_utf8(&buffer[..]).unwrap();
        Ok(str_slice.to_owned())
    }

    pub fn read(&self) -> Result<Vec<u8>> {
        let sz = try!(check_call_ret(unsafe { keyctl_read(self.id, ptr::null_mut(), 0) }));
        let mut buffer = Vec::with_capacity(sz as usize);
        let actual_sz = try!(check_call_ret(unsafe { keyctl_read(self.id, buffer.as_mut_ptr() as *mut libc::c_char, sz as usize) }));
        unsafe { buffer.set_len(actual_sz as usize) };
        Ok(buffer)
    }

    pub fn set_timeout(&mut self, timeout: u32) -> Result<()> {
        check_call(unsafe { keyctl_set_timeout(self.id, timeout) }, ())
    }

    pub fn get_security(&self) -> Result<String> {
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
    fn parse(desc: String) -> KeyDescription {
        unimplemented!()
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
