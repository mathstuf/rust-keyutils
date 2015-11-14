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
    match res {
        0   => Ok(value),
        -1  => Err(errno::errno()),
        _   => unreachable!(),
    }
}

fn get_keyring_id(id: KeyringSerial, create: bool) -> Result<KeyringSerial> {
    let res = unsafe { keyctl_get_keyring_ID(id, create as libc::c_int) };
    check_call(res as libc::c_long, res)
}

pub struct Keyring {
    id: KeyringSerial,
}

impl Keyring {
    pub fn set_default(keyring: DefaultKeyring) -> Result<()> {
        check_call(unsafe { keyctl_set_reqkey_keyring(keyring.serial()) }, ())
    }

    pub fn export_session_keyring_to_parent() -> Result<()> {
        check_call(unsafe { keyctl_session_to_parent() }, ())
    }

    pub fn attach(id: KeyringSerial) -> Result<Self> {
        get_keyring_id(id, false)
            .map(|id| {
                Keyring {
                    id: id,
                }
            })
    }

    pub fn attach_or_create(id: KeyringSerial) -> Result<Self> {
        get_keyring_id(id, true)
            .map(|id| {
                Keyring {
                    id: id,
                }
            })
    }

    pub fn join_session(name: Option<&str>) -> Result<Self> {
        let nameptr = if let Some(namestr) = name {
                CString::new(namestr).unwrap().as_ptr()
            } else {
                ptr::null()
            };
        let res = unsafe { keyctl_join_session_keyring(nameptr) };
        check_call(res as libc::c_long, res)
            .map(|id| {
                Keyring {
                    id: id,
                }
            })
    }

    pub fn clear(&mut self) -> Result<()> {
        check_call(unsafe { keyctl_clear(self.id) }, ())
    }

    pub fn link(&mut self, key: &Key) -> Result<()> {
        check_call(unsafe { keyctl_link(key.id, self.id) }, ())
    }

    pub fn unlink(&mut self, key: &Key) -> Result<()> {
        check_call(unsafe { keyctl_unlink(key.id, self.id) }, ())
    }

    pub fn search(&self, type_: &str, description: &str, dest: Option<Keyring>) -> Result<Key> {
        let typeptr = CString::new(type_).unwrap().as_ptr();
        let descptr = CString::new(description).unwrap().as_ptr();
        let destid = if let Some(dest_ring) = dest {
                dest_ring.id
            } else {
                0
            };
        let res = unsafe { keyctl_search(self.id, typeptr, descptr, destid) };
        check_call(res, Key { id: res as key_serial_t, })
    }

    pub fn read(&self) -> Result<Vec<Key>> {
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

    pub fn request_key(&mut self) -> Result<Key> {
        unimplemented!()
    }
}

pub struct Key {
    id: KeyringSerial,
}

impl Key {
    pub fn keyring(&self) -> Result<Keyring> {
        get_keyring_id(self.id, false)
            .map(|id| {
                Keyring {
                    id: id,
                }
            })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        check_call(unsafe { keyctl_update(self.id, data.as_ptr() as *const libc::c_void, data.len()) }, ())
    }

    pub fn revoke(self) -> Result<()> {
        check_call(unsafe { keyctl_revoke(self.id) }, ())
    }

    pub fn chown(&mut self, uid: uid_t, gid: gid_t) -> Result<()> {
        check_call(unsafe { keyctl_chown(self.id, uid, gid) }, ())
    }

    pub fn set_permissions(&mut self, perms: KeyPermissions) -> Result<()> {
        check_call(unsafe { keyctl_setperm(self.id, perms) }, ())
    }

    pub fn description(&self) -> Result<String> {
        let sz = unsafe { keyctl_describe(self.id, ptr::null_mut(), 0) };
        if sz < 0 {
            return Err(errno::errno());
        }
        let mut buffer = Vec::with_capacity(sz as usize);
        let res = unsafe { keyctl_describe(self.id, buffer.as_mut_ptr() as *mut libc::c_char, sz as usize) };
        if res < 0 {
            return Err(errno::errno());
        }
        let str_slice = str::from_utf8(&buffer[..]).unwrap();
        Ok(str_slice.to_owned())
    }

    pub fn read(&self) -> Result<Vec<u8>> {
        let sz = unsafe { keyctl_read(self.id, ptr::null_mut(), 0) };
        if sz < 0 {
            return Err(errno::errno());
        }
        let mut buffer = Vec::with_capacity(sz as usize);
        let res = unsafe { keyctl_read(self.id, buffer.as_mut_ptr() as *mut libc::c_char, sz as usize) };
        if res < 0 {
            return Err(errno::errno());
        }
        Ok(buffer)
    }

    pub fn set_timeout(&mut self, timeout: u32) -> Result<()> {
        check_call(unsafe { keyctl_set_timeout(self.id, timeout) }, ())
    }

    pub fn get_security(&self) -> Result<String> {
        let sz = unsafe { keyctl_get_security(self.id, ptr::null_mut(), 0) };
        if sz < 0 {
            return Err(errno::errno());
        }
        let mut buffer = Vec::with_capacity(sz as usize);
        let res = unsafe { keyctl_get_security(self.id, buffer.as_mut_ptr() as *mut libc::c_char, sz as usize) };
        if res < 0 {
            return Err(errno::errno());
        }
        let str_slice = str::from_utf8(&buffer[..]).unwrap();
        Ok(str_slice.to_owned())
    }

    pub fn invalidate(self) -> Result<()> {
        check_call(unsafe { keyctl_invalidate(self.id) }, ())
    }
}
