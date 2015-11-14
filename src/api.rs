extern crate errno;

extern crate libc;

use super::constants::*;
use super::ffi::*;

use std::result;

pub type Error = errno::Errno;
pub type Result<T> = result::Result<T, Error>;

pub struct Keyring {
    id: KeyringSerial,
}

