// Copyright (c) 2019, Ben Boeckel
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

use std::collections::HashMap;
use std::fs;
use std::str::FromStr;

use regex::{Captures, Regex};

lazy_static! {
    pub static ref PAGE_SIZE: usize = page_size();
    pub static ref UID: libc::uid_t = getuid();
    pub static ref GID: libc::gid_t = getgid();
    pub static ref KEY_INFO: KeyQuota = key_user_info();
}

fn page_size() -> usize {
    errno::set_errno(errno::Errno(0));
    let ret = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if ret < 0 {
        let err = errno::errno();
        if err.0 == 0 {
            panic!("page size is indeterminite?");
        } else {
            panic!("failed to query the page size: {}", errno::errno());
        }
    }
    ret as usize
}

const KEY_USERS_FILE: &str = "/proc/key-users";

lazy_static! {
    static ref KEY_USERS: Regex = Regex::new(
        " *(?P<uid>\\d+): +\
         (?P<usage>\\d+) \
         (?P<nkeys>\\d+)/(?P<nikeys>\\d+) \
         (?P<qnkeys>\\d+)/(?P<maxkeys>\\d+) \
         (?P<qnbytes>\\d+)/(?P<maxbytes>\\d+)"
    )
    .unwrap();
}

fn by_name<T: FromStr>(capture: &Captures, name: &str) -> T {
    let cap = capture
        .name(name)
        .expect("name should be captured")
        .as_str();
    match cap.parse() {
        Ok(v) => v,
        Err(_) => panic!("failed to parse {} as an integer", name),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KeyQuota {
    pub usage: usize,
    pub nkeys: usize,
    pub nikeys: usize,
    pub qnkeys: usize,
    pub maxkeys: usize,
    pub qnbytes: usize,
    pub maxbytes: usize,
}

fn all_key_user_info() -> HashMap<libc::uid_t, KeyQuota> {
    let data = String::from_utf8(fs::read(KEY_USERS_FILE).unwrap()).unwrap();
    (*KEY_USERS)
        .captures_iter(&data)
        .map(|capture| {
            let uid = by_name(&capture, "uid");
            let usage = by_name(&capture, "usage");
            let nkeys = by_name(&capture, "nkeys");
            let nikeys = by_name(&capture, "nikeys");
            let qnkeys = by_name(&capture, "qnkeys");
            let maxkeys = by_name(&capture, "maxkeys");
            let qnbytes = by_name(&capture, "qnbytes");
            let maxbytes = by_name(&capture, "maxbytes");

            (
                uid,
                KeyQuota {
                    usage,
                    nkeys,
                    nikeys,
                    qnkeys,
                    maxkeys,
                    qnbytes,
                    maxbytes,
                },
            )
        })
        .collect()
}

fn key_user_info() -> KeyQuota {
    let uid = unsafe { libc::getuid() };
    *all_key_user_info()
        .get(&uid)
        .expect("the current user has no keys?")
}

fn getuid() -> libc::uid_t {
    unsafe { libc::getuid() }
}

fn getgid() -> libc::gid_t {
    unsafe { libc::getgid() }
}
