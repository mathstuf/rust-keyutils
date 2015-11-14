extern crate libc;

#[allow(non_camel_case_types)]
pub type key_serial_t = libc::int32_t;

pub static KEY_SPEC_THREAD_KEYRING:         key_serial_t = -1;
pub static KEY_SPEC_PROCESS_KEYRING:        key_serial_t = -2;
pub static KEY_SPEC_SESSION_KEYRING:        key_serial_t = -3;
pub static KEY_SPEC_USER_KEYRING:           key_serial_t = -4;
pub static KEY_SPEC_USER_SESSION_KEYRING:   key_serial_t = -5;
pub static KEY_SPEC_GROUP_KEYRING:          key_serial_t = -6;
pub static KEY_SPEC_REQKEY_AUTH_KEY:        key_serial_t = -7;

pub static KEY_REQKEY_DEFL_NO_CHANGE:               key_serial_t = -1;
pub static KEY_REQKEY_DEFL_DEFAULT:                 key_serial_t = 0;
pub static KEY_REQKEY_DEFL_THREAD_KEYRING:          key_serial_t = 1;
pub static KEY_REQKEY_DEFL_PROCESS_KEYRING:         key_serial_t = 2;
pub static KEY_REQKEY_DEFL_SESSION_KEYRING:         key_serial_t = 3;
pub static KEY_REQKEY_DEFL_USER_KEYRING:            key_serial_t = 4;
pub static KEY_REQKEY_DEFL_USER_SESSION_KEYRING:    key_serial_t = 5;
pub static KEY_REQKEY_DEFL_GROUP_KEYRING:           key_serial_t = 6;

#[allow(non_camel_case_types)]
pub type key_perm_t = libc::uint32_t;

pub static KEY_POS_VIEW:    key_perm_t = 0x01000000;     /* possessor can view a key's attributes */
pub static KEY_POS_READ:    key_perm_t = 0x02000000;     /* possessor can read key payload / view keyring */
pub static KEY_POS_WRITE:   key_perm_t = 0x04000000;     /* possessor can update key payload / add link to keyring */
pub static KEY_POS_SEARCH:  key_perm_t = 0x08000000;     /* possessor can find a key in search / search a keyring */
pub static KEY_POS_LINK:    key_perm_t = 0x10000000;     /* possessor can create a link to a key/keyring */
pub static KEY_POS_SETATTR: key_perm_t = 0x20000000;     /* possessor can set key attributes */
pub static KEY_POS_ALL:     key_perm_t = 0x3f000000;

pub static KEY_USR_VIEW:    key_perm_t = 0x00010000;     /* user permissions... */
pub static KEY_USR_READ:    key_perm_t = 0x00020000;
pub static KEY_USR_WRITE:   key_perm_t = 0x00040000;
pub static KEY_USR_SEARCH:  key_perm_t = 0x00080000;
pub static KEY_USR_LINK:    key_perm_t = 0x00100000;
pub static KEY_USR_SETATTR: key_perm_t = 0x00200000;
pub static KEY_USR_ALL:     key_perm_t = 0x003f0000;

pub static KEY_GRP_VIEW:    key_perm_t = 0x00000100;     /* group permissions... */
pub static KEY_GRP_READ:    key_perm_t = 0x00000200;
pub static KEY_GRP_WRITE:   key_perm_t = 0x00000400;
pub static KEY_GRP_SEARCH:  key_perm_t = 0x00000800;
pub static KEY_GRP_LINK:    key_perm_t = 0x00001000;
pub static KEY_GRP_SETATTR: key_perm_t = 0x00002000;
pub static KEY_GRP_ALL:     key_perm_t = 0x00003f00;

pub static KEY_OTH_VIEW:    key_perm_t = 0x00000001;     /* third party permissions... */
pub static KEY_OTH_READ:    key_perm_t = 0x00000002;
pub static KEY_OTH_WRITE:   key_perm_t = 0x00000004;
pub static KEY_OTH_SEARCH:  key_perm_t = 0x00000008;
pub static KEY_OTH_LINK:    key_perm_t = 0x00000010;
pub static KEY_OTH_SETATTR: key_perm_t = 0x00000020;
pub static KEY_OTH_ALL:     key_perm_t = 0x0000003f;

#[allow(non_camel_case_types)]
type recursive_key_scanner_t =
    extern fn(
        parent:     key_serial_t,
        key:        key_serial_t,
        desc:       *mut libc::c_char,
        desc_len:   libc::c_int,
        data:       *mut libc::c_void)
        -> libc::c_int;

#[link(name = "keyutils")]
extern {
    pub fn add_key(
        type_:          *const libc::c_char,
        description:    *const libc::c_char,
        payload:        *const libc::c_void,
        plen:           libc::size_t,
        keyring:        key_serial_t)
        -> key_serial_t;
    pub fn request_key(
        type_:          *const libc::c_char,
        description:    *const libc::c_char,
        callout_info:   *const libc::c_char,
        keyring:        key_serial_t)
        -> key_serial_t;

    pub fn keyctl_get_keyring_ID(
        id:     key_serial_t,
        create: libc::c_int)
        -> key_serial_t;
    pub fn keyctl_join_session_keyring(
        name:   *const libc::c_char)
        -> key_serial_t;
    pub fn keyctl_update(
        id:         key_serial_t,
        payload:    *const libc::c_void,
        plen:       libc::size_t)
        -> libc::c_long;
    pub fn keyctl_revoke(
        id: key_serial_t)
        -> libc::c_long;
    pub fn keyctl_chown(
        id:     key_serial_t,
        uid:    libc::uid_t,
        gid:    libc::gid_t)
        -> libc::c_long;
    pub fn keyctl_setperm(
        id:     key_serial_t,
        perm:   key_perm_t)
        -> libc::c_long;
    pub fn keyctl_describe(
        id:     key_serial_t,
        buffer: *mut libc::c_char,
        buflen: libc::size_t)
        -> libc::c_long;
    pub fn keyctl_clear(
        ringid: key_serial_t)
        -> libc::c_long;
    pub fn keyctl_link(
        id:     key_serial_t,
        ringid: key_serial_t)
        -> libc::c_long;
    pub fn keyctl_unlink(
        id:     key_serial_t,
        ringid: key_serial_t)
        -> libc::c_long;
    pub fn keyctl_search(
        ringid:         key_serial_t,
        type_:          *const libc::c_char,
        description:    *const libc::c_char,
        destringid:     key_serial_t)
        -> libc::c_long;
    pub fn keyctl_read(
        id:     key_serial_t,
        buffer: *mut libc::c_char,
        buflen: libc::size_t)
        -> libc::c_long;
    pub fn keyctl_instantiate(
        id:         key_serial_t,
        payload:    *const libc::c_void,
        plen:       libc::size_t,
        ringid:     key_serial_t)
        -> libc::c_long;
    pub fn keyctl_negate(
        id:         key_serial_t,
        timeout:    libc::c_uint,
        ringid:     key_serial_t)
        -> libc::c_long;
    pub fn keyctl_set_reqkey_keyring(
        reqkey_defl:    libc::c_int)
        -> libc::c_long;
    pub fn keyctl_set_timeout(
        key:        key_serial_t,
        timeout:    libc::c_uint)
        -> libc::c_long;
    pub fn keyctl_assume_authority(
        key:    key_serial_t)
        -> libc::c_long;
    pub fn keyctl_get_security(
        key:    key_serial_t,
        buffer: *mut libc::c_char,
        buflen: libc::size_t)
        -> libc::c_long;
    pub fn keyctl_session_to_parent()
        -> libc::c_long;
    pub fn keyctl_reject(
        id:         key_serial_t,
        timeout:    libc::c_uint,
        error:      libc::c_uint,
        ringid:     key_serial_t)
        -> libc::c_long;
    //struct iovec;
    pub fn keyctl_instantiate_iov(
        id:             key_serial_t,
        payload_iov:    *const libc::c_void,
        //payload_iov:    *const struct iovec,
        ioc:            libc::c_uint,
        ringid:         key_serial_t)
        -> libc::c_long;
    pub fn keyctl_invalidate(
        id: key_serial_t)
        -> libc::c_long;
    pub fn keyctl_get_persistent(
        uid:    libc::uid_t,
        id:     key_serial_t)
        -> libc::c_long;

    pub fn keyctl_describe_alloc(
        id:     key_serial_t,
        buffer: *mut *mut libc::c_char)
        -> libc::c_int;
    pub fn keyctl_read_alloc(
        id:     key_serial_t,
        buffer: *mut *mut libc::c_void)
        -> libc::c_int;
    pub fn keyctl_get_security_alloc(
        id:     key_serial_t,
        buffer: *mut *mut libc::c_char)
        -> libc::c_int;

    pub fn recursive_key_scan(
        key:    key_serial_t,
        func:   recursive_key_scanner_t,
        data:   *mut libc::c_void)
        -> libc::c_int;
    pub fn recursive_session_key_scan(
        func:   recursive_key_scanner_t,
        data:   *mut libc::c_void)
        -> libc::c_int;
    pub fn find_key_by_type_and_desc(
        type_:      *const libc::c_char,
        desc:       *const libc::c_char,
        destringid: key_serial_t)
        -> key_serial_t;
}
