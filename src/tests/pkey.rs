// Copyright (c) 2020, Ben Boeckel
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

use crate::keytypes::User;

use super::utils;
use super::utils::kernel::*;

#[test]
fn invalid_keyring_query() {
    let keyring = utils::invalid_keyring();
    let key = utils::keyring_as_key(&keyring);
    let err = key.pkey_query_support(&Default::default()).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn invalid_key_query() {
    let key = utils::invalid_key();
    let err = key.pkey_query_support(&Default::default()).unwrap_err();
    assert_eq!(err, errno::Errno(libc::EINVAL));
}

#[test]
fn pkey_query_keyring() {
    let keyring = utils::new_test_keyring();
    let key = utils::keyring_as_key(&keyring);
    let err = key.pkey_query_support(&Default::default()).unwrap_err();

    if *HAVE_PKEY {
        assert_eq!(err, errno::Errno(libc::EOPNOTSUPP));
    } else {
        assert_eq!(err, errno::Errno(libc::ENOSYS));
    }
}

#[test]
fn pkey_query_user() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("pkey_query_user", payload)
        .unwrap();

    let err = key.pkey_query_support(&Default::default()).unwrap_err();

    if *HAVE_PKEY {
        assert_eq!(err, errno::Errno(libc::EOPNOTSUPP));
    } else {
        assert_eq!(err, errno::Errno(libc::ENOSYS));
    }
}

#[test]
fn pkey_encrypt_keyring() {
    let keyring = utils::new_test_keyring();
    let key = utils::keyring_as_key(&keyring);
    let data = &b"data"[..];
    let err = key.encrypt(&Default::default(), data).unwrap_err();

    if *HAVE_PKEY {
        assert_eq!(err, errno::Errno(libc::EOPNOTSUPP));
    } else {
        assert_eq!(err, errno::Errno(libc::ENOSYS));
    }
}

#[test]
fn pkey_encrypt_user() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("pkey_encrypt_user", payload)
        .unwrap();

    let data = &b"data"[..];
    let err = key.encrypt(&Default::default(), data).unwrap_err();

    if *HAVE_PKEY {
        assert_eq!(err, errno::Errno(libc::EOPNOTSUPP));
    } else {
        assert_eq!(err, errno::Errno(libc::ENOSYS));
    }
}

#[test]
fn pkey_decrypt_keyring() {
    let keyring = utils::new_test_keyring();
    let key = utils::keyring_as_key(&keyring);
    let data = &b"data"[..];
    let err = key.decrypt(&Default::default(), data).unwrap_err();

    if *HAVE_PKEY {
        assert_eq!(err, errno::Errno(libc::EOPNOTSUPP));
    } else {
        assert_eq!(err, errno::Errno(libc::ENOSYS));
    }
}

#[test]
fn pkey_decrypt_user() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("pkey_decrypt_user", payload)
        .unwrap();

    let data = &b"data"[..];
    let err = key.decrypt(&Default::default(), data).unwrap_err();

    if *HAVE_PKEY {
        assert_eq!(err, errno::Errno(libc::EOPNOTSUPP));
    } else {
        assert_eq!(err, errno::Errno(libc::ENOSYS));
    }
}

#[test]
fn pkey_sign_keyring() {
    let keyring = utils::new_test_keyring();
    let key = utils::keyring_as_key(&keyring);
    let data = &b"data"[..];
    let err = key.sign(&Default::default(), data).unwrap_err();

    if *HAVE_PKEY {
        assert_eq!(err, errno::Errno(libc::EOPNOTSUPP));
    } else {
        assert_eq!(err, errno::Errno(libc::ENOSYS));
    }
}

#[test]
fn pkey_sign_user() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("pkey_sign_user", payload)
        .unwrap();

    let data = &b"data"[..];
    let err = key.sign(&Default::default(), data).unwrap_err();

    if *HAVE_PKEY {
        assert_eq!(err, errno::Errno(libc::EOPNOTSUPP));
    } else {
        assert_eq!(err, errno::Errno(libc::ENOSYS));
    }
}

#[test]
fn pkey_verify_keyring() {
    let keyring = utils::new_test_keyring();
    let key = utils::keyring_as_key(&keyring);
    let data = &b"data"[..];
    let sig = &b"sig"[..];
    let err = key.verify(&Default::default(), data, sig).unwrap_err();

    if *HAVE_PKEY {
        assert_eq!(err, errno::Errno(libc::EOPNOTSUPP));
    } else {
        assert_eq!(err, errno::Errno(libc::ENOSYS));
    }
}

#[test]
fn pkey_verify_user() {
    let mut keyring = utils::new_test_keyring();
    let payload = &b"payload"[..];
    let key = keyring
        .add_key::<User, _, _>("pkey_verify_user", payload)
        .unwrap();

    let data = &b"data"[..];
    let sig = &b"sig"[..];
    let err = key.verify(&Default::default(), data, sig).unwrap_err();

    if *HAVE_PKEY {
        assert_eq!(err, errno::Errno(libc::EOPNOTSUPP));
    } else {
        assert_eq!(err, errno::Errno(libc::ENOSYS));
    }
}
