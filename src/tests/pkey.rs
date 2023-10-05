// Copyright (c) 2020, Patrick Uiterwijk
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

use crate::{keytypes::Asymmetric, KeyctlEncoding, KeyctlHash, PublicKeyOptions};

use super::utils;

#[test]
fn sign() {
    let mut keyring = utils::new_test_keyring();
    let payload = include_bytes!("privkey.pk8");
    let key = keyring
        .add_key::<Asymmetric, _, _>("sign_key", &payload[..])
        .unwrap();

    let expected_signature = &[
        155, 73, 224, 97, 40, 120, 205, 218, 243, 105, 36, 130, 122, 189, 13, 99, 211, 12, 210, 23,
        14, 8, 71, 162, 133, 65, 104, 241, 9, 94, 240, 85, 41, 170, 246, 111, 129, 107, 21, 133,
        24, 231, 144, 71, 195, 171, 162, 80, 143, 159, 143, 99, 195, 255, 18, 74, 32, 87, 66, 176,
        181, 127, 207, 146, 223, 195, 45, 80, 96, 2, 77, 71, 63, 116, 227, 11, 196, 151, 40, 158,
        215, 211, 53, 14, 132, 189, 201, 52, 25, 120, 159, 221, 42, 35, 224, 12, 109, 205, 225,
        159, 100, 230, 155, 59, 179, 73, 168, 68, 27, 172, 65, 220, 189, 177, 53, 46, 29, 70, 62,
        219, 210, 243, 36, 7, 149, 61, 154, 100, 227, 169, 97, 127, 187, 182, 187, 112, 170, 26,
        11, 81, 247, 111, 210, 128, 48, 85, 237, 84, 231, 171, 106, 197, 216, 16, 10, 169, 198,
        131, 68, 22, 229, 136, 180, 94, 180, 97, 136, 87, 50, 253, 150, 96, 185, 248, 42, 164, 1,
        200, 156, 250, 244, 160, 221, 231, 148, 108, 12, 114, 200, 244, 159, 219, 175, 19, 117,
        171, 252, 150, 192, 237, 124, 26, 167, 193, 43, 113, 102, 171, 13, 255, 26, 177, 83, 254,
        235, 242, 251, 249, 90, 58, 5, 79, 167, 76, 131, 236, 167, 40, 35, 140, 44, 179, 225, 94,
        108, 253, 162, 202, 227, 205, 11, 110, 46, 240, 83, 56, 108, 111, 137, 251, 86, 130, 190,
        1, 172, 109,
    ];
    let digest = &[0x1, 0x2, 0x3, 0x4];
    let options = PublicKeyOptions {
        encoding: Some(KeyctlEncoding::RsassaPkcs1V15),
        hash: Some(KeyctlHash::Sha256),
    };

    let signature = key.sign(&options, digest).unwrap();

    assert_eq!(signature.to_vec(), expected_signature.to_vec());
}
