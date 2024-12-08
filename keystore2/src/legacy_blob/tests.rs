// Copyright 2020, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Tests for legacy keyblob processing.

#![allow(dead_code)]
use super::*;
use crate::legacy_blob::test_utils::legacy_blob_test_vectors::*;
use crate::legacy_blob::test_utils::*;
use anyhow::{anyhow, Result};
use keystore2_crypto::aes_gcm_decrypt;
use keystore2_test_utils::TempDir;
use rand::Rng;
use std::convert::TryInto;
use std::ops::Deref;
use std::string::FromUtf8Error;

#[test]
fn decode_encode_alias_test() {
    static ALIAS: &str = "#({}test[])😗";
    static ENCODED_ALIAS: &str = "+S+X{}test[]+Y.`-O-H-G";
    // Second multi byte out of range ------v
    static ENCODED_ALIAS_ERROR1: &str = "+S+{}test[]+Y";
    // Incomplete multi byte ------------------------v
    static ENCODED_ALIAS_ERROR2: &str = "+S+X{}test[]+";
    // Our encoding: ".`-O-H-G"
    // is UTF-8: 0xF0 0x9F 0x98 0x97
    // is UNICODE: U+1F617
    // is 😗
    // But +H below is a valid encoding for 0x18 making this sequence invalid UTF-8.
    static ENCODED_ALIAS_ERROR_UTF8: &str = ".`-O+H-G";

    assert_eq!(ENCODED_ALIAS, &LegacyBlobLoader::encode_alias(ALIAS));
    assert_eq!(ALIAS, &LegacyBlobLoader::decode_alias(ENCODED_ALIAS).unwrap());
    assert_eq!(
        Some(&Error::BadEncoding),
        LegacyBlobLoader::decode_alias(ENCODED_ALIAS_ERROR1)
            .unwrap_err()
            .root_cause()
            .downcast_ref::<Error>()
    );
    assert_eq!(
        Some(&Error::BadEncoding),
        LegacyBlobLoader::decode_alias(ENCODED_ALIAS_ERROR2)
            .unwrap_err()
            .root_cause()
            .downcast_ref::<Error>()
    );
    assert!(LegacyBlobLoader::decode_alias(ENCODED_ALIAS_ERROR_UTF8)
        .unwrap_err()
        .root_cause()
        .downcast_ref::<FromUtf8Error>()
        .is_some());

    for _i in 0..100 {
        // Any valid UTF-8 string should be en- and decoded without loss.
        let alias_str = rand::thread_rng().gen::<[char; 20]>().iter().collect::<String>();
        let random_alias = alias_str.as_bytes();
        let encoded = LegacyBlobLoader::encode_alias(&alias_str);
        let decoded = match LegacyBlobLoader::decode_alias(&encoded) {
            Ok(d) => d,
            Err(_) => panic!("random_alias: {:x?}\nencoded {}", random_alias, encoded),
        };
        assert_eq!(random_alias.to_vec(), decoded.bytes().collect::<Vec<u8>>());
    }
}

#[test]
fn read_golden_key_blob_test() -> anyhow::Result<()> {
    let blob = LegacyBlobLoader::new_from_stream_decrypt_with(&mut &*BLOB, |_, _, _, _, _| {
        Err(anyhow!("should not be called"))
    })
    .unwrap();
    assert!(!blob.is_encrypted());
    assert!(!blob.is_fallback());
    assert!(!blob.is_strongbox());
    assert!(!blob.is_critical_to_device_encryption());
    assert_eq!(blob.value(), &BlobValue::Generic([0xde, 0xed, 0xbe, 0xef].to_vec()));

    let blob =
        LegacyBlobLoader::new_from_stream_decrypt_with(&mut &*REAL_LEGACY_BLOB, |_, _, _, _, _| {
            Err(anyhow!("should not be called"))
        })
        .unwrap();
    assert!(!blob.is_encrypted());
    assert!(!blob.is_fallback());
    assert!(!blob.is_strongbox());
    assert!(!blob.is_critical_to_device_encryption());
    assert_eq!(blob.value(), &BlobValue::Decrypted(REAL_LEGACY_BLOB_PAYLOAD.try_into().unwrap()));
    Ok(())
}

#[test]
fn read_aes_gcm_encrypted_key_blob_test() {
    let blob = LegacyBlobLoader::new_from_stream_decrypt_with(
        &mut &*AES_GCM_ENCRYPTED_BLOB,
        |d, iv, tag, salt, key_size| {
            assert_eq!(salt, None);
            assert_eq!(key_size, None);
            assert_eq!(
                iv,
                &[
                    0xbd, 0xdb, 0x8d, 0x69, 0x72, 0x56, 0xf0, 0xf5, 0xa4, 0x02, 0x88, 0x7f, 0x00,
                    0x00, 0x00, 0x00,
                ]
            );
            assert_eq!(
                tag,
                &[
                    0x50, 0xd9, 0x97, 0x95, 0x37, 0x6e, 0x28, 0x6a, 0x28, 0x9d, 0x51, 0xb9, 0xb9,
                    0xe0, 0x0b, 0xc3
                ][..]
            );
            aes_gcm_decrypt(d, iv, tag, AES_KEY).context("Trying to decrypt blob.")
        },
    )
    .unwrap();
    assert!(blob.is_encrypted());
    assert!(!blob.is_fallback());
    assert!(!blob.is_strongbox());
    assert!(!blob.is_critical_to_device_encryption());

    assert_eq!(blob.value(), &BlobValue::Decrypted(DECRYPTED_PAYLOAD.try_into().unwrap()));
}

#[test]
fn read_golden_key_blob_too_short_test() {
    let error =
        LegacyBlobLoader::new_from_stream_decrypt_with(&mut &BLOB[0..15], |_, _, _, _, _| {
            Err(anyhow!("should not be called"))
        })
        .unwrap_err();
    assert_eq!(Some(&Error::BadLen), error.root_cause().downcast_ref::<Error>());
}

#[test]
fn test_is_empty() {
    let temp_dir = TempDir::new("test_is_empty").expect("Failed to create temp dir.");
    let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());

    assert!(legacy_blob_loader.is_empty().expect("Should succeed and be empty."));

    let _db =
        crate::database::KeystoreDB::new(temp_dir.path(), None).expect("Failed to open database.");

    assert!(legacy_blob_loader.is_empty().expect("Should succeed and still be empty."));

    std::fs::create_dir(&*temp_dir.build().push("user_0")).expect("Failed to create user_0.");

    assert!(!legacy_blob_loader.is_empty().expect("Should succeed but not be empty."));

    std::fs::create_dir(&*temp_dir.build().push("user_10")).expect("Failed to create user_10.");

    assert!(!legacy_blob_loader.is_empty().expect("Should succeed but still not be empty."));

    std::fs::remove_dir_all(&*temp_dir.build().push("user_0")).expect("Failed to remove user_0.");

    assert!(!legacy_blob_loader.is_empty().expect("Should succeed but still not be empty."));

    std::fs::remove_dir_all(&*temp_dir.build().push("user_10")).expect("Failed to remove user_10.");

    assert!(legacy_blob_loader.is_empty().expect("Should succeed and be empty again."));
}

#[test]
fn test_legacy_blobs() -> anyhow::Result<()> {
    let temp_dir = TempDir::new("legacy_blob_test").unwrap();
    std::fs::create_dir(&*temp_dir.build().push("user_0")).unwrap();

    std::fs::write(&*temp_dir.build().push("user_0").push(".masterkey"), SUPERKEY).unwrap();

    std::fs::write(
        &*temp_dir.build().push("user_0").push("10223_USRPKEY_authbound"),
        USRPKEY_AUTHBOUND,
    )
    .unwrap();
    std::fs::write(
        &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_authbound"),
        USRPKEY_AUTHBOUND_CHR,
    )
    .unwrap();
    std::fs::write(
        &*temp_dir.build().push("user_0").push("10223_USRCERT_authbound"),
        USRCERT_AUTHBOUND,
    )
    .unwrap();
    std::fs::write(
        &*temp_dir.build().push("user_0").push("10223_CACERT_authbound"),
        CACERT_AUTHBOUND,
    )
    .unwrap();

    std::fs::write(
        &*temp_dir.build().push("user_0").push("10223_USRPKEY_non_authbound"),
        USRPKEY_NON_AUTHBOUND,
    )
    .unwrap();
    std::fs::write(
        &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_non_authbound"),
        USRPKEY_NON_AUTHBOUND_CHR,
    )
    .unwrap();
    std::fs::write(
        &*temp_dir.build().push("user_0").push("10223_USRCERT_non_authbound"),
        USRCERT_NON_AUTHBOUND,
    )
    .unwrap();
    std::fs::write(
        &*temp_dir.build().push("user_0").push("10223_CACERT_non_authbound"),
        CACERT_NON_AUTHBOUND,
    )
    .unwrap();

    let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());

    if let (Some((Blob { flags, value }, _params)), Some(cert), Some(chain)) =
        legacy_blob_loader.load_by_uid_alias(10223, "authbound", &None)?
    {
        assert_eq!(flags, 4);
        assert_eq!(
            value,
            BlobValue::Encrypted {
                data: USRPKEY_AUTHBOUND_ENC_PAYLOAD.to_vec(),
                iv: USRPKEY_AUTHBOUND_IV.to_vec(),
                tag: USRPKEY_AUTHBOUND_TAG.to_vec()
            }
        );
        assert_eq!(&cert[..], LOADED_CERT_AUTHBOUND);
        assert_eq!(&chain[..], LOADED_CACERT_AUTHBOUND);
    } else {
        panic!("");
    }

    if let (Some((Blob { flags, value: _ }, _params)), Some(cert), Some(chain)) =
        legacy_blob_loader.load_by_uid_alias(10223, "authbound", &None)?
    {
        assert_eq!(flags, 4);
        //assert_eq!(value, BlobValue::Encrypted(..));
        assert_eq!(&cert[..], LOADED_CERT_AUTHBOUND);
        assert_eq!(&chain[..], LOADED_CACERT_AUTHBOUND);
    } else {
        panic!("");
    }
    if let (Some((Blob { flags, value }, _params)), Some(cert), Some(chain)) =
        legacy_blob_loader.load_by_uid_alias(10223, "non_authbound", &None)?
    {
        assert_eq!(flags, 0);
        assert_eq!(value, BlobValue::Decrypted(LOADED_USRPKEY_NON_AUTHBOUND.try_into()?));
        assert_eq!(&cert[..], LOADED_CERT_NON_AUTHBOUND);
        assert_eq!(&chain[..], LOADED_CACERT_NON_AUTHBOUND);
    } else {
        panic!("");
    }

    legacy_blob_loader.remove_keystore_entry(10223, "authbound").expect("This should succeed.");
    legacy_blob_loader.remove_keystore_entry(10223, "non_authbound").expect("This should succeed.");

    assert_eq!(
        (None, None, None),
        legacy_blob_loader.load_by_uid_alias(10223, "authbound", &None)?
    );
    assert_eq!(
        (None, None, None),
        legacy_blob_loader.load_by_uid_alias(10223, "non_authbound", &None)?
    );

    // The database should not be empty due to the super key.
    assert!(!legacy_blob_loader.is_empty()?);
    assert!(!legacy_blob_loader.is_empty_user(0)?);

    // The database should be considered empty for user 1.
    assert!(legacy_blob_loader.is_empty_user(1)?);

    legacy_blob_loader.remove_super_key(0);

    // Now it should be empty.
    assert!(legacy_blob_loader.is_empty_user(0)?);
    assert!(legacy_blob_loader.is_empty()?);

    Ok(())
}

struct TestKey(ZVec);

impl crate::utils::AesGcmKey for TestKey {
    fn key(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for TestKey {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[test]
fn test_with_encrypted_characteristics() -> anyhow::Result<()> {
    let temp_dir = TempDir::new("test_with_encrypted_characteristics").unwrap();
    std::fs::create_dir(&*temp_dir.build().push("user_0")).unwrap();

    let pw: Password = PASSWORD.into();
    let pw_key = TestKey(pw.derive_key_pbkdf2(SUPERKEY_SALT, 32).unwrap());
    let super_key =
        Arc::new(TestKey(pw_key.decrypt(SUPERKEY_PAYLOAD, SUPERKEY_IV, SUPERKEY_TAG).unwrap()));

    std::fs::write(&*temp_dir.build().push("user_0").push(".masterkey"), SUPERKEY).unwrap();

    std::fs::write(
        &*temp_dir.build().push("user_0").push("10223_USRPKEY_authbound"),
        USRPKEY_AUTHBOUND,
    )
    .unwrap();
    make_encrypted_characteristics_file(
        &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_authbound"),
        &super_key,
        KEY_PARAMETERS,
    )
    .unwrap();
    std::fs::write(
        &*temp_dir.build().push("user_0").push("10223_USRCERT_authbound"),
        USRCERT_AUTHBOUND,
    )
    .unwrap();
    std::fs::write(
        &*temp_dir.build().push("user_0").push("10223_CACERT_authbound"),
        CACERT_AUTHBOUND,
    )
    .unwrap();

    let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());

    assert_eq!(
        legacy_blob_loader
            .load_by_uid_alias(10223, "authbound", &None)
            .unwrap_err()
            .root_cause()
            .downcast_ref::<Error>(),
        Some(&Error::LockedComponent)
    );

    assert_eq!(
        legacy_blob_loader.load_by_uid_alias(10223, "authbound", &Some(super_key)).unwrap(),
        (
            Some((
                Blob {
                    flags: 4,
                    value: BlobValue::Encrypted {
                        data: USRPKEY_AUTHBOUND_ENC_PAYLOAD.to_vec(),
                        iv: USRPKEY_AUTHBOUND_IV.to_vec(),
                        tag: USRPKEY_AUTHBOUND_TAG.to_vec()
                    }
                },
                structured_test_params()
            )),
            Some(LOADED_CERT_AUTHBOUND.to_vec()),
            Some(LOADED_CACERT_AUTHBOUND.to_vec())
        )
    );

    legacy_blob_loader.remove_keystore_entry(10223, "authbound").expect("This should succeed.");

    assert_eq!(
        (None, None, None),
        legacy_blob_loader.load_by_uid_alias(10223, "authbound", &None).unwrap()
    );

    // The database should not be empty due to the super key.
    assert!(!legacy_blob_loader.is_empty().unwrap());
    assert!(!legacy_blob_loader.is_empty_user(0).unwrap());

    // The database should be considered empty for user 1.
    assert!(legacy_blob_loader.is_empty_user(1).unwrap());

    legacy_blob_loader.remove_super_key(0);

    // Now it should be empty.
    assert!(legacy_blob_loader.is_empty_user(0).unwrap());
    assert!(legacy_blob_loader.is_empty().unwrap());

    Ok(())
}

#[test]
fn test_with_encrypted_certificates() -> anyhow::Result<()> {
    let temp_dir = TempDir::new("test_with_encrypted_certificates").unwrap();
    std::fs::create_dir(&*temp_dir.build().push("user_0")).unwrap();

    let pw: Password = PASSWORD.into();
    let pw_key = TestKey(pw.derive_key_pbkdf2(SUPERKEY_SALT, 32).unwrap());
    let super_key =
        Arc::new(TestKey(pw_key.decrypt(SUPERKEY_PAYLOAD, SUPERKEY_IV, SUPERKEY_TAG).unwrap()));

    std::fs::write(&*temp_dir.build().push("user_0").push(".masterkey"), SUPERKEY).unwrap();

    std::fs::write(
        &*temp_dir.build().push("user_0").push("10223_USRPKEY_authbound"),
        USRPKEY_AUTHBOUND,
    )
    .unwrap();
    std::fs::write(
        &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_authbound"),
        USRPKEY_AUTHBOUND_CHR,
    )
    .unwrap();
    make_encrypted_usr_cert_file(
        &*temp_dir.build().push("user_0").push("10223_USRCERT_authbound"),
        &super_key,
        LOADED_CERT_AUTHBOUND,
    )
    .unwrap();
    make_encrypted_ca_cert_file(
        &*temp_dir.build().push("user_0").push("10223_CACERT_authbound"),
        &super_key,
        LOADED_CACERT_AUTHBOUND,
    )
    .unwrap();

    let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());

    assert_eq!(
        legacy_blob_loader
            .load_by_uid_alias(10223, "authbound", &None)
            .unwrap_err()
            .root_cause()
            .downcast_ref::<Error>(),
        Some(&Error::LockedComponent)
    );

    assert_eq!(
        legacy_blob_loader.load_by_uid_alias(10223, "authbound", &Some(super_key)).unwrap(),
        (
            Some((
                Blob {
                    flags: 4,
                    value: BlobValue::Encrypted {
                        data: USRPKEY_AUTHBOUND_ENC_PAYLOAD.to_vec(),
                        iv: USRPKEY_AUTHBOUND_IV.to_vec(),
                        tag: USRPKEY_AUTHBOUND_TAG.to_vec()
                    }
                },
                structured_test_params_cache()
            )),
            Some(LOADED_CERT_AUTHBOUND.to_vec()),
            Some(LOADED_CACERT_AUTHBOUND.to_vec())
        )
    );

    legacy_blob_loader.remove_keystore_entry(10223, "authbound").expect("This should succeed.");

    assert_eq!(
        (None, None, None),
        legacy_blob_loader.load_by_uid_alias(10223, "authbound", &None).unwrap()
    );

    // The database should not be empty due to the super key.
    assert!(!legacy_blob_loader.is_empty().unwrap());
    assert!(!legacy_blob_loader.is_empty_user(0).unwrap());

    // The database should be considered empty for user 1.
    assert!(legacy_blob_loader.is_empty_user(1).unwrap());

    legacy_blob_loader.remove_super_key(0);

    // Now it should be empty.
    assert!(legacy_blob_loader.is_empty_user(0).unwrap());
    assert!(legacy_blob_loader.is_empty().unwrap());

    Ok(())
}

#[test]
fn test_in_place_key_migration() -> anyhow::Result<()> {
    let temp_dir = TempDir::new("test_in_place_key_migration").unwrap();
    std::fs::create_dir(&*temp_dir.build().push("user_0")).unwrap();

    let pw: Password = PASSWORD.into();
    let pw_key = TestKey(pw.derive_key_pbkdf2(SUPERKEY_SALT, 32).unwrap());
    let super_key =
        Arc::new(TestKey(pw_key.decrypt(SUPERKEY_PAYLOAD, SUPERKEY_IV, SUPERKEY_TAG).unwrap()));

    std::fs::write(&*temp_dir.build().push("user_0").push(".masterkey"), SUPERKEY).unwrap();

    std::fs::write(
        &*temp_dir.build().push("user_0").push("10223_USRPKEY_authbound"),
        USRPKEY_AUTHBOUND,
    )
    .unwrap();
    std::fs::write(
        &*temp_dir.build().push("user_0").push(".10223_chr_USRPKEY_authbound"),
        USRPKEY_AUTHBOUND_CHR,
    )
    .unwrap();
    make_encrypted_usr_cert_file(
        &*temp_dir.build().push("user_0").push("10223_USRCERT_authbound"),
        &super_key,
        LOADED_CERT_AUTHBOUND,
    )
    .unwrap();
    make_encrypted_ca_cert_file(
        &*temp_dir.build().push("user_0").push("10223_CACERT_authbound"),
        &super_key,
        LOADED_CACERT_AUTHBOUND,
    )
    .unwrap();

    let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());

    assert_eq!(
        legacy_blob_loader
            .load_by_uid_alias(10223, "authbound", &None)
            .unwrap_err()
            .root_cause()
            .downcast_ref::<Error>(),
        Some(&Error::LockedComponent)
    );

    let super_key: Option<Arc<dyn AesGcm>> = Some(super_key);

    assert_eq!(
        legacy_blob_loader.load_by_uid_alias(10223, "authbound", &super_key).unwrap(),
        (
            Some((
                Blob {
                    flags: 4,
                    value: BlobValue::Encrypted {
                        data: USRPKEY_AUTHBOUND_ENC_PAYLOAD.to_vec(),
                        iv: USRPKEY_AUTHBOUND_IV.to_vec(),
                        tag: USRPKEY_AUTHBOUND_TAG.to_vec()
                    }
                },
                structured_test_params_cache()
            )),
            Some(LOADED_CERT_AUTHBOUND.to_vec()),
            Some(LOADED_CACERT_AUTHBOUND.to_vec())
        )
    );

    legacy_blob_loader.move_keystore_entry(10223, 10224, "authbound", "boundauth").unwrap();

    assert_eq!(
        legacy_blob_loader
            .load_by_uid_alias(10224, "boundauth", &None)
            .unwrap_err()
            .root_cause()
            .downcast_ref::<Error>(),
        Some(&Error::LockedComponent)
    );

    assert_eq!(
        legacy_blob_loader.load_by_uid_alias(10224, "boundauth", &super_key).unwrap(),
        (
            Some((
                Blob {
                    flags: 4,
                    value: BlobValue::Encrypted {
                        data: USRPKEY_AUTHBOUND_ENC_PAYLOAD.to_vec(),
                        iv: USRPKEY_AUTHBOUND_IV.to_vec(),
                        tag: USRPKEY_AUTHBOUND_TAG.to_vec()
                    }
                },
                structured_test_params_cache()
            )),
            Some(LOADED_CERT_AUTHBOUND.to_vec()),
            Some(LOADED_CACERT_AUTHBOUND.to_vec())
        )
    );

    legacy_blob_loader.remove_keystore_entry(10224, "boundauth").expect("This should succeed.");

    assert_eq!(
        (None, None, None),
        legacy_blob_loader.load_by_uid_alias(10224, "boundauth", &None).unwrap()
    );

    // The database should not be empty due to the super key.
    assert!(!legacy_blob_loader.is_empty().unwrap());
    assert!(!legacy_blob_loader.is_empty_user(0).unwrap());

    // The database should be considered empty for user 1.
    assert!(legacy_blob_loader.is_empty_user(1).unwrap());

    legacy_blob_loader.remove_super_key(0);

    // Now it should be empty.
    assert!(legacy_blob_loader.is_empty_user(0).unwrap());
    assert!(legacy_blob_loader.is_empty().unwrap());

    Ok(())
}

#[test]
fn list_non_existing_user() -> Result<()> {
    let temp_dir = TempDir::new("list_non_existing_user").unwrap();
    let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());

    assert!(legacy_blob_loader.list_user(20)?.is_empty());

    Ok(())
}

#[test]
fn list_legacy_keystore_entries_on_non_existing_user() -> Result<()> {
    let temp_dir = TempDir::new("list_legacy_keystore_entries_on_non_existing_user").unwrap();
    let legacy_blob_loader = LegacyBlobLoader::new(temp_dir.path());

    assert!(legacy_blob_loader.list_legacy_keystore_entries_for_user(20)?.is_empty());

    Ok(())
}

#[test]
fn test_move_keystore_entry() {
    let temp_dir = TempDir::new("test_move_keystore_entry").unwrap();
    std::fs::create_dir(&*temp_dir.build().push("user_0")).unwrap();

    const SOME_CONTENT: &[u8] = b"some content";
    const ANOTHER_CONTENT: &[u8] = b"another content";
    const SOME_FILENAME: &str = "some_file";
    const ANOTHER_FILENAME: &str = "another_file";

    std::fs::write(&*temp_dir.build().push("user_0").push(SOME_FILENAME), SOME_CONTENT).unwrap();

    std::fs::write(&*temp_dir.build().push("user_0").push(ANOTHER_FILENAME), ANOTHER_CONTENT)
        .unwrap();

    // Non existent source id silently ignored.
    assert!(LegacyBlobLoader::move_keystore_file_if_exists(
        1,
        2,
        "non_existent",
        ANOTHER_FILENAME,
        "ignored",
        |_, alias, _| temp_dir.build().push("user_0").push(alias).to_path_buf()
    )
    .is_ok());

    // Content of another_file has not changed.
    let another_content =
        std::fs::read(&*temp_dir.build().push("user_0").push(ANOTHER_FILENAME)).unwrap();
    assert_eq!(&another_content, ANOTHER_CONTENT);

    // Check that some_file still exists.
    assert!(temp_dir.build().push("user_0").push(SOME_FILENAME).exists());
    // Existing target files are silently overwritten.

    assert!(LegacyBlobLoader::move_keystore_file_if_exists(
        1,
        2,
        SOME_FILENAME,
        ANOTHER_FILENAME,
        "ignored",
        |_, alias, _| temp_dir.build().push("user_0").push(alias).to_path_buf()
    )
    .is_ok());

    // Content of another_file is now "some content".
    let another_content =
        std::fs::read(&*temp_dir.build().push("user_0").push(ANOTHER_FILENAME)).unwrap();
    assert_eq!(&another_content, SOME_CONTENT);

    // Check that some_file no longer exists.
    assert!(!temp_dir.build().push("user_0").push(SOME_FILENAME).exists());
}
