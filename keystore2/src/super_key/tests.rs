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

//! Super-key tests.

use super::*;
use crate::database::tests::make_bootlevel_key_entry;
use crate::database::tests::make_test_key_entry;
use crate::database::tests::new_test_db;
use rand::prelude::*;
const USER_ID: u32 = 0;
const TEST_KEY_ALIAS: &str = "TEST_KEY";
const TEST_BOOT_KEY_ALIAS: &str = "TEST_BOOT_KEY";

pub fn generate_password_blob() -> Password<'static> {
    let mut rng = rand::thread_rng();
    let mut password = vec![0u8; 64];
    rng.fill_bytes(&mut password);

    let mut zvec = ZVec::new(64).expect("Failed to create ZVec");
    zvec[..].copy_from_slice(&password[..]);

    Password::Owned(zvec)
}

fn setup_test(pw: &Password) -> (Arc<RwLock<SuperKeyManager>>, KeystoreDB, LegacyImporter) {
    let mut keystore_db = new_test_db().unwrap();
    let mut legacy_importer = LegacyImporter::new(Arc::new(Default::default()));
    legacy_importer.set_empty();
    let skm: Arc<RwLock<SuperKeyManager>> = Default::default();
    assert!(skm
        .write()
        .unwrap()
        .initialize_user(&mut keystore_db, &legacy_importer, USER_ID, pw, false)
        .is_ok());
    (skm, keystore_db, legacy_importer)
}

fn assert_unlocked(
    skm: &Arc<RwLock<SuperKeyManager>>,
    keystore_db: &mut KeystoreDB,
    legacy_importer: &LegacyImporter,
    user_id: u32,
    err_msg: &str,
) {
    let user_state =
        skm.write().unwrap().get_user_state(keystore_db, legacy_importer, user_id).unwrap();
    match user_state {
        UserState::AfterFirstUnlock(_) => {}
        _ => panic!("{}", err_msg),
    }
}

fn assert_locked(
    skm: &Arc<RwLock<SuperKeyManager>>,
    keystore_db: &mut KeystoreDB,
    legacy_importer: &LegacyImporter,
    user_id: u32,
    err_msg: &str,
) {
    let user_state =
        skm.write().unwrap().get_user_state(keystore_db, legacy_importer, user_id).unwrap();
    match user_state {
        UserState::BeforeFirstUnlock => {}
        _ => panic!("{}", err_msg),
    }
}

fn assert_uninitialized(
    skm: &Arc<RwLock<SuperKeyManager>>,
    keystore_db: &mut KeystoreDB,
    legacy_importer: &LegacyImporter,
    user_id: u32,
    err_msg: &str,
) {
    let user_state =
        skm.write().unwrap().get_user_state(keystore_db, legacy_importer, user_id).unwrap();
    match user_state {
        UserState::Uninitialized => {}
        _ => panic!("{}", err_msg),
    }
}

#[test]
fn test_initialize_user() {
    let pw: Password = generate_password_blob();
    let (skm, mut keystore_db, legacy_importer) = setup_test(&pw);
    assert_unlocked(
        &skm,
        &mut keystore_db,
        &legacy_importer,
        USER_ID,
        "The user was not unlocked after initialization!",
    );
}

#[test]
fn test_unlock_user() {
    let pw: Password = generate_password_blob();
    let (skm, mut keystore_db, legacy_importer) = setup_test(&pw);
    assert_unlocked(
        &skm,
        &mut keystore_db,
        &legacy_importer,
        USER_ID,
        "The user was not unlocked after initialization!",
    );

    skm.write().unwrap().data.user_keys.clear();
    assert_locked(
        &skm,
        &mut keystore_db,
        &legacy_importer,
        USER_ID,
        "Clearing the cache did not lock the user!",
    );

    assert!(skm
        .write()
        .unwrap()
        .unlock_user(&mut keystore_db, &legacy_importer, USER_ID, &pw)
        .is_ok());
    assert_unlocked(&skm, &mut keystore_db, &legacy_importer, USER_ID, "The user did not unlock!");
}

#[test]
fn test_unlock_wrong_password() {
    let pw: Password = generate_password_blob();
    let wrong_pw: Password = generate_password_blob();
    let (skm, mut keystore_db, legacy_importer) = setup_test(&pw);
    assert_unlocked(
        &skm,
        &mut keystore_db,
        &legacy_importer,
        USER_ID,
        "The user was not unlocked after initialization!",
    );

    skm.write().unwrap().data.user_keys.clear();
    assert_locked(
        &skm,
        &mut keystore_db,
        &legacy_importer,
        USER_ID,
        "Clearing the cache did not lock the user!",
    );

    assert!(skm
        .write()
        .unwrap()
        .unlock_user(&mut keystore_db, &legacy_importer, USER_ID, &wrong_pw)
        .is_err());
    assert_locked(
        &skm,
        &mut keystore_db,
        &legacy_importer,
        USER_ID,
        "The user was unlocked with an incorrect password!",
    );
}

#[test]
fn test_unlock_user_idempotent() {
    let pw: Password = generate_password_blob();
    let (skm, mut keystore_db, legacy_importer) = setup_test(&pw);
    assert_unlocked(
        &skm,
        &mut keystore_db,
        &legacy_importer,
        USER_ID,
        "The user was not unlocked after initialization!",
    );

    skm.write().unwrap().data.user_keys.clear();
    assert_locked(
        &skm,
        &mut keystore_db,
        &legacy_importer,
        USER_ID,
        "Clearing the cache did not lock the user!",
    );

    for _ in 0..5 {
        assert!(skm
            .write()
            .unwrap()
            .unlock_user(&mut keystore_db, &legacy_importer, USER_ID, &pw)
            .is_ok());
        assert_unlocked(
            &skm,
            &mut keystore_db,
            &legacy_importer,
            USER_ID,
            "The user did not unlock!",
        );
    }
}

fn test_user_removal(locked: bool) {
    let pw: Password = generate_password_blob();
    let (skm, mut keystore_db, legacy_importer) = setup_test(&pw);
    assert_unlocked(
        &skm,
        &mut keystore_db,
        &legacy_importer,
        USER_ID,
        "The user was not unlocked after initialization!",
    );

    assert!(make_test_key_entry(
        &mut keystore_db,
        Domain::APP,
        USER_ID.into(),
        TEST_KEY_ALIAS,
        None
    )
    .is_ok());
    assert!(make_bootlevel_key_entry(
        &mut keystore_db,
        Domain::APP,
        USER_ID.into(),
        TEST_BOOT_KEY_ALIAS,
        false
    )
    .is_ok());

    assert!(keystore_db
        .key_exists(Domain::APP, USER_ID.into(), TEST_KEY_ALIAS, KeyType::Client)
        .unwrap());
    assert!(keystore_db
        .key_exists(Domain::APP, USER_ID.into(), TEST_BOOT_KEY_ALIAS, KeyType::Client)
        .unwrap());

    if locked {
        skm.write().unwrap().data.user_keys.clear();
        assert_locked(
            &skm,
            &mut keystore_db,
            &legacy_importer,
            USER_ID,
            "Clearing the cache did not lock the user!",
        );
    }

    assert!(skm.write().unwrap().remove_user(&mut keystore_db, &legacy_importer, USER_ID).is_ok());
    assert_uninitialized(
        &skm,
        &mut keystore_db,
        &legacy_importer,
        USER_ID,
        "The user was not removed!",
    );

    assert!(!skm
        .write()
        .unwrap()
        .super_key_exists_in_db_for_user(&mut keystore_db, &legacy_importer, USER_ID)
        .unwrap());

    assert!(!keystore_db
        .key_exists(Domain::APP, USER_ID.into(), TEST_KEY_ALIAS, KeyType::Client)
        .unwrap());
    assert!(!keystore_db
        .key_exists(Domain::APP, USER_ID.into(), TEST_BOOT_KEY_ALIAS, KeyType::Client)
        .unwrap());
}

#[test]
fn test_remove_unlocked_user() {
    test_user_removal(false);
}

#[test]
fn test_remove_locked_user() {
    test_user_removal(true);
}
