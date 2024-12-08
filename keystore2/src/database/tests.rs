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

//! Database tests.

use super::*;
use crate::key_parameter::{
    Algorithm, BlockMode, Digest, EcCurve, HardwareAuthenticatorType, KeyOrigin, KeyParameter,
    KeyParameterValue, KeyPurpose, PaddingMode, SecurityLevel,
};
use crate::key_perm_set;
use crate::permission::{KeyPerm, KeyPermSet};
use crate::super_key::{SuperKeyManager, USER_AFTER_FIRST_UNLOCK_SUPER_KEY, SuperEncryptionAlgorithm, SuperKeyType};
use keystore2_test_utils::TempDir;
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    HardwareAuthToken::HardwareAuthToken,
    HardwareAuthenticatorType::HardwareAuthenticatorType as kmhw_authenticator_type,
};
use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
    Timestamp::Timestamp,
};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};
use crate::utils::AesGcm;
#[cfg(disabled)]
use std::time::Instant;

pub fn new_test_db() -> Result<KeystoreDB> {
    new_test_db_at("file::memory:")
}

fn new_test_db_at(path: &str) -> Result<KeystoreDB> {
    let conn = KeystoreDB::make_connection(path)?;

    let mut db = KeystoreDB { conn, gc: None, perboot: Arc::new(perboot::PerbootDB::new()) };
    db.with_transaction(Immediate("TX_new_test_db"), |tx| {
        KeystoreDB::init_tables(tx).context("Failed to initialize tables.").no_gc()
    })?;
    Ok(db)
}

fn rebind_alias(
    db: &mut KeystoreDB,
    newid: &KeyIdGuard,
    alias: &str,
    domain: Domain,
    namespace: i64,
) -> Result<bool> {
    db.with_transaction(Immediate("TX_rebind_alias"), |tx| {
        KeystoreDB::rebind_alias(tx, newid, alias, &domain, &namespace, KeyType::Client).no_gc()
    })
    .context(ks_err!())
}

#[test]
fn datetime() -> Result<()> {
    let conn = Connection::open_in_memory()?;
    conn.execute("CREATE TABLE test (ts DATETIME);", [])?;
    let now = SystemTime::now();
    let duration = Duration::from_secs(1000);
    let then = now.checked_sub(duration).unwrap();
    let soon = now.checked_add(duration).unwrap();
    conn.execute(
        "INSERT INTO test (ts) VALUES (?), (?), (?);",
        params![DateTime::try_from(now)?, DateTime::try_from(then)?, DateTime::try_from(soon)?],
    )?;
    let mut stmt = conn.prepare("SELECT ts FROM test ORDER BY ts ASC;")?;
    let mut rows = stmt.query([])?;
    assert_eq!(DateTime::try_from(then)?, rows.next()?.unwrap().get(0)?);
    assert_eq!(DateTime::try_from(now)?, rows.next()?.unwrap().get(0)?);
    assert_eq!(DateTime::try_from(soon)?, rows.next()?.unwrap().get(0)?);
    assert!(rows.next()?.is_none());
    assert!(DateTime::try_from(then)? < DateTime::try_from(now)?);
    assert!(DateTime::try_from(then)? < DateTime::try_from(soon)?);
    assert!(DateTime::try_from(now)? < DateTime::try_from(soon)?);
    Ok(())
}

// Ensure that we're using the "injected" random function, not the real one.
#[test]
fn test_mocked_random() {
    let rand1 = random();
    let rand2 = random();
    let rand3 = random();
    if rand1 == rand2 {
        assert_eq!(rand2 + 1, rand3);
    } else {
        assert_eq!(rand1 + 1, rand2);
        assert_eq!(rand2, rand3);
    }
}

// Test that we have the correct tables.
#[test]
fn test_tables() -> Result<()> {
    let db = new_test_db()?;
    let tables = db
        .conn
        .prepare("SELECT name from persistent.sqlite_master WHERE type='table' ORDER BY name;")?
        .query_map(params![], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<String>>>()?;
    assert_eq!(tables.len(), 6);
    assert_eq!(tables[0], "blobentry");
    assert_eq!(tables[1], "blobmetadata");
    assert_eq!(tables[2], "grant");
    assert_eq!(tables[3], "keyentry");
    assert_eq!(tables[4], "keymetadata");
    assert_eq!(tables[5], "keyparameter");
    Ok(())
}

#[test]
fn test_auth_token_table_invariant() -> Result<()> {
    let mut db = new_test_db()?;
    let auth_token1 = HardwareAuthToken {
        challenge: i64::MAX,
        userId: 200,
        authenticatorId: 200,
        authenticatorType: kmhw_authenticator_type(kmhw_authenticator_type::PASSWORD.0),
        timestamp: Timestamp { milliSeconds: 500 },
        mac: String::from("mac").into_bytes(),
    };
    db.insert_auth_token(&auth_token1);
    let auth_tokens_returned = get_auth_tokens(&db);
    assert_eq!(auth_tokens_returned.len(), 1);

    // insert another auth token with the same values for the columns in the UNIQUE constraint
    // of the auth token table and different value for timestamp
    let auth_token2 = HardwareAuthToken {
        challenge: i64::MAX,
        userId: 200,
        authenticatorId: 200,
        authenticatorType: kmhw_authenticator_type(kmhw_authenticator_type::PASSWORD.0),
        timestamp: Timestamp { milliSeconds: 600 },
        mac: String::from("mac").into_bytes(),
    };

    db.insert_auth_token(&auth_token2);
    let mut auth_tokens_returned = get_auth_tokens(&db);
    assert_eq!(auth_tokens_returned.len(), 1);

    if let Some(auth_token) = auth_tokens_returned.pop() {
        assert_eq!(auth_token.auth_token.timestamp.milliSeconds, 600);
    }

    // insert another auth token with the different values for the columns in the UNIQUE
    // constraint of the auth token table
    let auth_token3 = HardwareAuthToken {
        challenge: i64::MAX,
        userId: 201,
        authenticatorId: 200,
        authenticatorType: kmhw_authenticator_type(kmhw_authenticator_type::PASSWORD.0),
        timestamp: Timestamp { milliSeconds: 600 },
        mac: String::from("mac").into_bytes(),
    };

    db.insert_auth_token(&auth_token3);
    let auth_tokens_returned = get_auth_tokens(&db);
    assert_eq!(auth_tokens_returned.len(), 2);

    Ok(())
}

// utility function for test_auth_token_table_invariant()
fn get_auth_tokens(db: &KeystoreDB) -> Vec<AuthTokenEntry> {
    db.perboot.get_all_auth_token_entries()
}

fn create_key_entry(
    db: &mut KeystoreDB,
    domain: &Domain,
    namespace: &i64,
    key_type: KeyType,
    km_uuid: &Uuid,
) -> Result<KeyIdGuard> {
    db.with_transaction(Immediate("TX_create_key_entry"), |tx| {
        KeystoreDB::create_key_entry_internal(tx, domain, namespace, key_type, km_uuid).no_gc()
    })
}

#[test]
fn test_persistence_for_files() -> Result<()> {
    let temp_dir = TempDir::new("persistent_db_test")?;
    let mut db = KeystoreDB::new(temp_dir.path(), None)?;

    create_key_entry(&mut db, &Domain::APP, &100, KeyType::Client, &KEYSTORE_UUID)?;
    let entries = get_keyentry(&db)?;
    assert_eq!(entries.len(), 1);

    let db = KeystoreDB::new(temp_dir.path(), None)?;

    let entries_new = get_keyentry(&db)?;
    assert_eq!(entries, entries_new);
    Ok(())
}

#[test]
fn test_create_key_entry() -> Result<()> {
    fn extractor(ke: &KeyEntryRow) -> (Domain, i64, Option<&str>, Uuid) {
        (ke.domain.unwrap(), ke.namespace.unwrap(), ke.alias.as_deref(), ke.km_uuid.unwrap())
    }

    let mut db = new_test_db()?;

    create_key_entry(&mut db, &Domain::APP, &100, KeyType::Client, &KEYSTORE_UUID)?;
    create_key_entry(&mut db, &Domain::SELINUX, &101, KeyType::Client, &KEYSTORE_UUID)?;

    let entries = get_keyentry(&db)?;
    assert_eq!(entries.len(), 2);
    assert_eq!(extractor(&entries[0]), (Domain::APP, 100, None, KEYSTORE_UUID));
    assert_eq!(extractor(&entries[1]), (Domain::SELINUX, 101, None, KEYSTORE_UUID));

    // Test that we must pass in a valid Domain.
    check_result_is_error_containing_string(
        create_key_entry(&mut db, &Domain::GRANT, &102, KeyType::Client, &KEYSTORE_UUID),
        &format!("Domain {:?} must be either App or SELinux.", Domain::GRANT),
    );
    check_result_is_error_containing_string(
        create_key_entry(&mut db, &Domain::BLOB, &103, KeyType::Client, &KEYSTORE_UUID),
        &format!("Domain {:?} must be either App or SELinux.", Domain::BLOB),
    );
    check_result_is_error_containing_string(
        create_key_entry(&mut db, &Domain::KEY_ID, &104, KeyType::Client, &KEYSTORE_UUID),
        &format!("Domain {:?} must be either App or SELinux.", Domain::KEY_ID),
    );

    Ok(())
}

#[test]
fn test_rebind_alias() -> Result<()> {
    fn extractor(ke: &KeyEntryRow) -> (Option<Domain>, Option<i64>, Option<&str>, Option<Uuid>) {
        (ke.domain, ke.namespace, ke.alias.as_deref(), ke.km_uuid)
    }

    let mut db = new_test_db()?;
    create_key_entry(&mut db, &Domain::APP, &42, KeyType::Client, &KEYSTORE_UUID)?;
    create_key_entry(&mut db, &Domain::APP, &42, KeyType::Client, &KEYSTORE_UUID)?;
    let entries = get_keyentry(&db)?;
    assert_eq!(entries.len(), 2);
    assert_eq!(extractor(&entries[0]), (Some(Domain::APP), Some(42), None, Some(KEYSTORE_UUID)));
    assert_eq!(extractor(&entries[1]), (Some(Domain::APP), Some(42), None, Some(KEYSTORE_UUID)));

    // Test that the first call to rebind_alias sets the alias.
    rebind_alias(&mut db, &KEY_ID_LOCK.get(entries[0].id), "foo", Domain::APP, 42)?;
    let entries = get_keyentry(&db)?;
    assert_eq!(entries.len(), 2);
    assert_eq!(
        extractor(&entries[0]),
        (Some(Domain::APP), Some(42), Some("foo"), Some(KEYSTORE_UUID))
    );
    assert_eq!(extractor(&entries[1]), (Some(Domain::APP), Some(42), None, Some(KEYSTORE_UUID)));

    // Test that the second call to rebind_alias also empties the old one.
    rebind_alias(&mut db, &KEY_ID_LOCK.get(entries[1].id), "foo", Domain::APP, 42)?;
    let entries = get_keyentry(&db)?;
    assert_eq!(entries.len(), 2);
    assert_eq!(extractor(&entries[0]), (None, None, None, Some(KEYSTORE_UUID)));
    assert_eq!(
        extractor(&entries[1]),
        (Some(Domain::APP), Some(42), Some("foo"), Some(KEYSTORE_UUID))
    );

    // Test that we must pass in a valid Domain.
    check_result_is_error_containing_string(
        rebind_alias(&mut db, &KEY_ID_LOCK.get(0), "foo", Domain::GRANT, 42),
        &format!("Domain {:?} must be either App or SELinux.", Domain::GRANT),
    );
    check_result_is_error_containing_string(
        rebind_alias(&mut db, &KEY_ID_LOCK.get(0), "foo", Domain::BLOB, 42),
        &format!("Domain {:?} must be either App or SELinux.", Domain::BLOB),
    );
    check_result_is_error_containing_string(
        rebind_alias(&mut db, &KEY_ID_LOCK.get(0), "foo", Domain::KEY_ID, 42),
        &format!("Domain {:?} must be either App or SELinux.", Domain::KEY_ID),
    );

    // Test that we correctly handle setting an alias for something that does not exist.
    check_result_is_error_containing_string(
        rebind_alias(&mut db, &KEY_ID_LOCK.get(0), "foo", Domain::SELINUX, 42),
        "Expected to update a single entry but instead updated 0",
    );
    // Test that we correctly abort the transaction in this case.
    let entries = get_keyentry(&db)?;
    assert_eq!(entries.len(), 2);
    assert_eq!(extractor(&entries[0]), (None, None, None, Some(KEYSTORE_UUID)));
    assert_eq!(
        extractor(&entries[1]),
        (Some(Domain::APP), Some(42), Some("foo"), Some(KEYSTORE_UUID))
    );

    Ok(())
}

#[test]
fn test_grant_ungrant() -> Result<()> {
    const CALLER_UID: u32 = 15;
    const GRANTEE_UID: u32 = 12;
    const SELINUX_NAMESPACE: i64 = 7;

    let mut db = new_test_db()?;
    db.conn.execute(
        "INSERT INTO persistent.keyentry (id, key_type, domain, namespace, alias, state, km_uuid)
                VALUES (1, 0, 0, 15, 'key', 1, ?), (2, 0, 2, 7, 'yek', 1, ?);",
        params![KEYSTORE_UUID, KEYSTORE_UUID],
    )?;
    let app_key = KeyDescriptor {
        domain: super::Domain::APP,
        nspace: 0,
        alias: Some("key".to_string()),
        blob: None,
    };
    const PVEC1: KeyPermSet = key_perm_set![KeyPerm::Use, KeyPerm::GetInfo];
    const PVEC2: KeyPermSet = key_perm_set![KeyPerm::Use];

    // Reset totally predictable random number generator in case we
    // are not the first test running on this thread.
    reset_random();
    let next_random = 0i64;

    let app_granted_key = db
        .grant(&app_key, CALLER_UID, GRANTEE_UID, PVEC1, |k, a| {
            assert_eq!(*a, PVEC1);
            assert_eq!(
                *k,
                KeyDescriptor {
                    domain: super::Domain::APP,
                    // namespace must be set to the caller_uid.
                    nspace: CALLER_UID as i64,
                    alias: Some("key".to_string()),
                    blob: None,
                }
            );
            Ok(())
        })
        .unwrap();

    assert_eq!(
        app_granted_key,
        KeyDescriptor {
            domain: super::Domain::GRANT,
            // The grantid is next_random due to the mock random number generator.
            nspace: next_random,
            alias: None,
            blob: None,
        }
    );

    let selinux_key = KeyDescriptor {
        domain: super::Domain::SELINUX,
        nspace: SELINUX_NAMESPACE,
        alias: Some("yek".to_string()),
        blob: None,
    };

    let selinux_granted_key = db
        .grant(&selinux_key, CALLER_UID, 12, PVEC1, |k, a| {
            assert_eq!(*a, PVEC1);
            assert_eq!(
                *k,
                KeyDescriptor {
                    domain: super::Domain::SELINUX,
                    // namespace must be the supplied SELinux
                    // namespace.
                    nspace: SELINUX_NAMESPACE,
                    alias: Some("yek".to_string()),
                    blob: None,
                }
            );
            Ok(())
        })
        .unwrap();

    assert_eq!(
        selinux_granted_key,
        KeyDescriptor {
            domain: super::Domain::GRANT,
            // The grantid is next_random + 1 due to the mock random number generator.
            nspace: next_random + 1,
            alias: None,
            blob: None,
        }
    );

    // This should update the existing grant with PVEC2.
    let selinux_granted_key = db
        .grant(&selinux_key, CALLER_UID, 12, PVEC2, |k, a| {
            assert_eq!(*a, PVEC2);
            assert_eq!(
                *k,
                KeyDescriptor {
                    domain: super::Domain::SELINUX,
                    // namespace must be the supplied SELinux
                    // namespace.
                    nspace: SELINUX_NAMESPACE,
                    alias: Some("yek".to_string()),
                    blob: None,
                }
            );
            Ok(())
        })
        .unwrap();

    assert_eq!(
        selinux_granted_key,
        KeyDescriptor {
            domain: super::Domain::GRANT,
            // Same grant id as before. The entry was only updated.
            nspace: next_random + 1,
            alias: None,
            blob: None,
        }
    );

    {
        // Limiting scope of stmt, because it borrows db.
        let mut stmt = db
            .conn
            .prepare("SELECT id, grantee, keyentryid, access_vector FROM persistent.grant;")?;
        let mut rows = stmt.query_map::<(i64, u32, i64, KeyPermSet), _, _>([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, KeyPermSet::from(row.get::<_, i32>(3)?)))
        })?;

        let r = rows.next().unwrap().unwrap();
        assert_eq!(r, (next_random, GRANTEE_UID, 1, PVEC1));
        let r = rows.next().unwrap().unwrap();
        assert_eq!(r, (next_random + 1, GRANTEE_UID, 2, PVEC2));
        assert!(rows.next().is_none());
    }

    debug_dump_keyentry_table(&mut db)?;
    println!("app_key {:?}", app_key);
    println!("selinux_key {:?}", selinux_key);

    db.ungrant(&app_key, CALLER_UID, GRANTEE_UID, |_| Ok(()))?;
    db.ungrant(&selinux_key, CALLER_UID, GRANTEE_UID, |_| Ok(()))?;

    Ok(())
}

static TEST_KEY_BLOB: &[u8] = b"my test blob";
static TEST_CERT_BLOB: &[u8] = b"my test cert";
static TEST_CERT_CHAIN_BLOB: &[u8] = b"my test cert_chain";

#[test]
fn test_set_blob() -> Result<()> {
    let key_id = KEY_ID_LOCK.get(3000);
    let mut db = new_test_db()?;
    let mut blob_metadata = BlobMetaData::new();
    blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));
    db.set_blob(&key_id, SubComponentType::KEY_BLOB, Some(TEST_KEY_BLOB), Some(&blob_metadata))?;
    db.set_blob(&key_id, SubComponentType::CERT, Some(TEST_CERT_BLOB), None)?;
    db.set_blob(&key_id, SubComponentType::CERT_CHAIN, Some(TEST_CERT_CHAIN_BLOB), None)?;
    drop(key_id);

    let mut stmt = db.conn.prepare(
        "SELECT subcomponent_type, keyentryid, blob, id FROM persistent.blobentry
                ORDER BY subcomponent_type ASC;",
    )?;
    let mut rows = stmt.query_map::<((SubComponentType, i64, Vec<u8>), i64), _, _>([], |row| {
        Ok(((row.get(0)?, row.get(1)?, row.get(2)?), row.get(3)?))
    })?;
    let (r, id) = rows.next().unwrap().unwrap();
    assert_eq!(r, (SubComponentType::KEY_BLOB, 3000, TEST_KEY_BLOB.to_vec()));
    let (r, _) = rows.next().unwrap().unwrap();
    assert_eq!(r, (SubComponentType::CERT, 3000, TEST_CERT_BLOB.to_vec()));
    let (r, _) = rows.next().unwrap().unwrap();
    assert_eq!(r, (SubComponentType::CERT_CHAIN, 3000, TEST_CERT_CHAIN_BLOB.to_vec()));

    drop(rows);
    drop(stmt);

    assert_eq!(
        db.with_transaction(Immediate("TX_test"), |tx| {
            BlobMetaData::load_from_db(id, tx).no_gc()
        })
        .expect("Should find blob metadata."),
        blob_metadata
    );
    Ok(())
}

static TEST_ALIAS: &str = "my super duper key";

#[test]
fn test_insert_and_load_full_keyentry_domain_app() -> Result<()> {
    let mut db = new_test_db()?;
    let key_id = make_test_key_entry(&mut db, Domain::APP, 1, TEST_ALIAS, None)
        .context("test_insert_and_load_full_keyentry_domain_app")?
        .0;
    let (_key_guard, key_entry) = db
        .load_key_entry(
            &KeyDescriptor {
                domain: Domain::APP,
                nspace: 0,
                alias: Some(TEST_ALIAS.to_string()),
                blob: None,
            },
            KeyType::Client,
            KeyEntryLoadBits::BOTH,
            1,
            |_k, _av| Ok(()),
        )
        .unwrap();
    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));

    db.unbind_key(
        &KeyDescriptor {
            domain: Domain::APP,
            nspace: 0,
            alias: Some(TEST_ALIAS.to_string()),
            blob: None,
        },
        KeyType::Client,
        1,
        |_, _| Ok(()),
    )
    .unwrap();

    assert_eq!(
        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
        db.load_key_entry(
            &KeyDescriptor {
                domain: Domain::APP,
                nspace: 0,
                alias: Some(TEST_ALIAS.to_string()),
                blob: None,
            },
            KeyType::Client,
            KeyEntryLoadBits::NONE,
            1,
            |_k, _av| Ok(()),
        )
        .unwrap_err()
        .root_cause()
        .downcast_ref::<KsError>()
    );

    Ok(())
}

#[test]
fn test_insert_and_load_certificate_entry_domain_app() -> Result<()> {
    let mut db = new_test_db()?;

    db.store_new_certificate(
        &KeyDescriptor {
            domain: Domain::APP,
            nspace: 1,
            alias: Some(TEST_ALIAS.to_string()),
            blob: None,
        },
        KeyType::Client,
        TEST_CERT_BLOB,
        &KEYSTORE_UUID,
    )
    .expect("Trying to insert cert.");

    let (_key_guard, mut key_entry) = db
        .load_key_entry(
            &KeyDescriptor {
                domain: Domain::APP,
                nspace: 1,
                alias: Some(TEST_ALIAS.to_string()),
                blob: None,
            },
            KeyType::Client,
            KeyEntryLoadBits::PUBLIC,
            1,
            |_k, _av| Ok(()),
        )
        .expect("Trying to read certificate entry.");

    assert!(key_entry.pure_cert());
    assert!(key_entry.cert().is_none());
    assert_eq!(key_entry.take_cert_chain(), Some(TEST_CERT_BLOB.to_vec()));

    db.unbind_key(
        &KeyDescriptor {
            domain: Domain::APP,
            nspace: 1,
            alias: Some(TEST_ALIAS.to_string()),
            blob: None,
        },
        KeyType::Client,
        1,
        |_, _| Ok(()),
    )
    .unwrap();

    assert_eq!(
        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
        db.load_key_entry(
            &KeyDescriptor {
                domain: Domain::APP,
                nspace: 1,
                alias: Some(TEST_ALIAS.to_string()),
                blob: None,
            },
            KeyType::Client,
            KeyEntryLoadBits::NONE,
            1,
            |_k, _av| Ok(()),
        )
        .unwrap_err()
        .root_cause()
        .downcast_ref::<KsError>()
    );

    Ok(())
}

#[test]
fn test_insert_and_load_full_keyentry_domain_selinux() -> Result<()> {
    let mut db = new_test_db()?;
    let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS, None)
        .context("test_insert_and_load_full_keyentry_domain_selinux")?
        .0;
    let (_key_guard, key_entry) = db
        .load_key_entry(
            &KeyDescriptor {
                domain: Domain::SELINUX,
                nspace: 1,
                alias: Some(TEST_ALIAS.to_string()),
                blob: None,
            },
            KeyType::Client,
            KeyEntryLoadBits::BOTH,
            1,
            |_k, _av| Ok(()),
        )
        .unwrap();
    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));

    db.unbind_key(
        &KeyDescriptor {
            domain: Domain::SELINUX,
            nspace: 1,
            alias: Some(TEST_ALIAS.to_string()),
            blob: None,
        },
        KeyType::Client,
        1,
        |_, _| Ok(()),
    )
    .unwrap();

    assert_eq!(
        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
        db.load_key_entry(
            &KeyDescriptor {
                domain: Domain::SELINUX,
                nspace: 1,
                alias: Some(TEST_ALIAS.to_string()),
                blob: None,
            },
            KeyType::Client,
            KeyEntryLoadBits::NONE,
            1,
            |_k, _av| Ok(()),
        )
        .unwrap_err()
        .root_cause()
        .downcast_ref::<KsError>()
    );

    Ok(())
}

#[test]
fn test_insert_and_load_full_keyentry_domain_key_id() -> Result<()> {
    let mut db = new_test_db()?;
    let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS, None)
        .context("test_insert_and_load_full_keyentry_domain_key_id")?
        .0;
    let (_, key_entry) = db
        .load_key_entry(
            &KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
            KeyType::Client,
            KeyEntryLoadBits::BOTH,
            1,
            |_k, _av| Ok(()),
        )
        .unwrap();

    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));

    db.unbind_key(
        &KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
        KeyType::Client,
        1,
        |_, _| Ok(()),
    )
    .unwrap();

    assert_eq!(
        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
        db.load_key_entry(
            &KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
            KeyType::Client,
            KeyEntryLoadBits::NONE,
            1,
            |_k, _av| Ok(()),
        )
        .unwrap_err()
        .root_cause()
        .downcast_ref::<KsError>()
    );

    Ok(())
}

#[test]
fn test_check_and_update_key_usage_count_with_limited_use_key() -> Result<()> {
    let mut db = new_test_db()?;
    let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS, Some(123))
        .context("test_check_and_update_key_usage_count_with_limited_use_key")?
        .0;
    // Update the usage count of the limited use key.
    db.check_and_update_key_usage_count(key_id)?;

    let (_key_guard, key_entry) = db.load_key_entry(
        &KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, alias: None, blob: None },
        KeyType::Client,
        KeyEntryLoadBits::BOTH,
        1,
        |_k, _av| Ok(()),
    )?;

    // The usage count is decremented now.
    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, Some(122)));

    Ok(())
}

#[test]
fn test_check_and_update_key_usage_count_with_exhausted_limited_use_key() -> Result<()> {
    let mut db = new_test_db()?;
    let key_id = make_test_key_entry(&mut db, Domain::SELINUX, 1, TEST_ALIAS, Some(1))
        .context("test_check_and_update_key_usage_count_with_exhausted_limited_use_key")?
        .0;
    // Update the usage count of the limited use key.
    db.check_and_update_key_usage_count(key_id).expect(concat!(
        "In test_check_and_update_key_usage_count_with_exhausted_limited_use_key: ",
        "This should succeed."
    ));

    // Try to update the exhausted limited use key.
    let e = db.check_and_update_key_usage_count(key_id).expect_err(concat!(
        "In test_check_and_update_key_usage_count_with_exhausted_limited_use_key: ",
        "This should fail."
    ));
    assert_eq!(
        &KsError::Km(ErrorCode::INVALID_KEY_BLOB),
        e.root_cause().downcast_ref::<KsError>().unwrap()
    );

    Ok(())
}

#[test]
fn test_insert_and_load_full_keyentry_from_grant() -> Result<()> {
    let mut db = new_test_db()?;
    let key_id = make_test_key_entry(&mut db, Domain::APP, 1, TEST_ALIAS, None)
        .context("test_insert_and_load_full_keyentry_from_grant")?
        .0;

    let granted_key = db
        .grant(
            &KeyDescriptor {
                domain: Domain::APP,
                nspace: 0,
                alias: Some(TEST_ALIAS.to_string()),
                blob: None,
            },
            1,
            2,
            key_perm_set![KeyPerm::Use],
            |_k, _av| Ok(()),
        )
        .unwrap();

    debug_dump_grant_table(&mut db)?;

    let (_key_guard, key_entry) = db
        .load_key_entry(&granted_key, KeyType::Client, KeyEntryLoadBits::BOTH, 2, |k, av| {
            assert_eq!(Domain::GRANT, k.domain);
            assert!(av.unwrap().includes(KeyPerm::Use));
            Ok(())
        })
        .unwrap();

    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));

    db.unbind_key(&granted_key, KeyType::Client, 2, |_, _| Ok(())).unwrap();

    assert_eq!(
        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
        db.load_key_entry(&granted_key, KeyType::Client, KeyEntryLoadBits::NONE, 2, |_k, _av| Ok(
            ()
        ),)
            .unwrap_err()
            .root_cause()
            .downcast_ref::<KsError>()
    );

    Ok(())
}

// This test attempts to load a key by key id while the caller is not the owner
// but a grant exists for the given key and the caller.
#[test]
fn test_insert_and_load_full_keyentry_from_grant_by_key_id() -> Result<()> {
    let mut db = new_test_db()?;
    const OWNER_UID: u32 = 1u32;
    const GRANTEE_UID: u32 = 2u32;
    const SOMEONE_ELSE_UID: u32 = 3u32;
    let key_id = make_test_key_entry(&mut db, Domain::APP, OWNER_UID as i64, TEST_ALIAS, None)
        .context("test_insert_and_load_full_keyentry_from_grant_by_key_id")?
        .0;

    db.grant(
        &KeyDescriptor {
            domain: Domain::APP,
            nspace: 0,
            alias: Some(TEST_ALIAS.to_string()),
            blob: None,
        },
        OWNER_UID,
        GRANTEE_UID,
        key_perm_set![KeyPerm::Use],
        |_k, _av| Ok(()),
    )
    .unwrap();

    debug_dump_grant_table(&mut db)?;

    let id_descriptor =
        KeyDescriptor { domain: Domain::KEY_ID, nspace: key_id, ..Default::default() };

    let (_, key_entry) = db
        .load_key_entry(
            &id_descriptor,
            KeyType::Client,
            KeyEntryLoadBits::BOTH,
            GRANTEE_UID,
            |k, av| {
                assert_eq!(Domain::APP, k.domain);
                assert_eq!(OWNER_UID as i64, k.nspace);
                assert!(av.unwrap().includes(KeyPerm::Use));
                Ok(())
            },
        )
        .unwrap();

    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));

    let (_, key_entry) = db
        .load_key_entry(
            &id_descriptor,
            KeyType::Client,
            KeyEntryLoadBits::BOTH,
            SOMEONE_ELSE_UID,
            |k, av| {
                assert_eq!(Domain::APP, k.domain);
                assert_eq!(OWNER_UID as i64, k.nspace);
                assert!(av.is_none());
                Ok(())
            },
        )
        .unwrap();

    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));

    db.unbind_key(&id_descriptor, KeyType::Client, OWNER_UID, |_, _| Ok(())).unwrap();

    assert_eq!(
        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
        db.load_key_entry(
            &id_descriptor,
            KeyType::Client,
            KeyEntryLoadBits::NONE,
            GRANTEE_UID,
            |_k, _av| Ok(()),
        )
        .unwrap_err()
        .root_cause()
        .downcast_ref::<KsError>()
    );

    Ok(())
}

// Creates a key migrates it to a different location and then tries to access it by the old
// and new location.
#[test]
fn test_migrate_key_app_to_app() -> Result<()> {
    let mut db = new_test_db()?;
    const SOURCE_UID: u32 = 1u32;
    const DESTINATION_UID: u32 = 2u32;
    static SOURCE_ALIAS: &str = "SOURCE_ALIAS";
    static DESTINATION_ALIAS: &str = "DESTINATION_ALIAS";
    let key_id_guard =
        make_test_key_entry(&mut db, Domain::APP, SOURCE_UID as i64, SOURCE_ALIAS, None)
            .context("test_insert_and_load_full_keyentry_from_grant_by_key_id")?;

    let source_descriptor: KeyDescriptor = KeyDescriptor {
        domain: Domain::APP,
        nspace: -1,
        alias: Some(SOURCE_ALIAS.to_string()),
        blob: None,
    };

    let destination_descriptor: KeyDescriptor = KeyDescriptor {
        domain: Domain::APP,
        nspace: -1,
        alias: Some(DESTINATION_ALIAS.to_string()),
        blob: None,
    };

    let key_id = key_id_guard.id();

    db.migrate_key_namespace(key_id_guard, &destination_descriptor, DESTINATION_UID, |_k| Ok(()))
        .unwrap();

    let (_, key_entry) = db
        .load_key_entry(
            &destination_descriptor,
            KeyType::Client,
            KeyEntryLoadBits::BOTH,
            DESTINATION_UID,
            |k, av| {
                assert_eq!(Domain::APP, k.domain);
                assert_eq!(DESTINATION_UID as i64, k.nspace);
                assert!(av.is_none());
                Ok(())
            },
        )
        .unwrap();

    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));

    assert_eq!(
        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
        db.load_key_entry(
            &source_descriptor,
            KeyType::Client,
            KeyEntryLoadBits::NONE,
            SOURCE_UID,
            |_k, _av| Ok(()),
        )
        .unwrap_err()
        .root_cause()
        .downcast_ref::<KsError>()
    );

    Ok(())
}

// Creates a key migrates it to a different location and then tries to access it by the old
// and new location.
#[test]
fn test_migrate_key_app_to_selinux() -> Result<()> {
    let mut db = new_test_db()?;
    const SOURCE_UID: u32 = 1u32;
    const DESTINATION_UID: u32 = 2u32;
    const DESTINATION_NAMESPACE: i64 = 1000i64;
    static SOURCE_ALIAS: &str = "SOURCE_ALIAS";
    static DESTINATION_ALIAS: &str = "DESTINATION_ALIAS";
    let key_id_guard =
        make_test_key_entry(&mut db, Domain::APP, SOURCE_UID as i64, SOURCE_ALIAS, None)
            .context("test_insert_and_load_full_keyentry_from_grant_by_key_id")?;

    let source_descriptor: KeyDescriptor = KeyDescriptor {
        domain: Domain::APP,
        nspace: -1,
        alias: Some(SOURCE_ALIAS.to_string()),
        blob: None,
    };

    let destination_descriptor: KeyDescriptor = KeyDescriptor {
        domain: Domain::SELINUX,
        nspace: DESTINATION_NAMESPACE,
        alias: Some(DESTINATION_ALIAS.to_string()),
        blob: None,
    };

    let key_id = key_id_guard.id();

    db.migrate_key_namespace(key_id_guard, &destination_descriptor, DESTINATION_UID, |_k| Ok(()))
        .unwrap();

    let (_, key_entry) = db
        .load_key_entry(
            &destination_descriptor,
            KeyType::Client,
            KeyEntryLoadBits::BOTH,
            DESTINATION_UID,
            |k, av| {
                assert_eq!(Domain::SELINUX, k.domain);
                assert_eq!(DESTINATION_NAMESPACE, k.nspace);
                assert!(av.is_none());
                Ok(())
            },
        )
        .unwrap();

    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));

    assert_eq!(
        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
        db.load_key_entry(
            &source_descriptor,
            KeyType::Client,
            KeyEntryLoadBits::NONE,
            SOURCE_UID,
            |_k, _av| Ok(()),
        )
        .unwrap_err()
        .root_cause()
        .downcast_ref::<KsError>()
    );

    Ok(())
}

// Creates two keys and tries to migrate the first to the location of the second which
// is expected to fail.
#[test]
fn test_migrate_key_destination_occupied() -> Result<()> {
    let mut db = new_test_db()?;
    const SOURCE_UID: u32 = 1u32;
    const DESTINATION_UID: u32 = 2u32;
    static SOURCE_ALIAS: &str = "SOURCE_ALIAS";
    static DESTINATION_ALIAS: &str = "DESTINATION_ALIAS";
    let key_id_guard =
        make_test_key_entry(&mut db, Domain::APP, SOURCE_UID as i64, SOURCE_ALIAS, None)
            .context("test_insert_and_load_full_keyentry_from_grant_by_key_id")?;
    make_test_key_entry(&mut db, Domain::APP, DESTINATION_UID as i64, DESTINATION_ALIAS, None)
        .context("test_insert_and_load_full_keyentry_from_grant_by_key_id")?;

    let destination_descriptor: KeyDescriptor = KeyDescriptor {
        domain: Domain::APP,
        nspace: -1,
        alias: Some(DESTINATION_ALIAS.to_string()),
        blob: None,
    };

    assert_eq!(
        Some(&KsError::Rc(ResponseCode::INVALID_ARGUMENT)),
        db.migrate_key_namespace(key_id_guard, &destination_descriptor, DESTINATION_UID, |_k| Ok(
            ()
        ))
        .unwrap_err()
        .root_cause()
        .downcast_ref::<KsError>()
    );

    Ok(())
}

#[test]
fn test_upgrade_0_to_1() {
    const ALIAS1: &str = "test_upgrade_0_to_1_1";
    const ALIAS2: &str = "test_upgrade_0_to_1_2";
    const ALIAS3: &str = "test_upgrade_0_to_1_3";
    const UID: u32 = 33;
    let temp_dir = Arc::new(TempDir::new("test_upgrade_0_to_1").unwrap());
    let mut db = KeystoreDB::new(temp_dir.path(), None).unwrap();
    let key_id_untouched1 =
        make_test_key_entry(&mut db, Domain::APP, UID as i64, ALIAS1, None).unwrap().id();
    let key_id_untouched2 =
        make_bootlevel_key_entry(&mut db, Domain::APP, UID as i64, ALIAS2, false).unwrap().id();
    let key_id_deleted =
        make_bootlevel_key_entry(&mut db, Domain::APP, UID as i64, ALIAS3, true).unwrap().id();

    let (_, key_entry) = db
        .load_key_entry(
            &KeyDescriptor {
                domain: Domain::APP,
                nspace: -1,
                alias: Some(ALIAS1.to_string()),
                blob: None,
            },
            KeyType::Client,
            KeyEntryLoadBits::BOTH,
            UID,
            |k, av| {
                assert_eq!(Domain::APP, k.domain);
                assert_eq!(UID as i64, k.nspace);
                assert!(av.is_none());
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id_untouched1, None));
    let (_, key_entry) = db
        .load_key_entry(
            &KeyDescriptor {
                domain: Domain::APP,
                nspace: -1,
                alias: Some(ALIAS2.to_string()),
                blob: None,
            },
            KeyType::Client,
            KeyEntryLoadBits::BOTH,
            UID,
            |k, av| {
                assert_eq!(Domain::APP, k.domain);
                assert_eq!(UID as i64, k.nspace);
                assert!(av.is_none());
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(key_entry, make_bootlevel_test_key_entry_test_vector(key_id_untouched2, false));
    let (_, key_entry) = db
        .load_key_entry(
            &KeyDescriptor {
                domain: Domain::APP,
                nspace: -1,
                alias: Some(ALIAS3.to_string()),
                blob: None,
            },
            KeyType::Client,
            KeyEntryLoadBits::BOTH,
            UID,
            |k, av| {
                assert_eq!(Domain::APP, k.domain);
                assert_eq!(UID as i64, k.nspace);
                assert!(av.is_none());
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(key_entry, make_bootlevel_test_key_entry_test_vector(key_id_deleted, true));

    db.with_transaction(Immediate("TX_test"), |tx| KeystoreDB::from_0_to_1(tx).no_gc()).unwrap();

    let (_, key_entry) = db
        .load_key_entry(
            &KeyDescriptor {
                domain: Domain::APP,
                nspace: -1,
                alias: Some(ALIAS1.to_string()),
                blob: None,
            },
            KeyType::Client,
            KeyEntryLoadBits::BOTH,
            UID,
            |k, av| {
                assert_eq!(Domain::APP, k.domain);
                assert_eq!(UID as i64, k.nspace);
                assert!(av.is_none());
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(key_entry, make_test_key_entry_test_vector(key_id_untouched1, None));
    let (_, key_entry) = db
        .load_key_entry(
            &KeyDescriptor {
                domain: Domain::APP,
                nspace: -1,
                alias: Some(ALIAS2.to_string()),
                blob: None,
            },
            KeyType::Client,
            KeyEntryLoadBits::BOTH,
            UID,
            |k, av| {
                assert_eq!(Domain::APP, k.domain);
                assert_eq!(UID as i64, k.nspace);
                assert!(av.is_none());
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(key_entry, make_bootlevel_test_key_entry_test_vector(key_id_untouched2, false));
    assert_eq!(
        Some(&KsError::Rc(ResponseCode::KEY_NOT_FOUND)),
        db.load_key_entry(
            &KeyDescriptor {
                domain: Domain::APP,
                nspace: -1,
                alias: Some(ALIAS3.to_string()),
                blob: None,
            },
            KeyType::Client,
            KeyEntryLoadBits::BOTH,
            UID,
            |k, av| {
                assert_eq!(Domain::APP, k.domain);
                assert_eq!(UID as i64, k.nspace);
                assert!(av.is_none());
                Ok(())
            },
        )
        .unwrap_err()
        .root_cause()
        .downcast_ref::<KsError>()
    );
}

static KEY_LOCK_TEST_ALIAS: &str = "my super duper locked key";

#[test]
fn test_insert_and_load_full_keyentry_domain_app_concurrently() -> Result<()> {
    let handle = {
        let temp_dir = Arc::new(TempDir::new("id_lock_test")?);
        let temp_dir_clone = temp_dir.clone();
        let mut db = KeystoreDB::new(temp_dir.path(), None)?;
        let key_id = make_test_key_entry(&mut db, Domain::APP, 33, KEY_LOCK_TEST_ALIAS, None)
            .context("test_insert_and_load_full_keyentry_domain_app")?
            .0;
        let (_key_guard, key_entry) = db
            .load_key_entry(
                &KeyDescriptor {
                    domain: Domain::APP,
                    nspace: 0,
                    alias: Some(KEY_LOCK_TEST_ALIAS.to_string()),
                    blob: None,
                },
                KeyType::Client,
                KeyEntryLoadBits::BOTH,
                33,
                |_k, _av| Ok(()),
            )
            .unwrap();
        assert_eq!(key_entry, make_test_key_entry_test_vector(key_id, None));
        let state = Arc::new(AtomicU8::new(1));
        let state2 = state.clone();

        // Spawning a second thread that attempts to acquire the key id lock
        // for the same key as the primary thread. The primary thread then
        // waits, thereby forcing the secondary thread into the second stage
        // of acquiring the lock (see KEY ID LOCK 2/2 above).
        // The test succeeds if the secondary thread observes the transition
        // of `state` from 1 to 2, despite having a whole second to overtake
        // the primary thread.
        let handle = thread::spawn(move || {
            let temp_dir = temp_dir_clone;
            let mut db = KeystoreDB::new(temp_dir.path(), None).unwrap();
            assert!(db
                .load_key_entry(
                    &KeyDescriptor {
                        domain: Domain::APP,
                        nspace: 0,
                        alias: Some(KEY_LOCK_TEST_ALIAS.to_string()),
                        blob: None,
                    },
                    KeyType::Client,
                    KeyEntryLoadBits::BOTH,
                    33,
                    |_k, _av| Ok(()),
                )
                .is_ok());
            // We should only see a 2 here because we can only return
            // from load_key_entry when the `_key_guard` expires,
            // which happens at the end of the scope.
            assert_eq!(2, state2.load(Ordering::Relaxed));
        });

        thread::sleep(std::time::Duration::from_millis(1000));

        assert_eq!(Ok(1), state.compare_exchange(1, 2, Ordering::Relaxed, Ordering::Relaxed));

        // Return the handle from this scope so we can join with the
        // secondary thread after the key id lock has expired.
        handle
        // This is where the `_key_guard` goes out of scope,
        // which is the reason for concurrent load_key_entry on the same key
        // to unblock.
    };
    // Join with the secondary thread and unwrap, to propagate failing asserts to the
    // main test thread. We will not see failing asserts in secondary threads otherwise.
    handle.join().unwrap();
    Ok(())
}

#[test]
fn test_database_busy_error_code() {
    let temp_dir =
        TempDir::new("test_database_busy_error_code_").expect("Failed to create temp dir.");

    let mut db1 = KeystoreDB::new(temp_dir.path(), None).expect("Failed to open database1.");
    let mut db2 = KeystoreDB::new(temp_dir.path(), None).expect("Failed to open database2.");

    let _tx1 = db1
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .expect("Failed to create first transaction.");

    let error = db2
        .conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .context("Transaction begin failed.")
        .expect_err("This should fail.");
    let root_cause = error.root_cause();
    if let Some(rusqlite::ffi::Error { code: rusqlite::ErrorCode::DatabaseBusy, .. }) =
        root_cause.downcast_ref::<rusqlite::ffi::Error>()
    {
        return;
    }
    panic!(
        "Unexpected error {:?} \n{:?} \n{:?}",
        error,
        root_cause,
        root_cause.downcast_ref::<rusqlite::ffi::Error>()
    )
}

#[cfg(disabled)]
#[test]
fn test_large_number_of_concurrent_db_manipulations() -> Result<()> {
    let temp_dir = Arc::new(
        TempDir::new("test_large_number_of_concurrent_db_manipulations_")
            .expect("Failed to create temp dir."),
    );

    let test_begin = Instant::now();

    const KEY_COUNT: u32 = 500u32;
    let mut db =
        new_test_db_with_gc(temp_dir.path(), |_, _| Ok(())).expect("Failed to open database.");
    const OPEN_DB_COUNT: u32 = 50u32;

    let mut actual_key_count = KEY_COUNT;
    // First insert KEY_COUNT keys.
    for count in 0..KEY_COUNT {
        if Instant::now().duration_since(test_begin) >= Duration::from_secs(15) {
            actual_key_count = count;
            break;
        }
        let alias = format!("test_alias_{}", count);
        make_test_key_entry(&mut db, Domain::APP, 1, &alias, None)
            .expect("Failed to make key entry.");
    }

    // Insert more keys from a different thread and into a different namespace.
    let temp_dir1 = temp_dir.clone();
    let handle1 = thread::spawn(move || {
        let mut db =
            new_test_db_with_gc(temp_dir1.path(), |_, _| Ok(())).expect("Failed to open database.");

        for count in 0..actual_key_count {
            if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                return;
            }
            let alias = format!("test_alias_{}", count);
            make_test_key_entry(&mut db, Domain::APP, 2, &alias, None)
                .expect("Failed to make key entry.");
        }

        // then unbind them again.
        for count in 0..actual_key_count {
            if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                return;
            }
            let key = KeyDescriptor {
                domain: Domain::APP,
                nspace: -1,
                alias: Some(format!("test_alias_{}", count)),
                blob: None,
            };
            db.unbind_key(&key, KeyType::Client, 2, |_, _| Ok(())).expect("Unbind Failed.");
        }
    });

    // And start unbinding the first set of keys.
    let temp_dir2 = temp_dir.clone();
    let handle2 = thread::spawn(move || {
        let mut db =
            new_test_db_with_gc(temp_dir2.path(), |_, _| Ok(())).expect("Failed to open database.");

        for count in 0..actual_key_count {
            if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                return;
            }
            let key = KeyDescriptor {
                domain: Domain::APP,
                nspace: -1,
                alias: Some(format!("test_alias_{}", count)),
                blob: None,
            };
            db.unbind_key(&key, KeyType::Client, 1, |_, _| Ok(())).expect("Unbind Failed.");
        }
    });

    // While a lot of inserting and deleting is going on we have to open database connections
    // successfully and use them.
    // This clone is not redundant, because temp_dir needs to be kept alive until db goes
    // out of scope.
    #[allow(clippy::redundant_clone)]
    let temp_dir4 = temp_dir.clone();
    let handle4 = thread::spawn(move || {
        for count in 0..OPEN_DB_COUNT {
            if Instant::now().duration_since(test_begin) >= Duration::from_secs(40) {
                return;
            }
            let mut db = new_test_db_with_gc(temp_dir4.path(), |_, _| Ok(()))
                .expect("Failed to open database.");

            let alias = format!("test_alias_{}", count);
            make_test_key_entry(&mut db, Domain::APP, 3, &alias, None)
                .expect("Failed to make key entry.");
            let key =
                KeyDescriptor { domain: Domain::APP, nspace: -1, alias: Some(alias), blob: None };
            db.unbind_key(&key, KeyType::Client, 3, |_, _| Ok(())).expect("Unbind Failed.");
        }
    });

    handle1.join().expect("Thread 1 panicked.");
    handle2.join().expect("Thread 2 panicked.");
    handle4.join().expect("Thread 4 panicked.");

    Ok(())
}

#[test]
fn list() -> Result<()> {
    let temp_dir = TempDir::new("list_test")?;
    let mut db = KeystoreDB::new(temp_dir.path(), None)?;
    static LIST_O_ENTRIES: &[(Domain, i64, &str)] = &[
        (Domain::APP, 1, "test1"),
        (Domain::APP, 1, "test2"),
        (Domain::APP, 1, "test3"),
        (Domain::APP, 1, "test4"),
        (Domain::APP, 1, "test5"),
        (Domain::APP, 1, "test6"),
        (Domain::APP, 1, "test7"),
        (Domain::APP, 2, "test1"),
        (Domain::APP, 2, "test2"),
        (Domain::APP, 2, "test3"),
        (Domain::APP, 2, "test4"),
        (Domain::APP, 2, "test5"),
        (Domain::APP, 2, "test6"),
        (Domain::APP, 2, "test8"),
        (Domain::SELINUX, 100, "test1"),
        (Domain::SELINUX, 100, "test2"),
        (Domain::SELINUX, 100, "test3"),
        (Domain::SELINUX, 100, "test4"),
        (Domain::SELINUX, 100, "test5"),
        (Domain::SELINUX, 100, "test6"),
        (Domain::SELINUX, 100, "test9"),
    ];

    let list_o_keys: Vec<(i64, i64)> = LIST_O_ENTRIES
        .iter()
        .map(|(domain, ns, alias)| {
            let entry =
                make_test_key_entry(&mut db, *domain, *ns, alias, None).unwrap_or_else(|e| {
                    panic!("Failed to insert {:?} {} {}. Error {:?}", domain, ns, alias, e)
                });
            (entry.id(), *ns)
        })
        .collect();

    for (domain, namespace) in
        &[(Domain::APP, 1i64), (Domain::APP, 2i64), (Domain::SELINUX, 100i64)]
    {
        let mut list_o_descriptors: Vec<KeyDescriptor> = LIST_O_ENTRIES
            .iter()
            .filter_map(|(domain, ns, alias)| match ns {
                ns if *ns == *namespace => Some(KeyDescriptor {
                    domain: *domain,
                    nspace: *ns,
                    alias: Some(alias.to_string()),
                    blob: None,
                }),
                _ => None,
            })
            .collect();
        list_o_descriptors.sort();
        let mut list_result = db.list_past_alias(*domain, *namespace, KeyType::Client, None)?;
        list_result.sort();
        assert_eq!(list_o_descriptors, list_result);

        let mut list_o_ids: Vec<i64> = list_o_descriptors
            .into_iter()
            .map(|d| {
                let (_, entry) = db
                    .load_key_entry(
                        &d,
                        KeyType::Client,
                        KeyEntryLoadBits::NONE,
                        *namespace as u32,
                        |_, _| Ok(()),
                    )
                    .unwrap();
                entry.id()
            })
            .collect();
        list_o_ids.sort_unstable();
        let mut loaded_entries: Vec<i64> = list_o_keys
            .iter()
            .filter_map(|(id, ns)| match ns {
                ns if *ns == *namespace => Some(*id),
                _ => None,
            })
            .collect();
        loaded_entries.sort_unstable();
        assert_eq!(list_o_ids, loaded_entries);
    }
    assert_eq!(
        Vec::<KeyDescriptor>::new(),
        db.list_past_alias(Domain::SELINUX, 101, KeyType::Client, None)?
    );

    Ok(())
}

// Helpers

// Checks that the given result is an error containing the given string.
fn check_result_is_error_containing_string<T>(result: Result<T>, target: &str) {
    let error_str =
        format!("{:#?}", result.err().unwrap_or_else(|| panic!("Expected the error: {}", target)));
    assert!(
        error_str.contains(target),
        "The string \"{}\" should contain \"{}\"",
        error_str,
        target
    );
}

#[derive(Debug, PartialEq)]
struct KeyEntryRow {
    id: i64,
    key_type: KeyType,
    domain: Option<Domain>,
    namespace: Option<i64>,
    alias: Option<String>,
    state: KeyLifeCycle,
    km_uuid: Option<Uuid>,
}

fn get_keyentry(db: &KeystoreDB) -> Result<Vec<KeyEntryRow>> {
    db.conn
        .prepare("SELECT * FROM persistent.keyentry;")?
        .query_map([], |row| {
            Ok(KeyEntryRow {
                id: row.get(0)?,
                key_type: row.get(1)?,
                domain: row.get::<_, Option<_>>(2)?.map(Domain),
                namespace: row.get(3)?,
                alias: row.get(4)?,
                state: row.get(5)?,
                km_uuid: row.get(6)?,
            })
        })?
        .map(|r| r.context("Could not read keyentry row."))
        .collect::<Result<Vec<_>>>()
}

fn make_test_params(max_usage_count: Option<i32>) -> Vec<KeyParameter> {
    make_test_params_with_sids(max_usage_count, &[42])
}

// Note: The parameters and SecurityLevel associations are nonsensical. This
// collection is only used to check if the parameters are preserved as expected by the
// database.
fn make_test_params_with_sids(
    max_usage_count: Option<i32>,
    user_secure_ids: &[i64],
) -> Vec<KeyParameter> {
    let mut params = vec![
        KeyParameter::new(KeyParameterValue::Invalid, SecurityLevel::TRUSTED_ENVIRONMENT),
        KeyParameter::new(
            KeyParameterValue::KeyPurpose(KeyPurpose::SIGN),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::KeyPurpose(KeyPurpose::DECRYPT),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::Algorithm(Algorithm::RSA),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(KeyParameterValue::KeySize(1024), SecurityLevel::TRUSTED_ENVIRONMENT),
        KeyParameter::new(
            KeyParameterValue::BlockMode(BlockMode::ECB),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::BlockMode(BlockMode::GCM),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(KeyParameterValue::Digest(Digest::NONE), SecurityLevel::STRONGBOX),
        KeyParameter::new(
            KeyParameterValue::Digest(Digest::MD5),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::Digest(Digest::SHA_2_224),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(KeyParameterValue::Digest(Digest::SHA_2_256), SecurityLevel::STRONGBOX),
        KeyParameter::new(
            KeyParameterValue::PaddingMode(PaddingMode::NONE),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::PaddingMode(PaddingMode::RSA_OAEP),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::PaddingMode(PaddingMode::RSA_PSS),
            SecurityLevel::STRONGBOX,
        ),
        KeyParameter::new(
            KeyParameterValue::PaddingMode(PaddingMode::RSA_PKCS1_1_5_SIGN),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(KeyParameterValue::CallerNonce, SecurityLevel::TRUSTED_ENVIRONMENT),
        KeyParameter::new(KeyParameterValue::MinMacLength(256), SecurityLevel::STRONGBOX),
        KeyParameter::new(
            KeyParameterValue::EcCurve(EcCurve::P_224),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(KeyParameterValue::EcCurve(EcCurve::P_256), SecurityLevel::STRONGBOX),
        KeyParameter::new(
            KeyParameterValue::EcCurve(EcCurve::P_384),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::EcCurve(EcCurve::P_521),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::RSAPublicExponent(3),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(KeyParameterValue::IncludeUniqueID, SecurityLevel::TRUSTED_ENVIRONMENT),
        KeyParameter::new(KeyParameterValue::BootLoaderOnly, SecurityLevel::STRONGBOX),
        KeyParameter::new(KeyParameterValue::RollbackResistance, SecurityLevel::STRONGBOX),
        KeyParameter::new(KeyParameterValue::ActiveDateTime(1234567890), SecurityLevel::STRONGBOX),
        KeyParameter::new(
            KeyParameterValue::OriginationExpireDateTime(1234567890),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::UsageExpireDateTime(1234567890),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::MinSecondsBetweenOps(1234567890),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::MaxUsesPerBoot(1234567890),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(KeyParameterValue::UserID(1), SecurityLevel::STRONGBOX),
        KeyParameter::new(KeyParameterValue::NoAuthRequired, SecurityLevel::TRUSTED_ENVIRONMENT),
        KeyParameter::new(
            KeyParameterValue::HardwareAuthenticatorType(HardwareAuthenticatorType::PASSWORD),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(KeyParameterValue::AuthTimeout(1234567890), SecurityLevel::SOFTWARE),
        KeyParameter::new(KeyParameterValue::AllowWhileOnBody, SecurityLevel::SOFTWARE),
        KeyParameter::new(
            KeyParameterValue::TrustedUserPresenceRequired,
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::TrustedConfirmationRequired,
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::UnlockedDeviceRequired,
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::ApplicationID(vec![1u8, 2u8, 3u8, 4u8]),
            SecurityLevel::SOFTWARE,
        ),
        KeyParameter::new(
            KeyParameterValue::ApplicationData(vec![4u8, 3u8, 2u8, 1u8]),
            SecurityLevel::SOFTWARE,
        ),
        KeyParameter::new(
            KeyParameterValue::CreationDateTime(12345677890),
            SecurityLevel::SOFTWARE,
        ),
        KeyParameter::new(
            KeyParameterValue::KeyOrigin(KeyOrigin::GENERATED),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::RootOfTrust(vec![3u8, 2u8, 1u8, 4u8]),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(KeyParameterValue::OSVersion(1), SecurityLevel::TRUSTED_ENVIRONMENT),
        KeyParameter::new(KeyParameterValue::OSPatchLevel(2), SecurityLevel::SOFTWARE),
        KeyParameter::new(
            KeyParameterValue::UniqueID(vec![4u8, 3u8, 1u8, 2u8]),
            SecurityLevel::SOFTWARE,
        ),
        KeyParameter::new(
            KeyParameterValue::AttestationChallenge(vec![4u8, 3u8, 1u8, 2u8]),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::AttestationApplicationID(vec![4u8, 3u8, 1u8, 2u8]),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::AttestationIdBrand(vec![4u8, 3u8, 1u8, 2u8]),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::AttestationIdDevice(vec![4u8, 3u8, 1u8, 2u8]),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::AttestationIdProduct(vec![4u8, 3u8, 1u8, 2u8]),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::AttestationIdSerial(vec![4u8, 3u8, 1u8, 2u8]),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::AttestationIdIMEI(vec![4u8, 3u8, 1u8, 2u8]),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::AttestationIdSecondIMEI(vec![4u8, 3u8, 1u8, 2u8]),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::AttestationIdMEID(vec![4u8, 3u8, 1u8, 2u8]),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::AttestationIdManufacturer(vec![4u8, 3u8, 1u8, 2u8]),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::AttestationIdModel(vec![4u8, 3u8, 1u8, 2u8]),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::VendorPatchLevel(3),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(KeyParameterValue::BootPatchLevel(4), SecurityLevel::TRUSTED_ENVIRONMENT),
        KeyParameter::new(
            KeyParameterValue::AssociatedData(vec![4u8, 3u8, 1u8, 2u8]),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::Nonce(vec![4u8, 3u8, 1u8, 2u8]),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(KeyParameterValue::MacLength(256), SecurityLevel::TRUSTED_ENVIRONMENT),
        KeyParameter::new(
            KeyParameterValue::ResetSinceIdRotation,
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
        KeyParameter::new(
            KeyParameterValue::ConfirmationToken(vec![5u8, 5u8, 5u8, 5u8]),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ),
    ];
    if let Some(value) = max_usage_count {
        params.push(KeyParameter::new(
            KeyParameterValue::UsageCountLimit(value),
            SecurityLevel::SOFTWARE,
        ));
    }

    for sid in user_secure_ids.iter() {
        params.push(KeyParameter::new(
            KeyParameterValue::UserSecureID(*sid),
            SecurityLevel::STRONGBOX,
        ));
    }
    params
}

pub fn make_test_key_entry(
    db: &mut KeystoreDB,
    domain: Domain,
    namespace: i64,
    alias: &str,
    max_usage_count: Option<i32>,
) -> Result<KeyIdGuard> {
    make_test_key_entry_with_sids(db, domain, namespace, alias, max_usage_count, &[42])
}

pub fn make_test_key_entry_with_sids(
    db: &mut KeystoreDB,
    domain: Domain,
    namespace: i64,
    alias: &str,
    max_usage_count: Option<i32>,
    sids: &[i64],
) -> Result<KeyIdGuard> {
    let key_id = create_key_entry(db, &domain, &namespace, KeyType::Client, &KEYSTORE_UUID)?;
    let mut blob_metadata = BlobMetaData::new();
    blob_metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::Password));
    blob_metadata.add(BlobMetaEntry::Salt(vec![1, 2, 3]));
    blob_metadata.add(BlobMetaEntry::Iv(vec![2, 3, 1]));
    blob_metadata.add(BlobMetaEntry::AeadTag(vec![3, 1, 2]));
    blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));

    db.set_blob(&key_id, SubComponentType::KEY_BLOB, Some(TEST_KEY_BLOB), Some(&blob_metadata))?;
    db.set_blob(&key_id, SubComponentType::CERT, Some(TEST_CERT_BLOB), None)?;
    db.set_blob(&key_id, SubComponentType::CERT_CHAIN, Some(TEST_CERT_CHAIN_BLOB), None)?;

    let params = make_test_params_with_sids(max_usage_count, sids);
    db.insert_keyparameter(&key_id, &params)?;

    let mut metadata = KeyMetaData::new();
    metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));
    db.insert_key_metadata(&key_id, &metadata)?;
    rebind_alias(db, &key_id, alias, domain, namespace)?;
    Ok(key_id)
}

fn make_test_key_entry_test_vector(key_id: i64, max_usage_count: Option<i32>) -> KeyEntry {
    let params = make_test_params(max_usage_count);

    let mut blob_metadata = BlobMetaData::new();
    blob_metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::Password));
    blob_metadata.add(BlobMetaEntry::Salt(vec![1, 2, 3]));
    blob_metadata.add(BlobMetaEntry::Iv(vec![2, 3, 1]));
    blob_metadata.add(BlobMetaEntry::AeadTag(vec![3, 1, 2]));
    blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));

    let mut metadata = KeyMetaData::new();
    metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));

    KeyEntry {
        id: key_id,
        key_blob_info: Some((TEST_KEY_BLOB.to_vec(), blob_metadata)),
        cert: Some(TEST_CERT_BLOB.to_vec()),
        cert_chain: Some(TEST_CERT_CHAIN_BLOB.to_vec()),
        km_uuid: KEYSTORE_UUID,
        parameters: params,
        metadata,
        pure_cert: false,
    }
}

pub fn make_bootlevel_key_entry(
    db: &mut KeystoreDB,
    domain: Domain,
    namespace: i64,
    alias: &str,
    logical_only: bool,
) -> Result<KeyIdGuard> {
    let key_id = create_key_entry(db, &domain, &namespace, KeyType::Client, &KEYSTORE_UUID)?;
    let mut blob_metadata = BlobMetaData::new();
    if !logical_only {
        blob_metadata.add(BlobMetaEntry::MaxBootLevel(3));
    }
    blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));

    db.set_blob(&key_id, SubComponentType::KEY_BLOB, Some(TEST_KEY_BLOB), Some(&blob_metadata))?;
    db.set_blob(&key_id, SubComponentType::CERT, Some(TEST_CERT_BLOB), None)?;
    db.set_blob(&key_id, SubComponentType::CERT_CHAIN, Some(TEST_CERT_CHAIN_BLOB), None)?;

    let mut params = make_test_params(None);
    params.push(KeyParameter::new(KeyParameterValue::MaxBootLevel(3), SecurityLevel::KEYSTORE));

    db.insert_keyparameter(&key_id, &params)?;

    let mut metadata = KeyMetaData::new();
    metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));
    db.insert_key_metadata(&key_id, &metadata)?;
    rebind_alias(db, &key_id, alias, domain, namespace)?;
    Ok(key_id)
}

// Creates an app key that is marked as being superencrypted by the given
// super key ID and that has the given authentication and unlocked device
// parameters. This does not actually superencrypt the key blob.
fn make_superencrypted_key_entry(
    db: &mut KeystoreDB,
    namespace: i64,
    alias: &str,
    requires_authentication: bool,
    requires_unlocked_device: bool,
    super_key_id: i64,
) -> Result<KeyIdGuard> {
    let domain = Domain::APP;
    let key_id = create_key_entry(db, &domain, &namespace, KeyType::Client, &KEYSTORE_UUID)?;

    let mut blob_metadata = BlobMetaData::new();
    blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));
    blob_metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::KeyId(super_key_id)));
    db.set_blob(&key_id, SubComponentType::KEY_BLOB, Some(TEST_KEY_BLOB), Some(&blob_metadata))?;

    let mut params = vec![];
    if requires_unlocked_device {
        params.push(KeyParameter::new(
            KeyParameterValue::UnlockedDeviceRequired,
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ));
    }
    if requires_authentication {
        params.push(KeyParameter::new(
            KeyParameterValue::UserSecureID(42),
            SecurityLevel::TRUSTED_ENVIRONMENT,
        ));
    }
    db.insert_keyparameter(&key_id, &params)?;

    let mut metadata = KeyMetaData::new();
    metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));
    db.insert_key_metadata(&key_id, &metadata)?;

    rebind_alias(db, &key_id, alias, domain, namespace)?;
    Ok(key_id)
}

fn make_bootlevel_test_key_entry_test_vector(key_id: i64, logical_only: bool) -> KeyEntry {
    let mut params = make_test_params(None);
    params.push(KeyParameter::new(KeyParameterValue::MaxBootLevel(3), SecurityLevel::KEYSTORE));

    let mut blob_metadata = BlobMetaData::new();
    if !logical_only {
        blob_metadata.add(BlobMetaEntry::MaxBootLevel(3));
    }
    blob_metadata.add(BlobMetaEntry::KmUuid(KEYSTORE_UUID));

    let mut metadata = KeyMetaData::new();
    metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));

    KeyEntry {
        id: key_id,
        key_blob_info: Some((TEST_KEY_BLOB.to_vec(), blob_metadata)),
        cert: Some(TEST_CERT_BLOB.to_vec()),
        cert_chain: Some(TEST_CERT_CHAIN_BLOB.to_vec()),
        km_uuid: KEYSTORE_UUID,
        parameters: params,
        metadata,
        pure_cert: false,
    }
}

fn debug_dump_keyentry_table(db: &mut KeystoreDB) -> Result<()> {
    let mut stmt = db.conn.prepare(
        "SELECT id, key_type, domain, namespace, alias, state, km_uuid FROM persistent.keyentry;",
    )?;
    let rows =
        stmt.query_map::<(i64, KeyType, i32, i64, String, KeyLifeCycle, Uuid), _, _>([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })?;

    println!("Key entry table rows:");
    for r in rows {
        let (id, key_type, domain, namespace, alias, state, km_uuid) = r.unwrap();
        println!(
            "    id: {} KeyType: {:?} Domain: {} Namespace: {} Alias: {} State: {:?} KmUuid: {:?}",
            id, key_type, domain, namespace, alias, state, km_uuid
        );
    }
    Ok(())
}

fn debug_dump_grant_table(db: &mut KeystoreDB) -> Result<()> {
    let mut stmt =
        db.conn.prepare("SELECT id, grantee, keyentryid, access_vector FROM persistent.grant;")?;
    let rows = stmt.query_map::<(i64, i64, i64, i64), _, _>([], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;

    println!("Grant table rows:");
    for r in rows {
        let (id, gt, ki, av) = r.unwrap();
        println!("    id: {} grantee: {} key_id: {} access_vector: {}", id, gt, ki, av);
    }
    Ok(())
}

// Use a custom random number generator that repeats each number once.
// This allows us to test repeated elements.

thread_local! {
    static RANDOM_COUNTER: RefCell<i64> = const { RefCell::new(0) };
}

fn reset_random() {
    RANDOM_COUNTER.with(|counter| {
        *counter.borrow_mut() = 0;
    })
}

pub fn random() -> i64 {
    RANDOM_COUNTER.with(|counter| {
        let result = *counter.borrow() / 2;
        *counter.borrow_mut() += 1;
        result
    })
}

#[test]
fn test_unbind_keys_for_user() -> Result<()> {
    let mut db = new_test_db()?;
    db.unbind_keys_for_user(1)?;

    make_test_key_entry(&mut db, Domain::APP, 210000, TEST_ALIAS, None)?;
    make_test_key_entry(&mut db, Domain::APP, 110000, TEST_ALIAS, None)?;
    db.unbind_keys_for_user(2)?;

    assert_eq!(1, db.list_past_alias(Domain::APP, 110000, KeyType::Client, None)?.len());
    assert_eq!(0, db.list_past_alias(Domain::APP, 210000, KeyType::Client, None)?.len());

    db.unbind_keys_for_user(1)?;
    assert_eq!(0, db.list_past_alias(Domain::APP, 110000, KeyType::Client, None)?.len());

    Ok(())
}

#[test]
fn test_unbind_keys_for_user_removes_superkeys() -> Result<()> {
    let mut db = new_test_db()?;
    let super_key = keystore2_crypto::generate_aes256_key()?;
    let pw: keystore2_crypto::Password = (&b"xyzabc"[..]).into();
    let (encrypted_super_key, metadata) = SuperKeyManager::encrypt_with_password(&super_key, &pw)?;

    let key_name_enc = SuperKeyType {
        alias: "test_super_key_1",
        algorithm: SuperEncryptionAlgorithm::Aes256Gcm,
        name: "test_super_key_1",
    };

    let key_name_nonenc = SuperKeyType {
        alias: "test_super_key_2",
        algorithm: SuperEncryptionAlgorithm::Aes256Gcm,
        name: "test_super_key_2",
    };

    // Install two super keys.
    db.store_super_key(1, &key_name_nonenc, &super_key, &BlobMetaData::new(), &KeyMetaData::new())?;
    db.store_super_key(1, &key_name_enc, &encrypted_super_key, &metadata, &KeyMetaData::new())?;

    // Check that both can be found in the database.
    assert!(db.load_super_key(&key_name_enc, 1)?.is_some());
    assert!(db.load_super_key(&key_name_nonenc, 1)?.is_some());

    // Install the same keys for a different user.
    db.store_super_key(2, &key_name_nonenc, &super_key, &BlobMetaData::new(), &KeyMetaData::new())?;
    db.store_super_key(2, &key_name_enc, &encrypted_super_key, &metadata, &KeyMetaData::new())?;

    // Check that the second pair of keys can be found in the database.
    assert!(db.load_super_key(&key_name_enc, 2)?.is_some());
    assert!(db.load_super_key(&key_name_nonenc, 2)?.is_some());

    // Delete all keys for user 1.
    db.unbind_keys_for_user(1)?;

    // All of user 1's keys should be gone.
    assert!(db.load_super_key(&key_name_enc, 1)?.is_none());
    assert!(db.load_super_key(&key_name_nonenc, 1)?.is_none());

    // User 2's keys should not have been touched.
    assert!(db.load_super_key(&key_name_enc, 2)?.is_some());
    assert!(db.load_super_key(&key_name_nonenc, 2)?.is_some());

    Ok(())
}

fn app_key_exists(db: &mut KeystoreDB, nspace: i64, alias: &str) -> Result<bool> {
    db.key_exists(Domain::APP, nspace, alias, KeyType::Client)
}

// Tests the unbind_auth_bound_keys_for_user() function.
#[test]
fn test_unbind_auth_bound_keys_for_user() -> Result<()> {
    let mut db = new_test_db()?;
    let user_id = 1;
    let nspace: i64 = (user_id * AID_USER_OFFSET).into();
    let other_user_id = 2;
    let other_user_nspace: i64 = (other_user_id * AID_USER_OFFSET).into();
    let super_key_type = &USER_AFTER_FIRST_UNLOCK_SUPER_KEY;

    // Create a superencryption key.
    let super_key = keystore2_crypto::generate_aes256_key()?;
    let pw: keystore2_crypto::Password = (&b"xyzabc"[..]).into();
    let (encrypted_super_key, blob_metadata) =
        SuperKeyManager::encrypt_with_password(&super_key, &pw)?;
    db.store_super_key(
        user_id,
        super_key_type,
        &encrypted_super_key,
        &blob_metadata,
        &KeyMetaData::new(),
    )?;
    let super_key_id = db.load_super_key(super_key_type, user_id)?.unwrap().0 .0;

    // Store 4 superencrypted app keys, one for each possible combination of
    // (authentication required, unlocked device required).
    make_superencrypted_key_entry(&mut db, nspace, "noauth_noud", false, false, super_key_id)?;
    make_superencrypted_key_entry(&mut db, nspace, "noauth_ud", false, true, super_key_id)?;
    make_superencrypted_key_entry(&mut db, nspace, "auth_noud", true, false, super_key_id)?;
    make_superencrypted_key_entry(&mut db, nspace, "auth_ud", true, true, super_key_id)?;
    assert!(app_key_exists(&mut db, nspace, "noauth_noud")?);
    assert!(app_key_exists(&mut db, nspace, "noauth_ud")?);
    assert!(app_key_exists(&mut db, nspace, "auth_noud")?);
    assert!(app_key_exists(&mut db, nspace, "auth_ud")?);

    // Also store a key for a different user that requires authentication.
    make_superencrypted_key_entry(&mut db, other_user_nspace, "auth_ud", true, true, super_key_id)?;

    db.unbind_auth_bound_keys_for_user(user_id)?;

    // Verify that only the user's app keys that require authentication were
    // deleted. Keys that require an unlocked device but not authentication
    // should *not* have been deleted, nor should the super key have been
    // deleted, nor should other users' keys have been deleted.
    assert!(db.load_super_key(super_key_type, user_id)?.is_some());
    assert!(app_key_exists(&mut db, nspace, "noauth_noud")?);
    assert!(app_key_exists(&mut db, nspace, "noauth_ud")?);
    assert!(!app_key_exists(&mut db, nspace, "auth_noud")?);
    assert!(!app_key_exists(&mut db, nspace, "auth_ud")?);
    assert!(app_key_exists(&mut db, other_user_nspace, "auth_ud")?);

    Ok(())
}

#[test]
fn test_store_super_key() -> Result<()> {
    let mut db = new_test_db()?;
    let pw: keystore2_crypto::Password = (&b"xyzabc"[..]).into();
    let super_key = keystore2_crypto::generate_aes256_key()?;
    let secret_bytes = b"keystore2 is great.";
    let (encrypted_secret, iv, tag) = keystore2_crypto::aes_gcm_encrypt(secret_bytes, &super_key)?;

    let (encrypted_super_key, metadata) = SuperKeyManager::encrypt_with_password(&super_key, &pw)?;
    db.store_super_key(
        1,
        &USER_AFTER_FIRST_UNLOCK_SUPER_KEY,
        &encrypted_super_key,
        &metadata,
        &KeyMetaData::new(),
    )?;

    // Check if super key exists.
    assert!(db.key_exists(
        Domain::APP,
        1,
        USER_AFTER_FIRST_UNLOCK_SUPER_KEY.alias,
        KeyType::Super
    )?);

    let (_, key_entry) = db.load_super_key(&USER_AFTER_FIRST_UNLOCK_SUPER_KEY, 1)?.unwrap();
    let loaded_super_key = SuperKeyManager::extract_super_key_from_key_entry(
        USER_AFTER_FIRST_UNLOCK_SUPER_KEY.algorithm,
        key_entry,
        &pw,
        None,
    )?;

    let decrypted_secret_bytes = loaded_super_key.decrypt(&encrypted_secret, &iv, &tag)?;
    assert_eq!(secret_bytes, &*decrypted_secret_bytes);

    Ok(())
}

fn get_valid_statsd_storage_types() -> Vec<MetricsStorage> {
    vec![
        MetricsStorage::KEY_ENTRY,
        MetricsStorage::KEY_ENTRY_ID_INDEX,
        MetricsStorage::KEY_ENTRY_DOMAIN_NAMESPACE_INDEX,
        MetricsStorage::BLOB_ENTRY,
        MetricsStorage::BLOB_ENTRY_KEY_ENTRY_ID_INDEX,
        MetricsStorage::KEY_PARAMETER,
        MetricsStorage::KEY_PARAMETER_KEY_ENTRY_ID_INDEX,
        MetricsStorage::KEY_METADATA,
        MetricsStorage::KEY_METADATA_KEY_ENTRY_ID_INDEX,
        MetricsStorage::GRANT,
        MetricsStorage::AUTH_TOKEN,
        MetricsStorage::BLOB_METADATA,
        MetricsStorage::BLOB_METADATA_BLOB_ENTRY_ID_INDEX,
    ]
}

/// Perform a simple check to ensure that we can query all the storage types
/// that are supported by the DB. Check for reasonable values.
#[test]
fn test_query_all_valid_table_sizes() -> Result<()> {
    const PAGE_SIZE: i32 = 4096;

    let mut db = new_test_db()?;

    for t in get_valid_statsd_storage_types() {
        let stat = db.get_storage_stat(t)?;
        // AuthToken can be less than a page since it's in a btree, not sqlite
        // TODO(b/187474736) stop using if-let here
        if let MetricsStorage::AUTH_TOKEN = t {
        } else {
            assert!(stat.size >= PAGE_SIZE);
        }
        assert!(stat.size >= stat.unused_size);
    }

    Ok(())
}

fn get_storage_stats_map(db: &mut KeystoreDB) -> BTreeMap<i32, StorageStats> {
    get_valid_statsd_storage_types()
        .into_iter()
        .map(|t| (t.0, db.get_storage_stat(t).unwrap()))
        .collect()
}

fn assert_storage_increased(
    db: &mut KeystoreDB,
    increased_storage_types: Vec<MetricsStorage>,
    baseline: &mut BTreeMap<i32, StorageStats>,
) {
    for storage in increased_storage_types {
        // Verify the expected storage increased.
        let new = db.get_storage_stat(storage).unwrap();
        let old = &baseline[&storage.0];
        assert!(new.size >= old.size, "{}: {} >= {}", storage.0, new.size, old.size);
        assert!(
            new.unused_size <= old.unused_size,
            "{}: {} <= {}",
            storage.0,
            new.unused_size,
            old.unused_size
        );

        // Update the baseline with the new value so that it succeeds in the
        // later comparison.
        baseline.insert(storage.0, new);
    }

    // Get an updated map of the storage and verify there were no unexpected changes.
    let updated_stats = get_storage_stats_map(db);
    assert_eq!(updated_stats.len(), baseline.len());

    for &k in baseline.keys() {
        let stringify = |map: &BTreeMap<i32, StorageStats>| -> String {
            let mut s = String::new();
            for &k in map.keys() {
                writeln!(&mut s, "  {}: {}, {}", &k, map[&k].size, map[&k].unused_size)
                    .expect("string concat failed");
            }
            s
        };

        assert!(
            updated_stats[&k].size == baseline[&k].size
                && updated_stats[&k].unused_size == baseline[&k].unused_size,
            "updated_stats:\n{}\nbaseline:\n{}",
            stringify(&updated_stats),
            stringify(baseline)
        );
    }
}

#[test]
fn test_verify_key_table_size_reporting() -> Result<()> {
    let mut db = new_test_db()?;
    let mut working_stats = get_storage_stats_map(&mut db);

    let key_id = create_key_entry(&mut db, &Domain::APP, &42, KeyType::Client, &KEYSTORE_UUID)?;
    assert_storage_increased(
        &mut db,
        vec![
            MetricsStorage::KEY_ENTRY,
            MetricsStorage::KEY_ENTRY_ID_INDEX,
            MetricsStorage::KEY_ENTRY_DOMAIN_NAMESPACE_INDEX,
        ],
        &mut working_stats,
    );

    let mut blob_metadata = BlobMetaData::new();
    blob_metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::Password));
    db.set_blob(&key_id, SubComponentType::KEY_BLOB, Some(TEST_KEY_BLOB), None)?;
    assert_storage_increased(
        &mut db,
        vec![
            MetricsStorage::BLOB_ENTRY,
            MetricsStorage::BLOB_ENTRY_KEY_ENTRY_ID_INDEX,
            MetricsStorage::BLOB_METADATA,
            MetricsStorage::BLOB_METADATA_BLOB_ENTRY_ID_INDEX,
        ],
        &mut working_stats,
    );

    let params = make_test_params(None);
    db.insert_keyparameter(&key_id, &params)?;
    assert_storage_increased(
        &mut db,
        vec![MetricsStorage::KEY_PARAMETER, MetricsStorage::KEY_PARAMETER_KEY_ENTRY_ID_INDEX],
        &mut working_stats,
    );

    let mut metadata = KeyMetaData::new();
    metadata.add(KeyMetaEntry::CreationDate(DateTime::from_millis_epoch(123456789)));
    db.insert_key_metadata(&key_id, &metadata)?;
    assert_storage_increased(
        &mut db,
        vec![MetricsStorage::KEY_METADATA, MetricsStorage::KEY_METADATA_KEY_ENTRY_ID_INDEX],
        &mut working_stats,
    );

    let mut sum = 0;
    for stat in working_stats.values() {
        sum += stat.size;
    }
    let total = db.get_storage_stat(MetricsStorage::DATABASE)?.size;
    assert!(sum <= total, "Expected sum <= total. sum: {}, total: {}", sum, total);

    Ok(())
}

#[test]
fn test_verify_auth_table_size_reporting() -> Result<()> {
    let mut db = new_test_db()?;
    let mut working_stats = get_storage_stats_map(&mut db);
    db.insert_auth_token(&HardwareAuthToken {
        challenge: 123,
        userId: 456,
        authenticatorId: 789,
        authenticatorType: kmhw_authenticator_type::ANY,
        timestamp: Timestamp { milliSeconds: 10 },
        mac: b"mac".to_vec(),
    });
    assert_storage_increased(&mut db, vec![MetricsStorage::AUTH_TOKEN], &mut working_stats);
    Ok(())
}

#[test]
fn test_verify_grant_table_size_reporting() -> Result<()> {
    const OWNER: i64 = 1;
    let mut db = new_test_db()?;
    make_test_key_entry(&mut db, Domain::APP, OWNER, TEST_ALIAS, None)?;

    let mut working_stats = get_storage_stats_map(&mut db);
    db.grant(
        &KeyDescriptor {
            domain: Domain::APP,
            nspace: 0,
            alias: Some(TEST_ALIAS.to_string()),
            blob: None,
        },
        OWNER as u32,
        123,
        key_perm_set![KeyPerm::Use],
        |_, _| Ok(()),
    )?;

    assert_storage_increased(&mut db, vec![MetricsStorage::GRANT], &mut working_stats);

    Ok(())
}

#[test]
fn find_auth_token_entry_returns_latest() -> Result<()> {
    let mut db = new_test_db()?;
    db.insert_auth_token(&HardwareAuthToken {
        challenge: 123,
        userId: 456,
        authenticatorId: 789,
        authenticatorType: kmhw_authenticator_type::ANY,
        timestamp: Timestamp { milliSeconds: 10 },
        mac: b"mac0".to_vec(),
    });
    std::thread::sleep(std::time::Duration::from_millis(1));
    db.insert_auth_token(&HardwareAuthToken {
        challenge: 123,
        userId: 457,
        authenticatorId: 789,
        authenticatorType: kmhw_authenticator_type::ANY,
        timestamp: Timestamp { milliSeconds: 12 },
        mac: b"mac1".to_vec(),
    });
    std::thread::sleep(std::time::Duration::from_millis(1));
    db.insert_auth_token(&HardwareAuthToken {
        challenge: 123,
        userId: 458,
        authenticatorId: 789,
        authenticatorType: kmhw_authenticator_type::ANY,
        timestamp: Timestamp { milliSeconds: 3 },
        mac: b"mac2".to_vec(),
    });
    // All three entries are in the database
    assert_eq!(db.perboot.auth_tokens_len(), 3);
    // It selected the most recent timestamp
    assert_eq!(db.find_auth_token_entry(|_| true).unwrap().auth_token.mac, b"mac2".to_vec());
    Ok(())
}

fn blob_count(db: &mut KeystoreDB, sc_type: SubComponentType) -> usize {
    db.with_transaction(TransactionBehavior::Deferred, |tx| {
        tx.query_row(
            "SELECT COUNT(*) FROM persistent.blobentry
                     WHERE subcomponent_type = ?;",
            params![sc_type],
            |row| row.get(0),
        )
        .context(ks_err!("Failed to count number of {sc_type:?} blobs"))
        .no_gc()
    })
    .unwrap()
}

#[test]
fn test_blobentry_gc() -> Result<()> {
    let mut db = new_test_db()?;
    let _key_id1 = make_test_key_entry(&mut db, Domain::APP, 1, "key1", None)?.0;
    let key_guard2 = make_test_key_entry(&mut db, Domain::APP, 2, "key2", None)?;
    let key_guard3 = make_test_key_entry(&mut db, Domain::APP, 3, "key3", None)?;
    let key_id4 = make_test_key_entry(&mut db, Domain::APP, 4, "key4", None)?.0;
    let key_id5 = make_test_key_entry(&mut db, Domain::APP, 5, "key5", None)?.0;

    assert_eq!(5, blob_count(&mut db, SubComponentType::KEY_BLOB));
    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));

    // Replace the keyblobs for keys 2 and 3.  The previous blobs will still exist.
    db.set_blob(&key_guard2, SubComponentType::KEY_BLOB, Some(&[1, 2, 3]), None)?;
    db.set_blob(&key_guard3, SubComponentType::KEY_BLOB, Some(&[1, 2, 3]), None)?;

    assert_eq!(7, blob_count(&mut db, SubComponentType::KEY_BLOB));
    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));

    // Delete keys 4 and 5.  The keyblobs aren't removed yet.
    db.with_transaction(Immediate("TX_delete_test_keys"), |tx| {
        KeystoreDB::mark_unreferenced(tx, key_id4)?;
        KeystoreDB::mark_unreferenced(tx, key_id5)?;
        Ok(()).no_gc()
    })
    .unwrap();

    assert_eq!(7, blob_count(&mut db, SubComponentType::KEY_BLOB));
    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));

    // First garbage collection should return all 4 blobentry rows that are no longer current for
    // their key.
    let superseded = db.handle_next_superseded_blobs(&[], 20).unwrap();
    let superseded_ids: Vec<i64> = superseded.iter().map(|v| v.blob_id).collect();
    assert_eq!(4, superseded.len());
    assert_eq!(7, blob_count(&mut db, SubComponentType::KEY_BLOB));
    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));

    // Feed the superseded blob IDs back in, to trigger removal of the old KEY_BLOB entries.  As no
    // new superseded KEY_BLOBs are found, the unreferenced CERT/CERT_CHAIN blobs are removed.
    let superseded = db.handle_next_superseded_blobs(&superseded_ids, 20).unwrap();
    let superseded_ids: Vec<i64> = superseded.iter().map(|v| v.blob_id).collect();
    assert_eq!(0, superseded.len());
    assert_eq!(3, blob_count(&mut db, SubComponentType::KEY_BLOB));
    assert_eq!(3, blob_count(&mut db, SubComponentType::CERT));
    assert_eq!(3, blob_count(&mut db, SubComponentType::CERT_CHAIN));

    // Nothing left to garbage collect.
    let superseded = db.handle_next_superseded_blobs(&superseded_ids, 20).unwrap();
    assert_eq!(0, superseded.len());
    assert_eq!(3, blob_count(&mut db, SubComponentType::KEY_BLOB));
    assert_eq!(3, blob_count(&mut db, SubComponentType::CERT));
    assert_eq!(3, blob_count(&mut db, SubComponentType::CERT_CHAIN));

    Ok(())
}

#[test]
fn test_load_key_descriptor() -> Result<()> {
    let mut db = new_test_db()?;
    let key_id = make_test_key_entry(&mut db, Domain::APP, 1, TEST_ALIAS, None)?.0;

    let key = db.load_key_descriptor(key_id)?.unwrap();

    assert_eq!(key.domain, Domain::APP);
    assert_eq!(key.nspace, 1);
    assert_eq!(key.alias, Some(TEST_ALIAS.to_string()));

    // No such id
    assert_eq!(db.load_key_descriptor(key_id + 1)?, None);
    Ok(())
}

#[test]
fn test_get_list_app_uids_for_sid() -> Result<()> {
    let uid: i32 = 1;
    let uid_offset: i64 = (uid as i64) * (AID_USER_OFFSET as i64);
    let first_sid = 667;
    let second_sid = 669;
    let first_app_id: i64 = 123 + uid_offset;
    let second_app_id: i64 = 456 + uid_offset;
    let third_app_id: i64 = 789 + uid_offset;
    let unrelated_app_id: i64 = 1011 + uid_offset;
    let mut db = new_test_db()?;
    make_test_key_entry_with_sids(
        &mut db,
        Domain::APP,
        first_app_id,
        TEST_ALIAS,
        None,
        &[first_sid],
    )
    .context("test_get_list_app_uids_for_sid")?;
    make_test_key_entry_with_sids(
        &mut db,
        Domain::APP,
        second_app_id,
        "alias2",
        None,
        &[first_sid],
    )
    .context("test_get_list_app_uids_for_sid")?;
    make_test_key_entry_with_sids(
        &mut db,
        Domain::APP,
        second_app_id,
        TEST_ALIAS,
        None,
        &[second_sid],
    )
    .context("test_get_list_app_uids_for_sid")?;
    make_test_key_entry_with_sids(
        &mut db,
        Domain::APP,
        third_app_id,
        "alias3",
        None,
        &[second_sid],
    )
    .context("test_get_list_app_uids_for_sid")?;
    make_test_key_entry_with_sids(&mut db, Domain::APP, unrelated_app_id, TEST_ALIAS, None, &[])
        .context("test_get_list_app_uids_for_sid")?;

    let mut first_sid_apps = db.get_app_uids_affected_by_sid(uid, first_sid)?;
    first_sid_apps.sort();
    assert_eq!(first_sid_apps, vec![first_app_id, second_app_id]);
    let mut second_sid_apps = db.get_app_uids_affected_by_sid(uid, second_sid)?;
    second_sid_apps.sort();
    assert_eq!(second_sid_apps, vec![second_app_id, third_app_id]);
    Ok(())
}

#[test]
fn test_get_list_app_uids_with_multiple_sids() -> Result<()> {
    let uid: i32 = 1;
    let uid_offset: i64 = (uid as i64) * (AID_USER_OFFSET as i64);
    let first_sid = 667;
    let second_sid = 669;
    let third_sid = 772;
    let first_app_id: i64 = 123 + uid_offset;
    let second_app_id: i64 = 456 + uid_offset;
    let mut db = new_test_db()?;
    make_test_key_entry_with_sids(
        &mut db,
        Domain::APP,
        first_app_id,
        TEST_ALIAS,
        None,
        &[first_sid, second_sid],
    )
    .context("test_get_list_app_uids_for_sid")?;
    make_test_key_entry_with_sids(
        &mut db,
        Domain::APP,
        second_app_id,
        "alias2",
        None,
        &[second_sid, third_sid],
    )
    .context("test_get_list_app_uids_for_sid")?;

    let first_sid_apps = db.get_app_uids_affected_by_sid(uid, first_sid)?;
    assert_eq!(first_sid_apps, vec![first_app_id]);

    let mut second_sid_apps = db.get_app_uids_affected_by_sid(uid, second_sid)?;
    second_sid_apps.sort();
    assert_eq!(second_sid_apps, vec![first_app_id, second_app_id]);

    let third_sid_apps = db.get_app_uids_affected_by_sid(uid, third_sid)?;
    assert_eq!(third_sid_apps, vec![second_app_id]);
    Ok(())
}

// Starting from `next_keyid`, add keys to the database until the count reaches
// `key_count`.  (`next_keyid` is assumed to indicate how many rows already exist.)
fn db_populate_keys(db: &mut KeystoreDB, next_keyid: usize, key_count: usize) {
    db.with_transaction(Immediate("test_keyentry"), |tx| {
        for next_keyid in next_keyid..key_count {
            tx.execute(
                "INSERT into persistent.keyentry
                        (id, key_type, domain, namespace, alias, state, km_uuid)
                        VALUES(?, ?, ?, ?, ?, ?, ?);",
                params![
                    next_keyid,
                    KeyType::Client,
                    Domain::APP.0 as u32,
                    10001,
                    &format!("alias-{next_keyid}"),
                    KeyLifeCycle::Live,
                    KEYSTORE_UUID,
                ],
            )?;
            tx.execute(
                "INSERT INTO persistent.blobentry
                         (subcomponent_type, keyentryid, blob) VALUES (?, ?, ?);",
                params![SubComponentType::KEY_BLOB, next_keyid, TEST_KEY_BLOB],
            )?;
            tx.execute(
                "INSERT INTO persistent.blobentry
                         (subcomponent_type, keyentryid, blob) VALUES (?, ?, ?);",
                params![SubComponentType::CERT, next_keyid, TEST_CERT_BLOB],
            )?;
            tx.execute(
                "INSERT INTO persistent.blobentry
                         (subcomponent_type, keyentryid, blob) VALUES (?, ?, ?);",
                params![SubComponentType::CERT_CHAIN, next_keyid, TEST_CERT_CHAIN_BLOB],
            )?;
        }
        Ok(()).no_gc()
    })
    .unwrap()
}

/// Run the provided `test_fn` against the database at various increasing stages of
/// database population.
fn run_with_many_keys<F, T>(max_count: usize, test_fn: F) -> Result<()>
where
    F: Fn(&mut KeystoreDB) -> T,
{
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keystore2_test")
            .with_max_level(log::LevelFilter::Debug),
    );
    // Put the test database on disk for a more realistic result.
    let db_root = tempfile::Builder::new().prefix("ks2db-test-").tempdir().unwrap();
    let mut db_path = db_root.path().to_owned();
    db_path.push("ks2-test.sqlite");
    let mut db = new_test_db_at(&db_path.to_string_lossy())?;

    println!("\nNumber_of_keys,time_in_s");
    let mut key_count = 10;
    let mut next_keyid = 0;
    while key_count < max_count {
        db_populate_keys(&mut db, next_keyid, key_count);
        assert_eq!(db_key_count(&mut db), key_count);

        let start = std::time::Instant::now();
        let _result = test_fn(&mut db);
        println!("{key_count}, {}", start.elapsed().as_secs_f64());

        next_keyid = key_count;
        key_count *= 2;
    }

    Ok(())
}

fn db_key_count(db: &mut KeystoreDB) -> usize {
    db.with_transaction(TransactionBehavior::Deferred, |tx| {
        tx.query_row(
            "SELECT COUNT(*) FROM persistent.keyentry
                         WHERE domain = ? AND state = ? AND key_type = ?;",
            params![Domain::APP.0 as u32, KeyLifeCycle::Live, KeyType::Client],
            |row| row.get::<usize, usize>(0),
        )
        .context(ks_err!("Failed to count number of keys."))
        .no_gc()
    })
    .unwrap()
}

#[test]
fn test_handle_superseded_with_many_keys() -> Result<()> {
    run_with_many_keys(1_000_000, |db| db.handle_next_superseded_blobs(&[], 20))
}

#[test]
fn test_get_storage_stats_with_many_keys() -> Result<()> {
    use android_security_metrics::aidl::android::security::metrics::Storage::Storage as MetricsStorage;
    run_with_many_keys(1_000_000, |db| {
        db.get_storage_stat(MetricsStorage::DATABASE).unwrap();
        db.get_storage_stat(MetricsStorage::KEY_ENTRY).unwrap();
        db.get_storage_stat(MetricsStorage::KEY_ENTRY_ID_INDEX).unwrap();
        db.get_storage_stat(MetricsStorage::KEY_ENTRY_DOMAIN_NAMESPACE_INDEX).unwrap();
        db.get_storage_stat(MetricsStorage::BLOB_ENTRY).unwrap();
        db.get_storage_stat(MetricsStorage::BLOB_ENTRY_KEY_ENTRY_ID_INDEX).unwrap();
        db.get_storage_stat(MetricsStorage::KEY_PARAMETER).unwrap();
        db.get_storage_stat(MetricsStorage::KEY_PARAMETER_KEY_ENTRY_ID_INDEX).unwrap();
        db.get_storage_stat(MetricsStorage::KEY_METADATA).unwrap();
        db.get_storage_stat(MetricsStorage::KEY_METADATA_KEY_ENTRY_ID_INDEX).unwrap();
        db.get_storage_stat(MetricsStorage::GRANT).unwrap();
        db.get_storage_stat(MetricsStorage::AUTH_TOKEN).unwrap();
        db.get_storage_stat(MetricsStorage::BLOB_METADATA).unwrap();
        db.get_storage_stat(MetricsStorage::BLOB_METADATA_BLOB_ENTRY_ID_INDEX).unwrap();
    })
}

#[test]
fn test_list_keys_with_many_keys() -> Result<()> {
    run_with_many_keys(1_000_000, |db: &mut KeystoreDB| -> Result<()> {
        // Behave equivalently to how clients list aliases.
        let domain = Domain::APP;
        let namespace = 10001;
        let mut start_past: Option<String> = None;
        let mut count = 0;
        let mut batches = 0;
        loop {
            let keys = db
                .list_past_alias(domain, namespace, KeyType::Client, start_past.as_deref())
                .unwrap();
            let batch_size = crate::utils::estimate_safe_amount_to_return(
                domain,
                namespace,
                &keys,
                crate::utils::RESPONSE_SIZE_LIMIT,
            );
            let batch = &keys[..batch_size];
            count += batch.len();
            match batch.last() {
                Some(key) => start_past.clone_from(&key.alias),
                None => {
                    log::info!("got {count} keys in {batches} non-empty batches");
                    return Ok(());
                }
            }
            batches += 1;
        }
    })
}
