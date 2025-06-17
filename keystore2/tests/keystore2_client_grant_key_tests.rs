// Copyright 2022, The Android Open Source Project
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

use crate::keystore2_client_test_utils::{
    generate_ec_key_and_grant_to_users, perform_sample_sign_operation,
};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Digest::Digest, KeyPurpose::KeyPurpose,
};
use android_security_maintenance::aidl::android::security::maintenance::IKeystoreMaintenance::IKeystoreMaintenance;
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
    KeyEntryResponse::KeyEntryResponse, KeyPermission::KeyPermission, ResponseCode::ResponseCode,
};
use keystore2_test_utils::{
    authorizations, get_keystore_service, key_generations,
    key_generations::{map_ks_error, Error},
    run_as, SecLevel,
};
use nix::unistd::getuid;
use rustutils::users::AID_USER_OFFSET;

static USER_MANAGER_SERVICE_NAME: &str = "android.security.maintenance";

/// Produce a [`KeyDescriptor`] for a granted key.
fn granted_key_descriptor(nspace: i64) -> KeyDescriptor {
    KeyDescriptor { domain: Domain::GRANT, nspace, alias: None, blob: None }
}

fn get_granted_key(
    ks2: &binder::Strong<dyn IKeystoreService>,
    nspace: i64,
) -> Result<KeyEntryResponse, Error> {
    map_ks_error(ks2.getKeyEntry(&granted_key_descriptor(nspace)))
}

/// Generate an EC signing key in the SELINUX domain and grant it to the user with given access
/// vector.
fn generate_and_grant_selinux_key(
    grantee_uid: u32,
    access_vector: i32,
) -> Result<KeyDescriptor, Error> {
    let sl = SecLevel::tee();
    let alias = format!("{}{}", "ks_grant_test_key_1", getuid());

    let key_metadata = key_generations::generate_ec_p256_signing_key(
        &sl,
        Domain::SELINUX,
        key_generations::SELINUX_SHELL_NAMESPACE,
        Some(alias),
        None,
    )
    .unwrap();

    map_ks_error(sl.keystore2.grant(
        &key_metadata.key,
        grantee_uid.try_into().unwrap(),
        access_vector,
    ))
}

/// Use a granted key to perform a signing operation.
fn sign_with_granted_key(grant_key_nspace: i64) -> Result<(), Error> {
    let sl = SecLevel::tee();
    let key_entry_response = get_granted_key(&sl.keystore2, grant_key_nspace)?;

    // Perform sample crypto operation using granted key.
    let op_response = map_ks_error(sl.binder.createOperation(
        &key_entry_response.metadata.key,
        &authorizations::AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256),
        false,
    ))?;

    assert!(op_response.iOperation.is_some());
    assert_eq!(
        Ok(()),
        map_ks_error(perform_sample_sign_operation(&op_response.iOperation.unwrap()))
    );

    Ok(())
}

fn get_maintenance() -> binder::Strong<dyn IKeystoreMaintenance> {
    binder::get_interface(USER_MANAGER_SERVICE_NAME).unwrap()
}

/// Try to grant an SELINUX key with permission that does not map to any of the `KeyPermission`
/// values.  An error is expected with values that does not map to set of permissions listed in
/// `KeyPermission`.
#[test]
fn grant_selinux_key_with_invalid_perm() {
    const USER_ID: u32 = 99;
    const APPLICATION_ID: u32 = 10001;
    let grantee_uid = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    let invalid_access_vector = KeyPermission::CONVERT_STORAGE_KEY_TO_EPHEMERAL.0 << 19;

    let result = generate_and_grant_selinux_key(grantee_uid, invalid_access_vector);
    assert!(result.is_err());
    assert_eq!(Error::Rc(ResponseCode::SYSTEM_ERROR), result.unwrap_err());
}

/// Try to grant an SELINUX key with empty access vector `KeyPermission::NONE`, should be able to
/// grant a key with empty access vector successfully. In grantee context try to use the granted
/// key, it should fail to load the key with permission denied error.
#[test]
fn grant_selinux_key_with_perm_none() {
    const USER_ID: u32 = 99;
    const APPLICATION_ID: u32 = 10001;
    static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    static GRANTEE_GID: u32 = GRANTEE_UID;

    let grantor_fn = || {
        let empty_access_vector = KeyPermission::NONE.0;

        let grant_key = generate_and_grant_selinux_key(GRANTEE_UID, empty_access_vector).unwrap();

        assert_eq!(grant_key.domain, Domain::GRANT);

        grant_key.nspace
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };

    // In grantee context try to load the key, it should fail to load the granted key as it is
    // granted with empty access vector.
    let grantee_fn = move || {
        let keystore2 = get_keystore_service();

        let result = get_granted_key(&keystore2, grant_key_nspace);
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
}

/// Grant an SELINUX key to the user (grantee) with `GET_INFO|USE` key permissions. Verify whether
/// grantee can succeed in loading the granted key and try to perform simple operation using this
/// granted key. Grantee should be able to load the key and use the key to perform crypto operation
/// successfully. Try to delete the granted key in grantee context where it is expected to fail to
/// delete it as `DELETE` permission is not granted.
#[test]
fn grant_selinux_key_get_info_use_perms() {
    const USER_ID: u32 = 99;
    const APPLICATION_ID: u32 = 10001;
    static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    static GRANTEE_GID: u32 = GRANTEE_UID;

    // Generate a key and grant it to a user with GET_INFO|USE key permissions.
    let grantor_fn = || {
        let access_vector = KeyPermission::GET_INFO.0 | KeyPermission::USE.0;
        let grant_key = generate_and_grant_selinux_key(GRANTEE_UID, access_vector).unwrap();

        assert_eq!(grant_key.domain, Domain::GRANT);

        grant_key.nspace
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };

    // In grantee context load the key and try to perform crypto operation.
    let grantee_fn = move || {
        let sl = SecLevel::tee();

        // Load the granted key.
        let key_entry_response = get_granted_key(&sl.keystore2, grant_key_nspace).unwrap();

        // Perform sample crypto operation using granted key.
        let op_response = sl
            .binder
            .createOperation(
                &key_entry_response.metadata.key,
                &authorizations::AuthSetBuilder::new()
                    .purpose(KeyPurpose::SIGN)
                    .digest(Digest::SHA_2_256),
                false,
            )
            .unwrap();
        assert!(op_response.iOperation.is_some());
        assert_eq!(
            Ok(()),
            map_ks_error(perform_sample_sign_operation(&op_response.iOperation.unwrap()))
        );

        // Try to delete the key, it is expected to be fail with permission denied error.
        let result =
            map_ks_error(sl.keystore2.deleteKey(&granted_key_descriptor(grant_key_nspace)));
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
}

/// Grant an SELINUX key to the user (grantee) with just `GET_INFO` key permissions. Verify whether
/// grantee can succeed in loading the granted key and try to perform simple operation using this
/// granted key.
#[test]
fn grant_selinux_key_get_info_only() {
    const USER_ID: u32 = 99;
    const APPLICATION_ID: u32 = 10001;
    static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    static GRANTEE_GID: u32 = GRANTEE_UID;

    // Generate a key and grant it to a user with (just) GET_INFO key permissions.
    let grantor_fn = || {
        let access_vector = KeyPermission::GET_INFO.0;
        let grant_key = generate_and_grant_selinux_key(GRANTEE_UID, access_vector).unwrap();

        assert_eq!(grant_key.domain, Domain::GRANT);

        grant_key.nspace
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };

    // In grantee context load the key and try to perform crypto operation.
    let grantee_fn = move || {
        let sl = SecLevel::tee();

        // Load the granted key.
        let key_entry_response = get_granted_key(&sl.keystore2, grant_key_nspace)
            .expect("failed to get info for granted key");

        // Attempt to perform sample crypto operation using granted key, now identified by <KEY_ID,
        // key_id>.
        let result = map_ks_error(
            sl.binder.createOperation(
                &key_entry_response.metadata.key,
                &authorizations::AuthSetBuilder::new()
                    .purpose(KeyPurpose::SIGN)
                    .digest(Digest::SHA_2_256),
                false,
            ),
        );
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());

        // Try to delete the key using a <GRANT, grant_id> descriptor.
        let result =
            map_ks_error(sl.keystore2.deleteKey(&granted_key_descriptor(grant_key_nspace)));
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());

        // Try to delete the key using a <KEY_ID, key_id> descriptor.
        let result = map_ks_error(sl.keystore2.deleteKey(&key_entry_response.metadata.key));
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
}

/// Grant an APP key to the user (grantee) with just `GET_INFO` key permissions. Verify whether
/// grantee can succeed in loading the granted key and try to perform simple operation using this
/// granted key.
#[test]
fn grant_app_key_get_info_only() {
    const USER_ID: u32 = 99;
    const APPLICATION_ID: u32 = 10001;
    static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    static GRANTEE_GID: u32 = GRANTEE_UID;
    static ALIAS: &str = "ks_grant_key_info_only";

    // Generate a key and grant it to a user with (just) GET_INFO key permissions.
    let grantor_fn = || {
        let sl = SecLevel::tee();
        let access_vector = KeyPermission::GET_INFO.0;
        let mut grant_keys = generate_ec_key_and_grant_to_users(
            &sl,
            Some(ALIAS.to_string()),
            vec![GRANTEE_UID.try_into().unwrap()],
            access_vector,
        )
        .unwrap();

        grant_keys.remove(0)
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };

    // In grantee context load the key and try to perform crypto operation.
    let grantee_fn = move || {
        let sl = SecLevel::tee();

        // Load the granted key.
        let key_entry_response = get_granted_key(&sl.keystore2, grant_key_nspace)
            .expect("failed to get info for granted key");

        // Attempt to perform sample crypto operation using granted key, now identified by <KEY_ID,
        // key_id>.
        let result = map_ks_error(
            sl.binder.createOperation(
                &key_entry_response.metadata.key,
                &authorizations::AuthSetBuilder::new()
                    .purpose(KeyPurpose::SIGN)
                    .digest(Digest::SHA_2_256),
                false,
            ),
        );
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());

        // Try to delete the key using a <GRANT, grant_id> descriptor.
        let result =
            map_ks_error(sl.keystore2.deleteKey(&granted_key_descriptor(grant_key_nspace)));
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());

        // Try to delete the key using a <KEY_ID, key_id> descriptor.
        let result = map_ks_error(sl.keystore2.deleteKey(&key_entry_response.metadata.key));
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
}

/// Grant an APP key to the user with DELETE access. In grantee context load the key and delete it.
/// Verify that grantee should succeed in deleting the granted key and in grantor context test
/// should fail to find the key with error response `KEY_NOT_FOUND`.
#[test]
fn grant_app_key_delete_success() {
    const USER_ID: u32 = 99;
    const APPLICATION_ID: u32 = 10001;
    static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    static GRANTEE_GID: u32 = GRANTEE_UID;
    static ALIAS: &str = "ks_grant_key_delete_success";

    // Generate a key and grant it to a user with DELETE permission.
    let grantor_fn = || {
        let sl = SecLevel::tee();
        let access_vector = KeyPermission::DELETE.0;
        let mut grant_keys = generate_ec_key_and_grant_to_users(
            &sl,
            Some(ALIAS.to_string()),
            vec![GRANTEE_UID.try_into().unwrap()],
            access_vector,
        )
        .unwrap();

        grant_keys.remove(0)
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };

    // Grantee context, delete the key.
    let grantee_fn = move || {
        let keystore2 = get_keystore_service();
        keystore2.deleteKey(&granted_key_descriptor(grant_key_nspace)).unwrap();
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };

    // Verify whether key got deleted in grantor's context.
    let grantor_fn = move || {
        let keystore2_inst = get_keystore_service();
        let result = map_ks_error(keystore2_inst.getKeyEntry(&KeyDescriptor {
            domain: Domain::APP,
            nspace: -1,
            alias: Some(ALIAS.to_string()),
            blob: None,
        }));
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    unsafe { run_as::run_as_root(grantor_fn) };
}

/// Grant an APP key to the user. In grantee context load the granted key and try to grant it to
/// second user. Test should fail with a response code `PERMISSION_DENIED` to grant a key to second
/// user from grantee context. Test should make sure second grantee should not have a access to
/// granted key.
#[test]
fn grant_granted_app_key_fails() {
    const GRANTOR_USER_ID: u32 = 97;
    const GRANTOR_APPLICATION_ID: u32 = 10003;
    static GRANTOR_UID: u32 = GRANTOR_USER_ID * AID_USER_OFFSET + GRANTOR_APPLICATION_ID;
    static GRANTOR_GID: u32 = GRANTOR_UID;

    const USER_ID: u32 = 99;
    const APPLICATION_ID: u32 = 10001;
    static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    static GRANTEE_GID: u32 = GRANTEE_UID;

    const SEC_USER_ID: u32 = 98;
    const SEC_APPLICATION_ID: u32 = 10001;
    static SEC_GRANTEE_UID: u32 = SEC_USER_ID * AID_USER_OFFSET + SEC_APPLICATION_ID;
    static SEC_GRANTEE_GID: u32 = SEC_GRANTEE_UID;

    // Generate a key and grant it to a user with GET_INFO permission.
    let grantor_fn = || {
        let sl = SecLevel::tee();
        let access_vector = KeyPermission::GET_INFO.0;
        let alias = format!("ks_grant_perm_denied_key_{}", getuid());
        let mut grant_keys = generate_ec_key_and_grant_to_users(
            &sl,
            Some(alias),
            vec![GRANTEE_UID.try_into().unwrap()],
            access_vector,
        )
        .unwrap();

        grant_keys.remove(0)
    };
    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    let grant_key_nspace = unsafe { run_as::run_as_app(GRANTOR_UID, GRANTOR_GID, grantor_fn) };

    // Grantee context, load the granted key and try to grant it to `SEC_GRANTEE_UID` grantee.
    let grantee_fn = move || {
        let keystore2 = get_keystore_service();
        let access_vector = KeyPermission::GET_INFO.0;

        // Try to grant when identifying the key with <GRANT, grant_nspace>.
        let result = map_ks_error(keystore2.grant(
            &granted_key_descriptor(grant_key_nspace),
            SEC_GRANTEE_UID.try_into().unwrap(),
            access_vector,
        ));
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::SYSTEM_ERROR), result.unwrap_err());

        // Load the key info and try to grant when identifying the key with <KEY_ID, keyid>.
        let key_entry_response = get_granted_key(&keystore2, grant_key_nspace).unwrap();
        let result = map_ks_error(keystore2.grant(
            &key_entry_response.metadata.key,
            SEC_GRANTEE_UID.try_into().unwrap(),
            access_vector,
        ));
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };

    // Make sure second grantee shouldn't have access to the above granted key.
    let grantee2_fn = move || {
        let keystore2 = get_keystore_service();
        let result = get_granted_key(&keystore2, grant_key_nspace);
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    unsafe { run_as::run_as_app(SEC_GRANTEE_UID, SEC_GRANTEE_GID, grantee2_fn) };
}

/// Grant an APP key to one user, from a normal user. Check that grantee context can load the
/// granted key, but that a second unrelated context cannot.
#[test]
fn grant_app_key_only_to_grantee() {
    const GRANTOR_USER_ID: u32 = 97;
    const GRANTOR_APPLICATION_ID: u32 = 10003;
    static GRANTOR_UID: u32 = GRANTOR_USER_ID * AID_USER_OFFSET + GRANTOR_APPLICATION_ID;
    static GRANTOR_GID: u32 = GRANTOR_UID;

    const USER_ID: u32 = 99;
    const APPLICATION_ID: u32 = 10001;
    static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    static GRANTEE_GID: u32 = GRANTEE_UID;

    const SEC_USER_ID: u32 = 98;
    const SEC_APPLICATION_ID: u32 = 10001;
    static SEC_GRANTEE_UID: u32 = SEC_USER_ID * AID_USER_OFFSET + SEC_APPLICATION_ID;
    static SEC_GRANTEE_GID: u32 = SEC_GRANTEE_UID;

    // Child function to generate a key and grant it to a user with `GET_INFO` permission.
    let grantor_fn = || {
        let sl = SecLevel::tee();
        let access_vector = KeyPermission::GET_INFO.0;
        let alias = format!("ks_grant_single_{}", getuid());
        let mut grant_keys = generate_ec_key_and_grant_to_users(
            &sl,
            Some(alias),
            vec![GRANTEE_UID.try_into().unwrap()],
            access_vector,
        )
        .unwrap();

        grant_keys.remove(0)
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    let grant_key_nspace = unsafe { run_as::run_as_app(GRANTOR_UID, GRANTOR_GID, grantor_fn) };

    // Child function for the grantee context: can load the granted key.
    let grantee_fn = move || {
        let keystore2 = get_keystore_service();
        let rsp = get_granted_key(&keystore2, grant_key_nspace).expect("failed to get granted key");

        // Return the underlying key ID to simulate an ID leak.
        assert_eq!(rsp.metadata.key.domain, Domain::KEY_ID);
        rsp.metadata.key.nspace
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    let key_id = unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };

    // Second context does not have access to the above granted key, because it's identified
    // by <uid, grant_nspace> and the implicit uid value is different.  Also, even if the
    // second context gets hold of the key ID somehow, that also doesn't work.
    let non_grantee_fn = move || {
        let keystore2 = get_keystore_service();
        let result = get_granted_key(&keystore2, grant_key_nspace);
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());

        let result = map_ks_error(keystore2.getKeyEntry(&KeyDescriptor {
            domain: Domain::KEY_ID,
            nspace: key_id,
            alias: None,
            blob: None,
        }));
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    unsafe { run_as::run_as_app(SEC_GRANTEE_UID, SEC_GRANTEE_GID, non_grantee_fn) };
}

/// Try to grant an APP key with `GRANT` access. Keystore2 system shouldn't allow to grant a key
/// with `GRANT` access. Test should fail to grant a key with `PERMISSION_DENIED` error response
/// code.
#[test]
fn grant_app_key_with_grant_perm_fails() {
    let sl = SecLevel::tee();
    let access_vector = KeyPermission::GRANT.0;
    let alias = format!("ks_grant_access_vec_key_{}", getuid());
    let user_id = 98;
    let application_id = 10001;
    let grantee_uid = user_id * AID_USER_OFFSET + application_id;

    let result = map_ks_error(generate_ec_key_and_grant_to_users(
        &sl,
        Some(alias),
        vec![grantee_uid.try_into().unwrap()],
        access_vector,
    ));
    assert!(result.is_err());
    assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
}

/// Try to grant a non-existing SELINUX key to the user. Test should fail with `KEY_NOT_FOUND` error
/// response.
#[test]
fn grant_fails_with_non_existing_selinux_key() {
    let keystore2 = get_keystore_service();
    let alias = format!("ks_grant_test_non_existing_key_5_{}", getuid());
    let user_id = 98;
    let application_id = 10001;
    let grantee_uid = user_id * AID_USER_OFFSET + application_id;
    let access_vector = KeyPermission::GET_INFO.0;

    let result = map_ks_error(keystore2.grant(
        &KeyDescriptor {
            domain: Domain::SELINUX,
            nspace: key_generations::SELINUX_SHELL_NAMESPACE,
            alias: Some(alias),
            blob: None,
        },
        grantee_uid.try_into().unwrap(),
        access_vector,
    ));
    assert!(result.is_err());
    assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
}

/// Grant a key to a UID (user ID A + app B) then uninstall user ID A. Initialize a new user with
/// the same user ID as the now-removed user. Check that app B for the new user can't load the key.
#[test]
fn grant_removed_when_grantee_user_id_removed() {
    const GRANTOR_USER_ID: u32 = 97;
    const GRANTOR_APPLICATION_ID: u32 = 10003;
    static GRANTOR_UID: u32 = GRANTOR_USER_ID * AID_USER_OFFSET + GRANTOR_APPLICATION_ID;
    static GRANTOR_GID: u32 = GRANTOR_UID;

    const GRANTEE_USER_ID: u32 = 99;
    const GRANTEE_APPLICATION_ID: u32 = 10001;
    static GRANTEE_UID: u32 = GRANTEE_USER_ID * AID_USER_OFFSET + GRANTEE_APPLICATION_ID;
    static GRANTEE_GID: u32 = GRANTEE_UID;

    // Add a new user.
    let create_grantee_user_id_fn = || {
        let maint = get_maintenance();
        maint.onUserAdded(GRANTEE_USER_ID.try_into().unwrap()).expect("failed to add user");
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    unsafe { run_as::run_as_root(create_grantee_user_id_fn) };

    // Child function to generate a key and grant it to GRANTEE_UID with `GET_INFO` permission.
    let grantor_fn = || {
        let sl = SecLevel::tee();
        let access_vector = KeyPermission::GET_INFO.0;
        let alias = format!("ks_grant_single_{}", getuid());
        let mut grant_keys = generate_ec_key_and_grant_to_users(
            &sl,
            Some(alias),
            vec![GRANTEE_UID.try_into().unwrap()],
            access_vector,
        )
        .unwrap();

        grant_keys.remove(0)
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    let grant_key_nspace = unsafe { run_as::run_as_app(GRANTOR_UID, GRANTOR_GID, grantor_fn) };

    // Child function for the grantee context: can load the granted key.
    let grantee_fn = move || {
        let keystore2 = get_keystore_service();
        let rsp = get_granted_key(&keystore2, grant_key_nspace).expect("failed to get granted key");

        // Return the underlying key ID to simulate an ID leak.
        assert_eq!(rsp.metadata.key.domain, Domain::KEY_ID);
        rsp.metadata.key.nspace
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    let key_id = unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };

    // Remove the grantee user and create a new user with the same user ID.
    let overwrite_grantee_user_id_fn = || {
        let maint = get_maintenance();
        maint.onUserRemoved(GRANTEE_USER_ID.try_into().unwrap()).expect("failed to remove user");
        maint.onUserAdded(GRANTEE_USER_ID.try_into().unwrap()).expect("failed to add user");
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    unsafe { run_as::run_as_root(overwrite_grantee_user_id_fn) };

    // Second context identified by <uid, grant_nspace> (where uid is the same because the
    // now-deleted and newly-created grantee users have the same user ID) does not have access to
    // the above granted key.
    let new_grantee_fn = move || {
        // Check that the key cannot be accessed via grant (i.e. KeyDescriptor with Domain::GRANT).
        let keystore2 = get_keystore_service();
        let result = get_granted_key(&keystore2, grant_key_nspace);
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());

        // Check that the key also cannot be accessed via key ID (i.e. KeyDescriptor with
        // Domain::KEY_ID) if the second context somehow gets a hold of it.
        let result = map_ks_error(keystore2.getKeyEntry(&KeyDescriptor {
            domain: Domain::KEY_ID,
            nspace: key_id,
            alias: None,
            blob: None,
        }));
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, new_grantee_fn) };

    // Clean up: remove grantee user.
    let remove_grantee_user_id_fn = || {
        let maint = get_maintenance();
        maint.onUserRemoved(GRANTEE_USER_ID.try_into().unwrap()).expect("failed to remove user");
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    unsafe { run_as::run_as_root(remove_grantee_user_id_fn) };
}

/// Grant a key to a UID (user ID A + app B) then clear the namespace for user ID A + app B. Check
/// that the key can't be loaded by that UID (which would be the UID used if another app were to be
/// installed for user ID A with the same application ID B).
#[test]
fn grant_removed_when_grantee_app_uninstalled() {
    const GRANTOR_USER_ID: u32 = 97;
    const GRANTOR_APPLICATION_ID: u32 = 10003;
    static GRANTOR_UID: u32 = GRANTOR_USER_ID * AID_USER_OFFSET + GRANTOR_APPLICATION_ID;
    static GRANTOR_GID: u32 = GRANTOR_UID;

    const GRANTEE_USER_ID: u32 = 99;
    const GRANTEE_APPLICATION_ID: u32 = 10001;
    static GRANTEE_UID: u32 = GRANTEE_USER_ID * AID_USER_OFFSET + GRANTEE_APPLICATION_ID;
    static GRANTEE_GID: u32 = GRANTEE_UID;

    // Add a new user.
    let create_grantee_user_id_fn = || {
        let maint = get_maintenance();
        maint.onUserAdded(GRANTEE_USER_ID.try_into().unwrap()).expect("failed to add user");
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    unsafe { run_as::run_as_root(create_grantee_user_id_fn) };

    // Child function to generate a key and grant it to GRANTEE_UID with `GET_INFO` permission.
    let grantor_fn = || {
        let sl = SecLevel::tee();
        let access_vector = KeyPermission::GET_INFO.0;
        let alias = format!("ks_grant_single_{}", getuid());
        let mut grant_keys = generate_ec_key_and_grant_to_users(
            &sl,
            Some(alias),
            vec![GRANTEE_UID.try_into().unwrap()],
            access_vector,
        )
        .unwrap();

        grant_keys.remove(0)
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    let grant_key_nspace = unsafe { run_as::run_as_app(GRANTOR_UID, GRANTOR_GID, grantor_fn) };

    // Child function for the grantee context: can load the granted key.
    let grantee_fn = move || {
        let keystore2 = get_keystore_service();
        let rsp = get_granted_key(&keystore2, grant_key_nspace).expect("failed to get granted key");

        // Return the underlying key ID to simulate an ID leak.
        assert_eq!(rsp.metadata.key.domain, Domain::KEY_ID);
        rsp.metadata.key.nspace
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    let key_id = unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };

    // Clear the app's namespace, which is what happens when an app is uninstalled. Exercising the
    // full app uninstallation "flow" isn't possible from a Keystore VTS test since we'd need to
    // exercise the Java code that calls into the Keystore service. So, we can only test the
    // entrypoint that we know gets triggered during app uninstallation based on the code's control
    // flow.
    let clear_grantee_uid_namespace_fn = || {
        let maint = get_maintenance();
        maint
            .clearNamespace(Domain::APP, GRANTEE_UID.try_into().unwrap())
            .expect("failed to clear namespace");
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    unsafe { run_as::run_as_root(clear_grantee_uid_namespace_fn) };

    // The same context identified by <uid, grant_nspace> not longer has access to the above granted
    // key. This would be the context if a new app were installed and assigned the same app ID.
    let new_grantee_fn = move || {
        // Check that the key cannot be accessed via grant (i.e. KeyDescriptor with Domain::GRANT).
        let keystore2 = get_keystore_service();
        let result = get_granted_key(&keystore2, grant_key_nspace);
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());

        // Check that the key also cannot be accessed via key ID (i.e. KeyDescriptor with
        // Domain::KEY_ID) if the second context somehow gets a hold of it.
        let result = map_ks_error(keystore2.getKeyEntry(&KeyDescriptor {
            domain: Domain::KEY_ID,
            nspace: key_id,
            alias: None,
            blob: None,
        }));
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, new_grantee_fn) };

    // Clean up: remove grantee user.
    let remove_grantee_user_id_fn = || {
        let maint = get_maintenance();
        maint.onUserRemoved(GRANTEE_USER_ID.try_into().unwrap()).expect("failed to remove user");
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder on the main thread.
    unsafe { run_as::run_as_root(remove_grantee_user_id_fn) };
}

/// Grant an APP key to the user and immediately ungrant the granted key. In grantee context try to load
/// the key. Grantee should fail to load the ungranted key with `KEY_NOT_FOUND` error response.
#[test]
fn ungrant_app_key_success() {
    const USER_ID: u32 = 99;
    const APPLICATION_ID: u32 = 10001;
    static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    static GRANTEE_GID: u32 = GRANTEE_UID;

    // Generate a key and grant it to a user with GET_INFO permission.
    let grantor_fn = || {
        let sl = SecLevel::tee();
        let alias = format!("ks_ungrant_test_key_1{}", getuid());
        let access_vector = KeyPermission::GET_INFO.0;
        let mut grant_keys = generate_ec_key_and_grant_to_users(
            &sl,
            Some(alias.to_string()),
            vec![GRANTEE_UID.try_into().unwrap()],
            access_vector,
        )
        .unwrap();

        let grant_key_nspace = grant_keys.remove(0);

        // Ungrant above granted key.
        sl.keystore2
            .ungrant(
                &KeyDescriptor { domain: Domain::APP, nspace: -1, alias: Some(alias), blob: None },
                GRANTEE_UID.try_into().unwrap(),
            )
            .unwrap();

        grant_key_nspace
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };

    // Grantee context, try to load the ungranted key.
    let grantee_fn = move || {
        let keystore2 = get_keystore_service();
        let result = get_granted_key(&keystore2, grant_key_nspace);
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
}

/// Generate a key, grant it to the user and then delete the granted key. Try to ungrant
/// a deleted key. Test should fail to ungrant a non-existing key with `KEY_NOT_FOUND` error
/// response. Generate a new key with the same alias and try to access the previously granted
/// key in grantee context. Test should fail to load the granted key in grantee context as the
/// associated key is deleted from grantor context.
#[test]
fn ungrant_deleted_app_key_fails() {
    const APPLICATION_ID: u32 = 10001;
    const USER_ID: u32 = 99;
    static GRANTEE_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    static GRANTEE_GID: u32 = GRANTEE_UID;

    let grantor_fn = || {
        let sl = SecLevel::tee();
        let alias = format!("{}{}", "ks_grant_delete_ungrant_test_key_1", getuid());

        let key_metadata = key_generations::generate_ec_p256_signing_key(
            &sl,
            Domain::SELINUX,
            key_generations::SELINUX_SHELL_NAMESPACE,
            Some(alias.to_string()),
            None,
        )
        .unwrap();

        let access_vector = KeyPermission::GET_INFO.0;
        let grant_key = sl
            .keystore2
            .grant(&key_metadata.key, GRANTEE_UID.try_into().unwrap(), access_vector)
            .unwrap();
        assert_eq!(grant_key.domain, Domain::GRANT);

        // Delete above granted key.
        sl.keystore2.deleteKey(&key_metadata.key).unwrap();

        // Try to ungrant above granted key.
        let result =
            map_ks_error(sl.keystore2.ungrant(&key_metadata.key, GRANTEE_UID.try_into().unwrap()));
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());

        // Generate a new key with the same alias and try to access the earlier granted key
        // in grantee context.
        let result = key_generations::generate_ec_p256_signing_key(
            &sl,
            Domain::SELINUX,
            key_generations::SELINUX_SHELL_NAMESPACE,
            Some(alias),
            None,
        );
        assert!(result.is_ok());

        grant_key.nspace
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    let grant_key_nspace = unsafe { run_as::run_as_root(grantor_fn) };

    // Make sure grant did not persist, try to access the earlier granted key in grantee context.
    // Grantee context should fail to load the granted key as its associated key is deleted in
    // grantor context.
    let grantee_fn = move || {
        let keystore2 = get_keystore_service();
        let result = get_granted_key(&keystore2, grant_key_nspace);
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    unsafe { run_as::run_as_app(GRANTEE_UID, GRANTEE_GID, grantee_fn) };
}

/// Grant a key to multiple users. Verify that all grantees should succeed in loading the key and
/// use it for performing an operation successfully.
#[test]
fn grant_app_key_to_multi_users_success() {
    const APPLICATION_ID: u32 = 10001;
    const USER_ID_1: u32 = 99;
    static GRANTEE_1_UID: u32 = USER_ID_1 * AID_USER_OFFSET + APPLICATION_ID;
    static GRANTEE_1_GID: u32 = GRANTEE_1_UID;

    const USER_ID_2: u32 = 98;
    static GRANTEE_2_UID: u32 = USER_ID_2 * AID_USER_OFFSET + APPLICATION_ID;
    static GRANTEE_2_GID: u32 = GRANTEE_2_UID;

    // Generate a key and grant it to multiple users with GET_INFO|USE permissions.
    let grantor_fn = || {
        let sl = SecLevel::tee();
        let alias = format!("ks_grant_test_key_2{}", getuid());
        let access_vector = KeyPermission::GET_INFO.0 | KeyPermission::USE.0;

        generate_ec_key_and_grant_to_users(
            &sl,
            Some(alias),
            vec![GRANTEE_1_UID.try_into().unwrap(), GRANTEE_2_UID.try_into().unwrap()],
            access_vector,
        )
        .unwrap()
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    let mut grant_keys = unsafe { run_as::run_as_root(grantor_fn) };

    for (grantee_uid, grantee_gid) in
        &[(GRANTEE_1_UID, GRANTEE_1_GID), (GRANTEE_2_UID, GRANTEE_2_GID)]
    {
        let grant_key_nspace = grant_keys.remove(0);
        let grantee_fn = move || {
            assert_eq!(Ok(()), sign_with_granted_key(grant_key_nspace));
        };
        // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
        // `--test-threads=1`), and nothing yet done with binder.
        unsafe { run_as::run_as_app(*grantee_uid, *grantee_gid, grantee_fn) };
    }
}

/// Grant a key to multiple users with GET_INFO|DELETE permissions. In one of the grantee context
/// use the key and delete it. Try to load the granted key in another grantee context. Test should
/// fail to load the granted key with `KEY_NOT_FOUND` error response.
#[test]
fn grant_app_key_to_multi_users_delete_then_key_not_found() {
    const USER_ID_1: u32 = 99;
    const APPLICATION_ID: u32 = 10001;
    static GRANTEE_1_UID: u32 = USER_ID_1 * AID_USER_OFFSET + APPLICATION_ID;
    static GRANTEE_1_GID: u32 = GRANTEE_1_UID;

    const USER_ID_2: u32 = 98;
    static GRANTEE_2_UID: u32 = USER_ID_2 * AID_USER_OFFSET + APPLICATION_ID;
    static GRANTEE_2_GID: u32 = GRANTEE_2_UID;

    // Generate a key and grant it to multiple users with GET_INFO permission.
    let grantor_fn = || {
        let sl = SecLevel::tee();
        let alias = format!("ks_grant_test_key_2{}", getuid());
        let access_vector =
            KeyPermission::GET_INFO.0 | KeyPermission::USE.0 | KeyPermission::DELETE.0;

        generate_ec_key_and_grant_to_users(
            &sl,
            Some(alias),
            vec![GRANTEE_1_UID.try_into().unwrap(), GRANTEE_2_UID.try_into().unwrap()],
            access_vector,
        )
        .unwrap()
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    let mut grant_keys = unsafe { run_as::run_as_root(grantor_fn) };

    // Grantee #1 context
    let grant_key1_nspace = grant_keys.remove(0);
    let grantee1_fn = move || {
        assert_eq!(Ok(()), sign_with_granted_key(grant_key1_nspace));

        // Delete the granted key.
        get_keystore_service().deleteKey(&granted_key_descriptor(grant_key1_nspace)).unwrap();
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    unsafe { run_as::run_as_app(GRANTEE_1_UID, GRANTEE_1_GID, grantee1_fn) };

    // Grantee #2 context
    let grant_key2_nspace = grant_keys.remove(0);
    let grantee2_fn = move || {
        let keystore2 = get_keystore_service();

        let result =
            map_ks_error(keystore2.getKeyEntry(&granted_key_descriptor(grant_key2_nspace)));
        assert!(result.is_err());
        assert_eq!(Error::Rc(ResponseCode::KEY_NOT_FOUND), result.unwrap_err());
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    unsafe { run_as::run_as_app(GRANTEE_2_UID, GRANTEE_2_GID, grantee2_fn) };
}
