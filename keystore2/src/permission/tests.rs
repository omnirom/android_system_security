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

//! Access control tests.

use super::*;
use crate::key_perm_set;
use anyhow::anyhow;
use anyhow::Result;
use keystore2_selinux::*;

const ALL_PERMS: KeyPermSet = key_perm_set![
    KeyPerm::ManageBlob,
    KeyPerm::Delete,
    KeyPerm::UseDevId,
    KeyPerm::ReqForcedOp,
    KeyPerm::GenUniqueId,
    KeyPerm::Grant,
    KeyPerm::GetInfo,
    KeyPerm::Rebind,
    KeyPerm::Update,
    KeyPerm::Use,
    KeyPerm::ConvertStorageKeyToEphemeral,
];

const SYSTEM_SERVER_PERMISSIONS_NO_GRANT: KeyPermSet = key_perm_set![
    KeyPerm::Delete,
    KeyPerm::UseDevId,
    // No KeyPerm::Grant
    KeyPerm::GetInfo,
    KeyPerm::Rebind,
    KeyPerm::Update,
    KeyPerm::Use,
];

const NOT_GRANT_PERMS: KeyPermSet = key_perm_set![
    KeyPerm::ManageBlob,
    KeyPerm::Delete,
    KeyPerm::UseDevId,
    KeyPerm::ReqForcedOp,
    KeyPerm::GenUniqueId,
    // No KeyPerm::Grant
    KeyPerm::GetInfo,
    KeyPerm::Rebind,
    KeyPerm::Update,
    KeyPerm::Use,
    KeyPerm::ConvertStorageKeyToEphemeral,
];

const UNPRIV_PERMS: KeyPermSet = key_perm_set![
    KeyPerm::Delete,
    KeyPerm::GetInfo,
    KeyPerm::Rebind,
    KeyPerm::Update,
    KeyPerm::Use,
];

/// The su_key namespace as defined in su.te and keystore_key_contexts of the
/// SePolicy (system/sepolicy).
const SU_KEY_NAMESPACE: i32 = 0;
/// The shell_key namespace as defined in shell.te and keystore_key_contexts of the
/// SePolicy (system/sepolicy).
const SHELL_KEY_NAMESPACE: i32 = 1;

pub fn test_getcon() -> Result<Context> {
    Context::new("u:object_r:keystore:s0")
}

// This macro evaluates the given expression and checks that
// a) evaluated to Result::Err() and that
// b) the wrapped error is selinux::Error::perm() (permission denied).
// We use a macro here because a function would mask which invocation caused the failure.
//
// TODO b/164121720 Replace this macro with a function when `track_caller` is available.
macro_rules! assert_perm_failed {
    ($test_function:expr) => {
        let result = $test_function;
        assert!(result.is_err(), "Permission check should have failed.");
        assert_eq!(
            Some(&selinux::Error::perm()),
            result.err().unwrap().root_cause().downcast_ref::<selinux::Error>()
        );
    };
}

fn check_context() -> Result<(selinux::Context, i32, bool)> {
    // Calling the non mocked selinux::getcon here intended.
    let context = selinux::getcon()?;
    match context.to_str().unwrap() {
        "u:r:su:s0" => Ok((context, SU_KEY_NAMESPACE, true)),
        "u:r:shell:s0" => Ok((context, SHELL_KEY_NAMESPACE, false)),
        c => Err(anyhow!(format!(
            "This test must be run as \"su\" or \"shell\". Current context: \"{}\"",
            c
        ))),
    }
}

#[test]
fn check_keystore_permission_test() -> Result<()> {
    let system_server_ctx = Context::new("u:r:system_server:s0")?;
    assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::AddAuth).is_ok());
    assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::ClearNs).is_ok());
    assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::Lock).is_ok());
    assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::Reset).is_ok());
    assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::Unlock).is_ok());
    assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::ChangeUser).is_ok());
    assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::ChangePassword).is_ok());
    assert!(check_keystore_permission(&system_server_ctx, KeystorePerm::ClearUID).is_ok());
    let shell_ctx = Context::new("u:r:shell:s0")?;
    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::AddAuth));
    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::ClearNs));
    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::List));
    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::Lock));
    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::Reset));
    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::Unlock));
    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::ChangeUser));
    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::ChangePassword));
    assert_perm_failed!(check_keystore_permission(&shell_ctx, KeystorePerm::ClearUID));
    Ok(())
}

#[test]
fn check_grant_permission_app() -> Result<()> {
    let system_server_ctx = Context::new("u:r:system_server:s0")?;
    let shell_ctx = Context::new("u:r:shell:s0")?;
    let key = KeyDescriptor { domain: Domain::APP, nspace: 0, alias: None, blob: None };
    check_grant_permission(&system_server_ctx, SYSTEM_SERVER_PERMISSIONS_NO_GRANT, &key)
        .expect("Grant permission check failed.");

    // attempts to grant the grant permission must always fail even when privileged.
    assert_perm_failed!(check_grant_permission(&system_server_ctx, KeyPerm::Grant.into(), &key));
    // unprivileged grant attempts always fail. shell does not have the grant permission.
    assert_perm_failed!(check_grant_permission(&shell_ctx, UNPRIV_PERMS, &key));
    Ok(())
}

#[test]
fn check_grant_permission_selinux() -> Result<()> {
    let (sctx, namespace, is_su) = check_context()?;
    let key = KeyDescriptor {
        domain: Domain::SELINUX,
        nspace: namespace as i64,
        alias: None,
        blob: None,
    };
    if is_su {
        assert!(check_grant_permission(&sctx, NOT_GRANT_PERMS, &key).is_ok());
        // attempts to grant the grant permission must always fail even when privileged.
        assert_perm_failed!(check_grant_permission(&sctx, KeyPerm::Grant.into(), &key));
    } else {
        // unprivileged grant attempts always fail. shell does not have the grant permission.
        assert_perm_failed!(check_grant_permission(&sctx, UNPRIV_PERMS, &key));
    }
    Ok(())
}

#[test]
fn check_key_permission_domain_grant() -> Result<()> {
    let key = KeyDescriptor { domain: Domain::GRANT, nspace: 0, alias: None, blob: None };

    assert_perm_failed!(check_key_permission(
        0,
        &selinux::Context::new("ignored").unwrap(),
        KeyPerm::Grant,
        &key,
        &Some(UNPRIV_PERMS)
    ));

    check_key_permission(
        0,
        &selinux::Context::new("ignored").unwrap(),
        KeyPerm::Use,
        &key,
        &Some(ALL_PERMS),
    )
}

#[test]
fn check_key_permission_domain_app() -> Result<()> {
    let system_server_ctx = Context::new("u:r:system_server:s0")?;
    let shell_ctx = Context::new("u:r:shell:s0")?;
    let gmscore_app = Context::new("u:r:gmscore_app:s0")?;

    let key = KeyDescriptor { domain: Domain::APP, nspace: 0, alias: None, blob: None };

    assert!(check_key_permission(0, &system_server_ctx, KeyPerm::Use, &key, &None).is_ok());
    assert!(check_key_permission(0, &system_server_ctx, KeyPerm::Delete, &key, &None).is_ok());
    assert!(check_key_permission(0, &system_server_ctx, KeyPerm::GetInfo, &key, &None).is_ok());
    assert!(check_key_permission(0, &system_server_ctx, KeyPerm::Rebind, &key, &None).is_ok());
    assert!(check_key_permission(0, &system_server_ctx, KeyPerm::Update, &key, &None).is_ok());
    assert!(check_key_permission(0, &system_server_ctx, KeyPerm::Grant, &key, &None).is_ok());
    assert!(check_key_permission(0, &system_server_ctx, KeyPerm::UseDevId, &key, &None).is_ok());
    assert!(check_key_permission(0, &gmscore_app, KeyPerm::GenUniqueId, &key, &None).is_ok());

    assert!(check_key_permission(0, &shell_ctx, KeyPerm::Use, &key, &None).is_ok());
    assert!(check_key_permission(0, &shell_ctx, KeyPerm::Delete, &key, &None).is_ok());
    assert!(check_key_permission(0, &shell_ctx, KeyPerm::GetInfo, &key, &None).is_ok());
    assert!(check_key_permission(0, &shell_ctx, KeyPerm::Rebind, &key, &None).is_ok());
    assert!(check_key_permission(0, &shell_ctx, KeyPerm::Update, &key, &None).is_ok());
    assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::Grant, &key, &None));
    assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::ReqForcedOp, &key, &None));
    assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::ManageBlob, &key, &None));
    assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::UseDevId, &key, &None));
    assert_perm_failed!(check_key_permission(0, &shell_ctx, KeyPerm::GenUniqueId, &key, &None));

    // Also make sure that the permission fails if the caller is not the owner.
    assert_perm_failed!(check_key_permission(
        1, // the owner is 0
        &system_server_ctx,
        KeyPerm::Use,
        &key,
        &None
    ));
    // Unless there was a grant.
    assert!(check_key_permission(
        1,
        &system_server_ctx,
        KeyPerm::Use,
        &key,
        &Some(key_perm_set![KeyPerm::Use])
    )
    .is_ok());
    // But fail if the grant did not cover the requested permission.
    assert_perm_failed!(check_key_permission(
        1,
        &system_server_ctx,
        KeyPerm::Use,
        &key,
        &Some(key_perm_set![KeyPerm::GetInfo])
    ));

    Ok(())
}

#[test]
fn check_key_permission_domain_selinux() -> Result<()> {
    let (sctx, namespace, is_su) = check_context()?;
    let key = KeyDescriptor {
        domain: Domain::SELINUX,
        nspace: namespace as i64,
        alias: None,
        blob: None,
    };

    assert!(check_key_permission(0, &sctx, KeyPerm::Use, &key, &None).is_ok());
    assert!(check_key_permission(0, &sctx, KeyPerm::Delete, &key, &None).is_ok());
    assert!(check_key_permission(0, &sctx, KeyPerm::GetInfo, &key, &None).is_ok());
    assert!(check_key_permission(0, &sctx, KeyPerm::Rebind, &key, &None).is_ok());
    assert!(check_key_permission(0, &sctx, KeyPerm::Update, &key, &None).is_ok());

    if is_su {
        assert!(check_key_permission(0, &sctx, KeyPerm::Grant, &key, &None).is_ok());
        assert!(check_key_permission(0, &sctx, KeyPerm::ManageBlob, &key, &None).is_ok());
        assert!(check_key_permission(0, &sctx, KeyPerm::UseDevId, &key, &None).is_ok());
        assert!(check_key_permission(0, &sctx, KeyPerm::GenUniqueId, &key, &None).is_ok());
        assert!(check_key_permission(0, &sctx, KeyPerm::ReqForcedOp, &key, &None).is_ok());
    } else {
        assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::Grant, &key, &None));
        assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::ReqForcedOp, &key, &None));
        assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::ManageBlob, &key, &None));
        assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::UseDevId, &key, &None));
        assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::GenUniqueId, &key, &None));
    }
    Ok(())
}

#[test]
fn check_key_permission_domain_blob() -> Result<()> {
    let (sctx, namespace, is_su) = check_context()?;
    let key =
        KeyDescriptor { domain: Domain::BLOB, nspace: namespace as i64, alias: None, blob: None };

    if is_su {
        check_key_permission(0, &sctx, KeyPerm::Use, &key, &None)
    } else {
        assert_perm_failed!(check_key_permission(0, &sctx, KeyPerm::Use, &key, &None));
        Ok(())
    }
}

#[test]
fn check_key_permission_domain_key_id() -> Result<()> {
    let key = KeyDescriptor { domain: Domain::KEY_ID, nspace: 0, alias: None, blob: None };

    assert_eq!(
        Some(&KsError::sys()),
        check_key_permission(
            0,
            &selinux::Context::new("ignored").unwrap(),
            KeyPerm::Use,
            &key,
            &None
        )
        .err()
        .unwrap()
        .root_cause()
        .downcast_ref::<KsError>()
    );
    Ok(())
}

#[test]
fn key_perm_set_all_test() {
    let v = key_perm_set![
        KeyPerm::ManageBlob,
        KeyPerm::Delete,
        KeyPerm::UseDevId,
        KeyPerm::ReqForcedOp,
        KeyPerm::GenUniqueId,
        KeyPerm::Grant,
        KeyPerm::GetInfo,
        KeyPerm::Rebind,
        KeyPerm::Update,
        KeyPerm::Use // Test if the macro accepts missing comma at the end of the list.
    ];
    let mut i = v.into_iter();
    assert_eq!(i.next().unwrap().name(), "delete");
    assert_eq!(i.next().unwrap().name(), "gen_unique_id");
    assert_eq!(i.next().unwrap().name(), "get_info");
    assert_eq!(i.next().unwrap().name(), "grant");
    assert_eq!(i.next().unwrap().name(), "manage_blob");
    assert_eq!(i.next().unwrap().name(), "rebind");
    assert_eq!(i.next().unwrap().name(), "req_forced_op");
    assert_eq!(i.next().unwrap().name(), "update");
    assert_eq!(i.next().unwrap().name(), "use");
    assert_eq!(i.next().unwrap().name(), "use_dev_id");
    assert_eq!(None, i.next());
}
#[test]
fn key_perm_set_sparse_test() {
    let v = key_perm_set![
        KeyPerm::ManageBlob,
        KeyPerm::ReqForcedOp,
        KeyPerm::GenUniqueId,
        KeyPerm::Update,
        KeyPerm::Use, // Test if macro accepts the comma at the end of the list.
    ];
    let mut i = v.into_iter();
    assert_eq!(i.next().unwrap().name(), "gen_unique_id");
    assert_eq!(i.next().unwrap().name(), "manage_blob");
    assert_eq!(i.next().unwrap().name(), "req_forced_op");
    assert_eq!(i.next().unwrap().name(), "update");
    assert_eq!(i.next().unwrap().name(), "use");
    assert_eq!(None, i.next());
}
#[test]
fn key_perm_set_empty_test() {
    let v = key_perm_set![];
    let mut i = v.into_iter();
    assert_eq!(None, i.next());
}
#[test]
fn key_perm_set_include_subset_test() {
    let v1 = key_perm_set![
        KeyPerm::ManageBlob,
        KeyPerm::Delete,
        KeyPerm::UseDevId,
        KeyPerm::ReqForcedOp,
        KeyPerm::GenUniqueId,
        KeyPerm::Grant,
        KeyPerm::GetInfo,
        KeyPerm::Rebind,
        KeyPerm::Update,
        KeyPerm::Use,
    ];
    let v2 = key_perm_set![
        KeyPerm::ManageBlob,
        KeyPerm::Delete,
        KeyPerm::Rebind,
        KeyPerm::Update,
        KeyPerm::Use,
    ];
    assert!(v1.includes(v2));
    assert!(!v2.includes(v1));
}
#[test]
fn key_perm_set_include_equal_test() {
    let v1 = key_perm_set![
        KeyPerm::ManageBlob,
        KeyPerm::Delete,
        KeyPerm::Rebind,
        KeyPerm::Update,
        KeyPerm::Use,
    ];
    let v2 = key_perm_set![
        KeyPerm::ManageBlob,
        KeyPerm::Delete,
        KeyPerm::Rebind,
        KeyPerm::Update,
        KeyPerm::Use,
    ];
    assert!(v1.includes(v2));
    assert!(v2.includes(v1));
}
#[test]
fn key_perm_set_include_overlap_test() {
    let v1 = key_perm_set![
        KeyPerm::ManageBlob,
        KeyPerm::Delete,
        KeyPerm::Grant, // only in v1
        KeyPerm::Rebind,
        KeyPerm::Update,
        KeyPerm::Use,
    ];
    let v2 = key_perm_set![
        KeyPerm::ManageBlob,
        KeyPerm::Delete,
        KeyPerm::ReqForcedOp, // only in v2
        KeyPerm::Rebind,
        KeyPerm::Update,
        KeyPerm::Use,
    ];
    assert!(!v1.includes(v2));
    assert!(!v2.includes(v1));
}
#[test]
fn key_perm_set_include_no_overlap_test() {
    let v1 = key_perm_set![KeyPerm::ManageBlob, KeyPerm::Delete, KeyPerm::Grant,];
    let v2 = key_perm_set![KeyPerm::ReqForcedOp, KeyPerm::Rebind, KeyPerm::Update, KeyPerm::Use,];
    assert!(!v1.includes(v2));
    assert!(!v2.includes(v1));
}
