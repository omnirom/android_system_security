// Copyright 2024, The Android Open Source Project
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

//! Tests for user authentication interactions (via `IKeystoreAuthorization`).

use crate::keystore2_client_test_utils::BarrierReached;
use android_security_authorization::aidl::android::security::authorization::{
    IKeystoreAuthorization::IKeystoreAuthorization
};
use android_security_maintenance::aidl::android::security::maintenance::IKeystoreMaintenance::{
     IKeystoreMaintenance,
};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, HardwareAuthToken::HardwareAuthToken,
    HardwareAuthenticatorType::HardwareAuthenticatorType, SecurityLevel::SecurityLevel,
    KeyPurpose::KeyPurpose
};
use android_system_keystore2::aidl::android::system::keystore2::{
    CreateOperationResponse::CreateOperationResponse, Domain::Domain, KeyDescriptor::KeyDescriptor,
    KeyMetadata::KeyMetadata,
};
use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
    Timestamp::Timestamp,
};
use keystore2_test_utils::{
    get_keystore_service, run_as, authorizations::AuthSetBuilder,
};
use log::{warn, info};
use nix::unistd::{Gid, Uid};
use rustutils::users::AID_USER_OFFSET;

/// Test user ID.
const TEST_USER_ID: i32 = 100;
/// Fake password blob.
static PASSWORD: &[u8] = &[
    0x42, 0x39, 0x30, 0x37, 0x44, 0x37, 0x32, 0x37, 0x39, 0x39, 0x43, 0x42, 0x39, 0x41, 0x42, 0x30,
    0x34, 0x31, 0x30, 0x38, 0x46, 0x44, 0x33, 0x45, 0x39, 0x42, 0x32, 0x38, 0x36, 0x35, 0x41, 0x36,
    0x33, 0x44, 0x42, 0x42, 0x43, 0x36, 0x33, 0x42, 0x34, 0x39, 0x37, 0x33, 0x35, 0x45, 0x41, 0x41,
    0x32, 0x45, 0x31, 0x35, 0x43, 0x43, 0x46, 0x32, 0x39, 0x36, 0x33, 0x34, 0x31, 0x32, 0x41, 0x39,
];
/// Fake SID value corresponding to Gatekeeper.
static GK_SID: i64 = 123456;
/// Fake SID value corresponding to a biometric authenticator.
static BIO_SID1: i64 = 345678;
/// Fake SID value corresponding to a biometric authenticator.
static BIO_SID2: i64 = 456789;

const WEAK_UNLOCK_ENABLED: bool = true;
const WEAK_UNLOCK_DISABLED: bool = false;
const UNFORCED: bool = false;

fn get_authorization() -> binder::Strong<dyn IKeystoreAuthorization> {
    binder::get_interface("android.security.authorization").unwrap()
}

fn get_maintenance() -> binder::Strong<dyn IKeystoreMaintenance> {
    binder::get_interface("android.security.maintenance").unwrap()
}

fn abort_op(result: binder::Result<CreateOperationResponse>) {
    if let Ok(rsp) = result {
        if let Some(op) = rsp.iOperation {
            if let Err(e) = op.abort() {
                warn!("abort op failed: {e:?}");
            }
        } else {
            warn!("can't abort op with missing iOperation");
        }
    } else {
        warn!("can't abort failed op: {result:?}");
    }
}

/// RAII structure to ensure that test users are removed at the end of a test.
struct TestUser {
    id: i32,
    maint: binder::Strong<dyn IKeystoreMaintenance>,
}

impl TestUser {
    fn new() -> Self {
        Self::new_user(TEST_USER_ID, PASSWORD)
    }
    fn new_user(user_id: i32, password: &[u8]) -> Self {
        let maint = get_maintenance();
        maint.onUserAdded(user_id).expect("failed to add test user");
        maint
            .initUserSuperKeys(user_id, password, /* allowExisting= */ false)
            .expect("failed to init test user");
        Self { id: user_id, maint }
    }
}

impl Drop for TestUser {
    fn drop(&mut self) {
        let _ = self.maint.onUserRemoved(self.id);
    }
}

#[test]
fn keystore2_test_unlocked_device_required() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keystore2_client_tests")
            .with_max_level(log::LevelFilter::Debug),
    );
    static CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
    const UID: u32 = TEST_USER_ID as u32 * AID_USER_OFFSET + 1001;

    // Safety: only one thread at this point, and nothing yet done with binder.
    let mut child_handle = unsafe {
        // Perform keystore actions while running as the test user.
        run_as::run_as_child(
            CTX,
            Uid::from_raw(UID),
            Gid::from_raw(UID),
            move |reader, writer| -> Result<(), String> {
                // Action A: create a new unlocked-device-required key (which thus requires
                // super-encryption), while the device is unlocked.
                let ks2 = get_keystore_service();
                if ks2.getInterfaceVersion().unwrap() < 4 {
                    // Assuming `IKeystoreAuthorization::onDeviceLocked` and
                    // `IKeystoreAuthorization::onDeviceUnlocked` APIs will be supported on devices
                    // with `IKeystoreService` >= 4.
                    return Ok(());
                }

                // Now we're in a new process, wait to be notified before starting.
                reader.recv();

                let sec_level = ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).unwrap();
                let params = AuthSetBuilder::new()
                    .no_auth_required()
                    .unlocked_device_required()
                    .algorithm(Algorithm::EC)
                    .purpose(KeyPurpose::SIGN)
                    .purpose(KeyPurpose::VERIFY)
                    .digest(Digest::SHA_2_256)
                    .ec_curve(EcCurve::P_256);

                let KeyMetadata { key, .. } = sec_level
                    .generateKey(
                        &KeyDescriptor {
                            domain: Domain::APP,
                            nspace: -1,
                            alias: Some("unlocked-device-required".to_string()),
                            blob: None,
                        },
                        None,
                        &params,
                        0,
                        b"entropy",
                    )
                    .expect("key generation failed");
                info!("A: created unlocked-device-required key while unlocked {key:?}");
                writer.send(&BarrierReached {}); // A done.

                // Action B: fail to use the unlocked-device-required key while locked.
                reader.recv();
                let params =
                    AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
                let result = sec_level.createOperation(&key, &params, UNFORCED);
                info!("B: use unlocked-device-required key while locked => {result:?}");
                assert!(result.is_err());
                writer.send(&BarrierReached {}); // B done.

                // Action C: try to use the unlocked-device-required key while unlocked with a
                // password.
                reader.recv();
                let result = sec_level.createOperation(&key, &params, UNFORCED);
                info!("C: use unlocked-device-required key while lskf-unlocked => {result:?}");
                assert!(result.is_ok(), "failed with {result:?}");
                abort_op(result);
                writer.send(&BarrierReached {}); // C done.

                // Action D: try to use the unlocked-device-required key while unlocked with a weak
                // biometric.
                reader.recv();
                let result = sec_level.createOperation(&key, &params, UNFORCED);
                info!("D: use unlocked-device-required key while weak-locked => {result:?}");
                assert!(result.is_ok(), "createOperation failed: {result:?}");
                abort_op(result);
                writer.send(&BarrierReached {}); // D done.

                let _ = sec_level.deleteKey(&key);
                Ok(())
            },
        )
    }
    .unwrap();

    let ks2 = get_keystore_service();
    if ks2.getInterfaceVersion().unwrap() < 4 {
        // Assuming `IKeystoreAuthorization::onDeviceLocked` and
        // `IKeystoreAuthorization::onDeviceUnlocked` APIs will be supported on devices
        // with `IKeystoreService` >= 4.
        assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
        return;
    }
    // Now that the separate process has been forked off, it's safe to use binder.
    let user = TestUser::new();
    let user_id = user.id;
    let auth_service = get_authorization();

    // Lock and unlock to ensure super keys are already created.
    auth_service.onDeviceLocked(user_id, &[BIO_SID1, BIO_SID2], WEAK_UNLOCK_DISABLED).unwrap();
    auth_service.onDeviceUnlocked(user_id, Some(PASSWORD)).unwrap();
    auth_service.addAuthToken(&fake_lskf_token(GK_SID)).unwrap();

    info!("trigger child process action A while unlocked and wait for completion");
    child_handle.send(&BarrierReached {});
    child_handle.recv();

    // Move to locked and don't allow weak unlock, so super keys are wiped.
    auth_service.onDeviceLocked(user_id, &[BIO_SID1, BIO_SID2], WEAK_UNLOCK_DISABLED).unwrap();

    info!("trigger child process action B while locked and wait for completion");
    child_handle.send(&BarrierReached {});
    child_handle.recv();

    // Unlock with password => loads super key from database.
    auth_service.onDeviceUnlocked(user_id, Some(PASSWORD)).unwrap();
    auth_service.addAuthToken(&fake_lskf_token(GK_SID)).unwrap();

    info!("trigger child process action C while lskf-unlocked and wait for completion");
    child_handle.send(&BarrierReached {});
    child_handle.recv();

    // Move to locked and allow weak unlock, then do a weak unlock.
    auth_service.onDeviceLocked(user_id, &[BIO_SID1, BIO_SID2], WEAK_UNLOCK_ENABLED).unwrap();
    auth_service.onDeviceUnlocked(user_id, None).unwrap();

    info!("trigger child process action D while weak-unlocked and wait for completion");
    child_handle.send(&BarrierReached {});
    child_handle.recv();

    assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
}

/// Generate a fake [`HardwareAuthToken`] for the given sid.
fn fake_lskf_token(gk_sid: i64) -> HardwareAuthToken {
    HardwareAuthToken {
        challenge: 0,
        userId: gk_sid,
        authenticatorId: 0,
        authenticatorType: HardwareAuthenticatorType::PASSWORD,
        timestamp: Timestamp { milliSeconds: 123 },
        mac: vec![1, 2, 3],
    }
}
