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

use crate::keystore2_client_test_utils::{
    BarrierReached, BarrierReachedWithData, get_vsr_api_level
};
use android_security_authorization::aidl::android::security::authorization::{
    IKeystoreAuthorization::IKeystoreAuthorization
};
use android_security_maintenance::aidl::android::security::maintenance::IKeystoreMaintenance::{
     IKeystoreMaintenance,
};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, ErrorCode::ErrorCode,
    HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
    KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
};
use android_hardware_gatekeeper::aidl::android::hardware::gatekeeper::{
    IGatekeeper::IGatekeeper, IGatekeeper::ERROR_RETRY_TIMEOUT,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    CreateOperationResponse::CreateOperationResponse, Domain::Domain, KeyDescriptor::KeyDescriptor,
    KeyMetadata::KeyMetadata,
};
use android_system_keystore2::binder::{ExceptionCode, Result as BinderResult};
use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
    Timestamp::Timestamp,
};
use anyhow::Context;
use keystore2_test_utils::{
    authorizations::AuthSetBuilder, expect, get_keystore_service, run_as,
    run_as::{ChannelReader, ChannelWriter}, expect_km_error,
};
use log::{warn, info};
use rustutils::users::AID_USER_OFFSET;
use std::{time::Duration, thread::sleep};

/// Test user ID.
const TEST_USER_ID: i32 = 100;
/// Corresponding uid value.
const UID: u32 = TEST_USER_ID as u32 * AID_USER_OFFSET + 1001;
/// Fake synthetic password blob.
static SYNTHETIC_PASSWORD: &[u8] = &[
    0x42, 0x39, 0x30, 0x37, 0x44, 0x37, 0x32, 0x37, 0x39, 0x39, 0x43, 0x42, 0x39, 0x41, 0x42, 0x30,
    0x34, 0x31, 0x30, 0x38, 0x46, 0x44, 0x33, 0x45, 0x39, 0x42, 0x32, 0x38, 0x36, 0x35, 0x41, 0x36,
    0x33, 0x44, 0x42, 0x42, 0x43, 0x36, 0x33, 0x42, 0x34, 0x39, 0x37, 0x33, 0x35, 0x45, 0x41, 0x41,
    0x32, 0x45, 0x31, 0x35, 0x43, 0x43, 0x46, 0x32, 0x39, 0x36, 0x33, 0x34, 0x31, 0x32, 0x41, 0x39,
];
/// Gatekeeper password.
static GK_PASSWORD: &[u8] = b"correcthorsebatterystaple";
/// Fake SID base value corresponding to Gatekeeper.  Individual tests use different SIDs to reduce
/// the chances of cross-contamination, calculated statically (because each test is forked into a
/// separate process).
static GK_FAKE_SID_BASE: i64 = 123400;
/// Fake SID base value corresponding to a biometric authenticator.  Individual tests use different
/// SIDs to reduce the chances of cross-contamination.
static BIO_FAKE_SID_BASE: i64 = 345600;

const WEAK_UNLOCK_ENABLED: bool = true;
const WEAK_UNLOCK_DISABLED: bool = false;
const UNFORCED: bool = false;

fn get_authorization() -> binder::Strong<dyn IKeystoreAuthorization> {
    binder::get_interface("android.security.authorization").unwrap()
}

fn get_maintenance() -> binder::Strong<dyn IKeystoreMaintenance> {
    binder::get_interface("android.security.maintenance").unwrap()
}

/// Get the default Gatekeeper instance. This may fail on older devices where Gatekeeper is still a
/// HIDL interface rather than AIDL.
fn get_gatekeeper() -> Option<binder::Strong<dyn IGatekeeper>> {
    binder::get_interface("android.hardware.gatekeeper.IGatekeeper/default").ok()
}

/// Indicate whether a Gatekeeper result indicates a delayed-retry is needed.
fn is_gk_retry<T: std::fmt::Debug>(result: &BinderResult<T>) -> bool {
    matches!(result, Err(s) if s.exception_code() == ExceptionCode::SERVICE_SPECIFIC
                 && s.service_specific_error() == ERROR_RETRY_TIMEOUT)
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
    gk: Option<binder::Strong<dyn IGatekeeper>>,
    gk_sid: Option<i64>,
    gk_handle: Vec<u8>,
}

impl TestUser {
    fn new() -> Self {
        Self::new_user(TEST_USER_ID, SYNTHETIC_PASSWORD)
    }
    fn new_user(user_id: i32, sp: &[u8]) -> Self {
        let maint = get_maintenance();
        maint.onUserAdded(user_id).expect("failed to add test user");
        maint
            .initUserSuperKeys(user_id, sp, /* allowExisting= */ false)
            .expect("failed to init test user");
        let gk = get_gatekeeper();
        let (gk_sid, gk_handle) = if let Some(gk) = &gk {
            // AIDL Gatekeeper is available, so enroll a password.
            loop {
                let result = gk.enroll(user_id, &[], &[], GK_PASSWORD);
                if is_gk_retry(&result) {
                    sleep(Duration::from_secs(1));
                    continue;
                }
                let rsp = result.expect("gk.enroll() failed");
                info!("registered test user {user_id} as sid {} with GK", rsp.secureUserId);
                break (Some(rsp.secureUserId), rsp.data);
            }
        } else {
            (None, vec![])
        };
        Self { id: user_id, maint, gk, gk_sid, gk_handle }
    }

    /// Perform Gatekeeper verification, which will return a HAT on success.
    fn gk_verify(&self, challenge: i64) -> Option<HardwareAuthToken> {
        let Some(gk) = &self.gk else { return None };
        loop {
            let result = gk.verify(self.id, challenge, &self.gk_handle, GK_PASSWORD);
            if is_gk_retry(&result) {
                sleep(Duration::from_secs(1));
                continue;
            }
            let rsp = result.expect("gk.verify failed");
            break Some(rsp.hardwareAuthToken);
        }
    }
}

impl Drop for TestUser {
    fn drop(&mut self) {
        let _ = self.maint.onUserRemoved(self.id);
        if let Some(gk) = &self.gk {
            info!("deregister test user {} with GK", self.id);
            if let Err(e) = gk.deleteUser(self.id) {
                warn!("failed to deregister test user {}: {e:?}", self.id);
            }
        }
    }
}

#[test]
fn test_auth_bound_timeout_with_gk() {
    let bio_fake_sid1 = BIO_FAKE_SID_BASE + 1;
    let bio_fake_sid2 = BIO_FAKE_SID_BASE + 2;
    type Barrier = BarrierReachedWithData<Option<i64>>;
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keystore2_client_tests")
            .with_max_level(log::LevelFilter::Debug),
    );

    let child_fn = move |reader: &mut ChannelReader<Barrier>,
                         writer: &mut ChannelWriter<Barrier>|
          -> Result<(), run_as::Error> {
        // Now we're in a new process, wait to be notified before starting.
        let gk_sid: i64 = match reader.recv().0 {
            Some(sid) => sid,
            None => {
                // There is no AIDL Gatekeeper available, so abandon the test.  It would be nice to
                // know this before starting the child process, but finding it out requires Binder,
                // which can't be used until after the child has forked.
                return Ok(());
            }
        };

        // Action A: create a new auth-bound key which requires auth in the last 3 seconds,
        // and fail to start an operation using it.
        let ks2 = get_keystore_service();
        let sec_level =
            ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).context("no TEE")?;
        let params = AuthSetBuilder::new()
            .user_secure_id(gk_sid)
            .user_secure_id(bio_fake_sid1)
            .user_secure_id(bio_fake_sid2)
            .user_auth_type(HardwareAuthenticatorType::ANY)
            .auth_timeout(3)
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
                    alias: Some("auth-bound-timeout-1".to_string()),
                    blob: None,
                },
                None,
                &params,
                0,
                b"entropy",
            )
            .context("key generation failed")?;
        info!("A: created auth-timeout key {key:?} bound to sids {gk_sid}, {bio_fake_sid1}, {bio_fake_sid2}");

        // No HATs so cannot create an operation using the key.
        let params = AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
        let result = sec_level.createOperation(&key, &params, UNFORCED);
        expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
        info!("A: failed auth-bound operation (no HAT) as expected {result:?}");

        writer.send(&Barrier::new(None)); // A done.

        // Action B: succeed when a valid HAT is available.
        reader.recv();

        let result = sec_level.createOperation(&key, &params, UNFORCED);
        expect!(result.is_ok());
        let op = result.unwrap().iOperation.context("no operation in result")?;
        let result = op.finish(Some(b"data"), None);
        expect!(result.is_ok());
        info!("B: performed auth-bound operation (with valid GK HAT) as expected");

        writer.send(&Barrier::new(None)); // B done.

        // Action C: fail again when the HAT is old enough to not even be checked.
        reader.recv();
        info!("C: wait so that any HAT times out");
        sleep(Duration::from_secs(4));
        let result = sec_level.createOperation(&key, &params, UNFORCED);
        info!("C: failed auth-bound operation (HAT is too old) as expected {result:?}");
        writer.send(&Barrier::new(None)); // C done.

        Ok(())
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    let mut child_handle = unsafe {
        // Perform keystore actions while running as the test user.
        run_as::run_as_child_app(UID, UID, child_fn)
    }
    .unwrap();

    // Now that the separate process has been forked off, it's safe to use binder to setup a test
    // user.
    let _ks2 = get_keystore_service();
    let user = TestUser::new();
    if user.gk.is_none() {
        // Can't run this test if there's no AIDL Gatekeeper.
        child_handle.send(&Barrier::new(None));
        assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
        return;
    }
    let user_id = user.id;
    let auth_service = get_authorization();

    // Lock and unlock to ensure super keys are already created.
    auth_service
        .onDeviceLocked(user_id, &[bio_fake_sid1, bio_fake_sid2], WEAK_UNLOCK_DISABLED)
        .unwrap();
    auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();

    info!("trigger child process action A and wait for completion");
    child_handle.send(&Barrier::new(Some(user.gk_sid.unwrap())));
    child_handle.recv_or_die();

    // Unlock with GK password to get a genuine auth token.
    let real_hat = user.gk_verify(0).expect("failed to perform GK verify");
    auth_service.addAuthToken(&real_hat).unwrap();

    info!("trigger child process action B and wait for completion");
    child_handle.send(&Barrier::new(None));
    child_handle.recv_or_die();

    info!("trigger child process action C and wait for completion");
    child_handle.send(&Barrier::new(None));
    child_handle.recv_or_die();

    assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
}

#[test]
fn test_auth_bound_timeout_failure() {
    let gk_fake_sid = GK_FAKE_SID_BASE + 1;
    let bio_fake_sid1 = BIO_FAKE_SID_BASE + 3;
    let bio_fake_sid2 = BIO_FAKE_SID_BASE + 4;
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keystore2_client_tests")
            .with_max_level(log::LevelFilter::Debug),
    );

    let child_fn = move |reader: &mut ChannelReader<BarrierReached>,
                         writer: &mut ChannelWriter<BarrierReached>|
          -> Result<(), run_as::Error> {
        // Now we're in a new process, wait to be notified before starting.
        reader.recv();

        // Action A: create a new auth-bound key which requires auth in the last 3 seconds,
        // and fail to start an operation using it.
        let ks2 = get_keystore_service();

        let sec_level =
            ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).context("no TEE")?;
        let params = AuthSetBuilder::new()
            .user_secure_id(bio_fake_sid1)
            .user_secure_id(bio_fake_sid2)
            .user_auth_type(HardwareAuthenticatorType::ANY)
            .auth_timeout(3)
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
                    alias: Some("auth-bound-timeout-2".to_string()),
                    blob: None,
                },
                None,
                &params,
                0,
                b"entropy",
            )
            .context("key generation failed")?;
        info!("A: created auth-timeout key {key:?} bound to sids {bio_fake_sid1}, {bio_fake_sid2}");

        // No HATs so cannot create an operation using the key.
        let params = AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
        let result = sec_level.createOperation(&key, &params, UNFORCED);
        expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
        info!("A: failed auth-bound operation (no HAT) as expected {result:?}");

        writer.send(&BarrierReached {}); // A done.

        // Action B: fail again when an invalid HAT is available.
        reader.recv();

        let result = sec_level.createOperation(&key, &params, UNFORCED);
        expect!(result.is_err());
        if get_vsr_api_level() >= 35 {
            // Older devices may report an incorrect error code when presented with an invalid auth
            // token.
            expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
        }
        info!("B: failed auth-bound operation (HAT is invalid) as expected {result:?}");

        writer.send(&BarrierReached {}); // B done.

        // Action C: fail again when the HAT is old enough to not even be checked.
        reader.recv();
        info!("C: wait so that any HAT times out");
        sleep(Duration::from_secs(4));
        let result = sec_level.createOperation(&key, &params, UNFORCED);
        expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
        info!("C: failed auth-bound operation (HAT is too old) as expected {result:?}");
        writer.send(&BarrierReached {}); // C done.

        Ok(())
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    let mut child_handle = unsafe {
        // Perform keystore actions while running as the test user.
        run_as::run_as_child_app(UID, UID, child_fn)
    }
    .unwrap();

    // Now that the separate process has been forked off, it's safe to use binder to setup a test
    // user.
    let _ks2 = get_keystore_service();
    let user = TestUser::new();
    let user_id = user.id;
    let auth_service = get_authorization();

    // Lock and unlock to ensure super keys are already created.
    auth_service
        .onDeviceLocked(user_id, &[bio_fake_sid1, bio_fake_sid2], WEAK_UNLOCK_DISABLED)
        .unwrap();
    auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
    auth_service.addAuthToken(&fake_lskf_token(gk_fake_sid)).unwrap();

    info!("trigger child process action A and wait for completion");
    child_handle.send(&BarrierReached {});
    child_handle.recv_or_die();

    // Unlock with password and a fake auth token that matches the key
    auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
    auth_service.addAuthToken(&fake_bio_lskf_token(gk_fake_sid, bio_fake_sid1)).unwrap();

    info!("trigger child process action B and wait for completion");
    child_handle.send(&BarrierReached {});
    child_handle.recv_or_die();

    info!("trigger child process action C and wait for completion");
    child_handle.send(&BarrierReached {});
    child_handle.recv_or_die();

    assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
}

#[test]
fn test_auth_bound_per_op_with_gk() {
    let bio_fake_sid1 = BIO_FAKE_SID_BASE + 5;
    let bio_fake_sid2 = BIO_FAKE_SID_BASE + 6;
    type Barrier = BarrierReachedWithData<Option<i64>>;
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keystore2_client_tests")
            .with_max_level(log::LevelFilter::Debug),
    );

    let child_fn = move |reader: &mut ChannelReader<Barrier>,
                         writer: &mut ChannelWriter<Barrier>|
          -> Result<(), run_as::Error> {
        // Now we're in a new process, wait to be notified before starting.
        let gk_sid: i64 = match reader.recv().0 {
            Some(sid) => sid,
            None => {
                // There is no AIDL Gatekeeper available, so abandon the test.  It would be nice to
                // know this before starting the child process, but finding it out requires Binder,
                // which can't be used until after the child has forked.
                return Ok(());
            }
        };

        // Action A: create a new auth-bound key which requires auth-per-operation (because
        // AUTH_TIMEOUT is not specified), and fail to finish an operation using it.
        let ks2 = get_keystore_service();
        let sec_level =
            ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).context("no TEE")?;
        let params = AuthSetBuilder::new()
            .user_secure_id(gk_sid)
            .user_secure_id(bio_fake_sid1)
            .user_auth_type(HardwareAuthenticatorType::ANY)
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
                    alias: Some("auth-per-op-1".to_string()),
                    blob: None,
                },
                None,
                &params,
                0,
                b"entropy",
            )
            .context("key generation failed")?;
        info!("A: created auth-per-op key {key:?} bound to sids {gk_sid}, {bio_fake_sid1}");

        // We can create an operation using the key...
        let params = AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
        let result = sec_level
            .createOperation(&key, &params, UNFORCED)
            .expect("failed to create auth-per-op operation");
        let op = result.iOperation.context("no operation in result")?;
        info!("A: created auth-per-op operation, got challenge {:?}", result.operationChallenge);

        // .. but attempting to finish the operation fails because Keystore can't find a HAT.
        let result = op.finish(Some(b"data"), None);
        expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
        info!("A: failed auth-per-op op (no HAT) as expected {result:?}");

        writer.send(&Barrier::new(None)); // A done.

        // Action B: start an operation and pass out the challenge
        reader.recv();
        let result = sec_level
            .createOperation(&key, &params, UNFORCED)
            .expect("failed to create auth-per-op operation");
        let op = result.iOperation.context("no operation in result")?;
        info!("B: created auth-per-op operation, got challenge {:?}", result.operationChallenge);
        writer.send(&Barrier::new(Some(result.operationChallenge.unwrap().challenge))); // B done.

        // Action C: finishing the operation succeeds now there's a per-op HAT.
        reader.recv();
        let result = op.finish(Some(b"data"), None);
        expect!(result.is_ok());
        info!("C: performed auth-per-op op expected");
        writer.send(&Barrier::new(None)); // D done.

        Ok(())
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    let mut child_handle = unsafe {
        // Perform keystore actions while running as the test user.
        run_as::run_as_child_app(UID, UID, child_fn)
    }
    .unwrap();

    // Now that the separate process has been forked off, it's safe to use binder to setup a test
    // user.
    let _ks2 = get_keystore_service();
    let user = TestUser::new();
    if user.gk.is_none() {
        // Can't run this test if there's no AIDL Gatekeeper.
        child_handle.send(&Barrier::new(None));
        assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
        return;
    }
    let user_id = user.id;
    let auth_service = get_authorization();

    // Lock and unlock to ensure super keys are already created.
    auth_service
        .onDeviceLocked(user_id, &[bio_fake_sid1, bio_fake_sid2], WEAK_UNLOCK_DISABLED)
        .unwrap();
    auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();

    info!("trigger child process action A and wait for completion");
    child_handle.send(&Barrier::new(Some(user.gk_sid.unwrap())));
    child_handle.recv_or_die();

    info!("trigger child process action B and wait for completion");
    child_handle.send(&Barrier::new(None));
    let challenge = child_handle.recv_or_die().0.expect("no challenge");

    // Unlock with GK and the challenge to get a genuine per-op auth token
    let real_hat = user.gk_verify(challenge).expect("failed to perform GK verify");
    auth_service.addAuthToken(&real_hat).unwrap();

    info!("trigger child process action C and wait for completion");
    child_handle.send(&Barrier::new(None));
    child_handle.recv_or_die();

    assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
}

#[test]
fn test_auth_bound_per_op_with_gk_failure() {
    let bio_fake_sid1 = BIO_FAKE_SID_BASE + 7;
    let bio_fake_sid2 = BIO_FAKE_SID_BASE + 8;
    type Barrier = BarrierReachedWithData<Option<i64>>;
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keystore2_client_tests")
            .with_max_level(log::LevelFilter::Debug),
    );

    let child_fn = move |reader: &mut ChannelReader<Barrier>,
                         writer: &mut ChannelWriter<Barrier>|
          -> Result<(), run_as::Error> {
        // Now we're in a new process, wait to be notified before starting.
        let gk_sid: i64 = match reader.recv().0 {
            Some(sid) => sid,
            None => {
                // There is no AIDL Gatekeeper available, so abandon the test.  It would be nice to
                // know this before starting the child process, but finding it out requires Binder,
                // which can't be used until after the child has forked.
                return Ok(());
            }
        };

        // Action A: create a new auth-bound key which requires auth-per-operation (because
        // AUTH_TIMEOUT is not specified), and fail to finish an operation using it.
        let ks2 = get_keystore_service();
        let sec_level =
            ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).context("no TEE")?;
        let params = AuthSetBuilder::new()
            .user_secure_id(gk_sid)
            .user_secure_id(bio_fake_sid1)
            .user_auth_type(HardwareAuthenticatorType::ANY)
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
                    alias: Some("auth-per-op-2".to_string()),
                    blob: None,
                },
                None,
                &params,
                0,
                b"entropy",
            )
            .context("key generation failed")?;
        info!("A: created auth-per-op key {key:?} bound to sids {gk_sid}, {bio_fake_sid1}");

        // We can create an operation using the key...
        let params = AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
        let result = sec_level
            .createOperation(&key, &params, UNFORCED)
            .expect("failed to create auth-per-op operation");
        let op = result.iOperation.context("no operation in result")?;
        info!("A: created auth-per-op operation, got challenge {:?}", result.operationChallenge);

        // .. but attempting to finish the operation fails because Keystore can't find a HAT.
        let result = op.finish(Some(b"data"), None);
        expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
        info!("A: failed auth-per-op op (no HAT) as expected {result:?}");

        writer.send(&Barrier::new(None)); // A done.

        // Action B: fail again when an irrelevant HAT is available.
        reader.recv();

        let result = sec_level
            .createOperation(&key, &params, UNFORCED)
            .expect("failed to create auth-per-op operation");
        let op = result.iOperation.context("no operation in result")?;
        info!("B: created auth-per-op operation, got challenge {:?}", result.operationChallenge);
        // The operation fails because the HAT that Keystore received is not related to the
        // challenge.
        let result = op.finish(Some(b"data"), None);
        expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
        info!("B: failed auth-per-op op (HAT is not per-op) as expected {result:?}");

        writer.send(&Barrier::new(None)); // B done.

        // Action C: start an operation and pass out the challenge
        reader.recv();
        let result = sec_level
            .createOperation(&key, &params, UNFORCED)
            .expect("failed to create auth-per-op operation");
        let op = result.iOperation.context("no operation in result")?;
        info!("C: created auth-per-op operation, got challenge {:?}", result.operationChallenge);
        writer.send(&Barrier::new(Some(result.operationChallenge.unwrap().challenge))); // C done.

        // Action D: finishing the operation still fails because the per-op HAT
        // is invalid (the HMAC signature is faked and so the secure world
        // rejects the HAT).
        reader.recv();
        let result = op.finish(Some(b"data"), None);
        expect_km_error!(&result, ErrorCode::KEY_USER_NOT_AUTHENTICATED);
        info!("D: failed auth-per-op op (HAT is per-op but invalid) as expected {result:?}");
        writer.send(&Barrier::new(None)); // D done.

        Ok(())
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    let mut child_handle = unsafe {
        // Perform keystore actions while running as the test user.
        run_as::run_as_child_app(UID, UID, child_fn)
    }
    .unwrap();

    // Now that the separate process has been forked off, it's safe to use binder to setup a test
    // user.
    let _ks2 = get_keystore_service();
    let user = TestUser::new();
    if user.gk.is_none() {
        // Can't run this test if there's no AIDL Gatekeeper.
        child_handle.send(&Barrier::new(None));
        assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
        return;
    }
    let user_id = user.id;
    let auth_service = get_authorization();

    // Lock and unlock to ensure super keys are already created.
    auth_service
        .onDeviceLocked(user_id, &[bio_fake_sid1, bio_fake_sid2], WEAK_UNLOCK_DISABLED)
        .unwrap();
    auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();

    info!("trigger child process action A and wait for completion");
    let gk_sid = user.gk_sid.unwrap();
    child_handle.send(&Barrier::new(Some(gk_sid)));
    child_handle.recv_or_die();

    // Unlock with password and a fake auth token.
    auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
    auth_service.addAuthToken(&fake_lskf_token(gk_sid)).unwrap();

    info!("trigger child process action B and wait for completion");
    child_handle.send(&Barrier::new(None));
    child_handle.recv_or_die();

    info!("trigger child process action C and wait for completion");
    child_handle.send(&Barrier::new(None));
    let challenge = child_handle.recv_or_die().0.expect("no challenge");

    // Add a fake auth token with the challenge value.
    auth_service.addAuthToken(&fake_lskf_token_with_challenge(gk_sid, challenge)).unwrap();

    info!("trigger child process action D and wait for completion");
    child_handle.send(&Barrier::new(None));
    child_handle.recv_or_die();

    assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
}

#[test]
fn test_unlocked_device_required() {
    let gk_fake_sid = GK_FAKE_SID_BASE + 3;
    let bio_fake_sid1 = BIO_FAKE_SID_BASE + 9;
    let bio_fake_sid2 = BIO_FAKE_SID_BASE + 10;
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keystore2_client_tests")
            .with_max_level(log::LevelFilter::Debug),
    );

    let child_fn = move |reader: &mut ChannelReader<BarrierReached>,
                         writer: &mut ChannelWriter<BarrierReached>|
          -> Result<(), run_as::Error> {
        let ks2 = get_keystore_service();
        if ks2.getInterfaceVersion().unwrap() < 4 {
            // Assuming `IKeystoreAuthorization::onDeviceLocked` and
            // `IKeystoreAuthorization::onDeviceUnlocked` APIs will be supported on devices
            // with `IKeystoreService` >= 4.
            return Ok(());
        }

        // Now we're in a new process, wait to be notified before starting.
        reader.recv();

        // Action A: create a new unlocked-device-required key (which thus requires
        // super-encryption), while the device is unlocked.
        let sec_level =
            ks2.getSecurityLevel(SecurityLevel::TRUSTED_ENVIRONMENT).context("no TEE")?;
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
            .context("key generation failed")?;
        info!("A: created unlocked-device-required key while unlocked {key:?}");
        writer.send(&BarrierReached {}); // A done.

        // Action B: fail to use the unlocked-device-required key while locked.
        reader.recv();
        let params = AuthSetBuilder::new().purpose(KeyPurpose::SIGN).digest(Digest::SHA_2_256);
        let result = sec_level.createOperation(&key, &params, UNFORCED);
        info!("B: use unlocked-device-required key while locked => {result:?}");
        expect_km_error!(&result, ErrorCode::DEVICE_LOCKED);
        writer.send(&BarrierReached {}); // B done.

        // Action C: try to use the unlocked-device-required key while unlocked with a
        // password.
        reader.recv();
        let result = sec_level.createOperation(&key, &params, UNFORCED);
        info!("C: use unlocked-device-required key while lskf-unlocked => {result:?}");
        expect!(result.is_ok(), "failed with {result:?}");
        abort_op(result);
        writer.send(&BarrierReached {}); // C done.

        // Action D: try to use the unlocked-device-required key while unlocked with a weak
        // biometric.
        reader.recv();
        let result = sec_level.createOperation(&key, &params, UNFORCED);
        info!("D: use unlocked-device-required key while weak-locked => {result:?}");
        expect!(result.is_ok(), "createOperation failed: {result:?}");
        abort_op(result);
        writer.send(&BarrierReached {}); // D done.

        Ok(())
    };

    // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
    // `--test-threads=1`), and nothing yet done with binder.
    let mut child_handle = unsafe {
        // Perform keystore actions while running as the test user.
        run_as::run_as_child_app(UID, UID, child_fn)
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
    auth_service
        .onDeviceLocked(user_id, &[bio_fake_sid1, bio_fake_sid2], WEAK_UNLOCK_DISABLED)
        .unwrap();
    auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
    auth_service.addAuthToken(&fake_lskf_token(gk_fake_sid)).unwrap();

    info!("trigger child process action A while unlocked and wait for completion");
    child_handle.send(&BarrierReached {});
    child_handle.recv_or_die();

    // Move to locked and don't allow weak unlock, so super keys are wiped.
    auth_service
        .onDeviceLocked(user_id, &[bio_fake_sid1, bio_fake_sid2], WEAK_UNLOCK_DISABLED)
        .unwrap();

    info!("trigger child process action B while locked and wait for completion");
    child_handle.send(&BarrierReached {});
    child_handle.recv_or_die();

    // Unlock with password => loads super key from database.
    auth_service.onDeviceUnlocked(user_id, Some(SYNTHETIC_PASSWORD)).unwrap();
    auth_service.addAuthToken(&fake_lskf_token(gk_fake_sid)).unwrap();

    info!("trigger child process action C while lskf-unlocked and wait for completion");
    child_handle.send(&BarrierReached {});
    child_handle.recv_or_die();

    // Move to locked and allow weak unlock, then do a weak unlock.
    auth_service
        .onDeviceLocked(user_id, &[bio_fake_sid1, bio_fake_sid2], WEAK_UNLOCK_ENABLED)
        .unwrap();
    auth_service.onDeviceUnlocked(user_id, None).unwrap();

    info!("trigger child process action D while weak-unlocked and wait for completion");
    child_handle.send(&BarrierReached {});
    child_handle.recv_or_die();

    assert_eq!(child_handle.get_result(), Ok(()), "child process failed");
}

/// Generate a fake [`HardwareAuthToken`] for the given sid.
fn fake_lskf_token(gk_sid: i64) -> HardwareAuthToken {
    fake_lskf_token_with_challenge(gk_sid, 0)
}

/// Generate a fake [`HardwareAuthToken`] for the given sid and challenge.
fn fake_lskf_token_with_challenge(gk_sid: i64, challenge: i64) -> HardwareAuthToken {
    HardwareAuthToken {
        challenge,
        userId: gk_sid,
        authenticatorId: 0,
        authenticatorType: HardwareAuthenticatorType::PASSWORD,
        timestamp: Timestamp { milliSeconds: 123 },
        mac: vec![1, 2, 3],
    }
}

/// Generate a fake [`HardwareAuthToken`] for the given sids
fn fake_bio_lskf_token(gk_sid: i64, bio_sid: i64) -> HardwareAuthToken {
    HardwareAuthToken {
        challenge: 0,
        userId: gk_sid,
        authenticatorId: bio_sid,
        authenticatorType: HardwareAuthenticatorType::FINGERPRINT,
        timestamp: Timestamp { milliSeconds: 123 },
        mac: vec![1, 2, 3],
    }
}
