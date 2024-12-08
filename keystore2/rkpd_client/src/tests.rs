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

//! RKPD tests.

use super::*;
use android_security_rkp_aidl::aidl::android::security::rkp::IRegistration::BnRegistration;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

const DEFAULT_RPC_SERVICE_NAME: &str =
    "android.hardware.security.keymint.IRemotelyProvisionedComponent/default";

struct MockRegistrationValues {
    key: RemotelyProvisionedKey,
    latency: Option<Duration>,
    thread_join_handles: Vec<Option<std::thread::JoinHandle<()>>>,
}

struct MockRegistration(Arc<Mutex<MockRegistrationValues>>);

impl MockRegistration {
    pub fn new_native_binder(
        key: &RemotelyProvisionedKey,
        latency: Option<Duration>,
    ) -> Strong<dyn IRegistration> {
        let result = Self(Arc::new(Mutex::new(MockRegistrationValues {
            key: RemotelyProvisionedKey {
                keyBlob: key.keyBlob.clone(),
                encodedCertChain: key.encodedCertChain.clone(),
            },
            latency,
            thread_join_handles: Vec::new(),
        })));
        BnRegistration::new_binder(result, BinderFeatures::default())
    }
}

impl Drop for MockRegistration {
    fn drop(&mut self) {
        let mut values = self.0.lock().unwrap();
        for handle in values.thread_join_handles.iter_mut() {
            // These are test threads. So, no need to worry too much about error handling.
            handle.take().unwrap().join().unwrap();
        }
    }
}

impl Interface for MockRegistration {}

impl IRegistration for MockRegistration {
    fn getKey(&self, _: i32, cb: &Strong<dyn IGetKeyCallback>) -> binder::Result<()> {
        let mut values = self.0.lock().unwrap();
        let key = RemotelyProvisionedKey {
            keyBlob: values.key.keyBlob.clone(),
            encodedCertChain: values.key.encodedCertChain.clone(),
        };
        let latency = values.latency;
        let get_key_cb = cb.clone();

        // Need a separate thread to trigger timeout in the caller.
        let join_handle = std::thread::spawn(move || {
            if let Some(duration) = latency {
                std::thread::sleep(duration);
            }
            get_key_cb.onSuccess(&key).unwrap();
        });
        values.thread_join_handles.push(Some(join_handle));
        Ok(())
    }

    fn cancelGetKey(&self, _: &Strong<dyn IGetKeyCallback>) -> binder::Result<()> {
        Ok(())
    }

    fn storeUpgradedKeyAsync(
        &self,
        _: &[u8],
        _: &[u8],
        cb: &Strong<dyn IStoreUpgradedKeyCallback>,
    ) -> binder::Result<()> {
        // We are primarily concerned with timing out correctly. Storing the key in this mock
        // registration isn't particularly interesting, so skip that part.
        let values = self.0.lock().unwrap();
        let store_cb = cb.clone();
        let latency = values.latency;

        std::thread::spawn(move || {
            if let Some(duration) = latency {
                std::thread::sleep(duration);
            }
            store_cb.onSuccess().unwrap();
        });
        Ok(())
    }
}

fn get_mock_registration(
    key: &RemotelyProvisionedKey,
    latency: Option<Duration>,
) -> Result<binder::Strong<dyn IRegistration>> {
    let (tx, rx) = oneshot::channel();
    let cb = GetRegistrationCallback::new_native_binder(tx);
    let mock_registration = MockRegistration::new_native_binder(key, latency);

    assert!(cb.onSuccess(&mock_registration).is_ok());
    tokio_rt().block_on(rx).unwrap()
}

// Using the same key ID makes test cases race with each other. So, we use separate key IDs for
// different test cases.
fn get_next_key_id() -> u32 {
    static ID: AtomicU32 = AtomicU32::new(0);
    ID.fetch_add(1, Ordering::Relaxed)
}

#[test]
fn test_get_registration_cb_success() {
    let key: RemotelyProvisionedKey = Default::default();
    let registration = get_mock_registration(&key, /*latency=*/ None);
    assert!(registration.is_ok());
}

#[test]
fn test_get_registration_cb_cancel() {
    let (tx, rx) = oneshot::channel();
    let cb = GetRegistrationCallback::new_native_binder(tx);
    assert!(cb.onCancel().is_ok());

    let result = tokio_rt().block_on(rx).unwrap();
    assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::RequestCancelled);
}

#[test]
fn test_get_registration_cb_error() {
    let (tx, rx) = oneshot::channel();
    let cb = GetRegistrationCallback::new_native_binder(tx);
    assert!(cb.onError("error").is_ok());

    let result = tokio_rt().block_on(rx).unwrap();
    assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::GetRegistrationFailed);
}

#[test]
fn test_get_key_cb_success() {
    let mock_key =
        RemotelyProvisionedKey { keyBlob: vec![1, 2, 3], encodedCertChain: vec![4, 5, 6] };
    let (tx, rx) = oneshot::channel();
    let cb = GetKeyCallback::new_native_binder(tx);
    assert!(cb.onSuccess(&mock_key).is_ok());

    let key = tokio_rt().block_on(rx).unwrap().unwrap();
    assert_eq!(key, mock_key);
}

#[test]
fn test_get_key_cb_cancel() {
    let (tx, rx) = oneshot::channel();
    let cb = GetKeyCallback::new_native_binder(tx);
    assert!(cb.onCancel().is_ok());

    let result = tokio_rt().block_on(rx).unwrap();
    assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::RequestCancelled);
}

#[test]
fn test_get_key_cb_error() {
    for get_key_error in GetKeyErrorCode::enum_values() {
        let (tx, rx) = oneshot::channel();
        let cb = GetKeyCallback::new_native_binder(tx);
        assert!(cb.onError(get_key_error, "error").is_ok());

        let result = tokio_rt().block_on(rx).unwrap();
        assert_eq!(
            result.unwrap_err().downcast::<Error>().unwrap(),
            Error::GetKeyFailed(get_key_error),
        );
    }
}

#[test]
fn test_store_upgraded_cb_success() {
    let (tx, rx) = oneshot::channel();
    let cb = StoreUpgradedKeyCallback::new_native_binder(tx);
    assert!(cb.onSuccess().is_ok());

    tokio_rt().block_on(rx).unwrap().unwrap();
}

#[test]
fn test_store_upgraded_key_cb_error() {
    let (tx, rx) = oneshot::channel();
    let cb = StoreUpgradedKeyCallback::new_native_binder(tx);
    assert!(cb.onError("oh no! it failed").is_ok());

    let result = tokio_rt().block_on(rx).unwrap();
    assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::StoreUpgradedKeyFailed);
}

#[test]
fn test_get_mock_key_success() {
    let mock_key =
        RemotelyProvisionedKey { keyBlob: vec![1, 2, 3], encodedCertChain: vec![4, 5, 6] };
    let registration = get_mock_registration(&mock_key, /*latency=*/ None).unwrap();

    let key = tokio_rt()
        .block_on(get_rkpd_attestation_key_from_registration_async(&registration, 0))
        .unwrap();
    assert_eq!(key, mock_key);
}

#[test]
fn test_get_mock_key_timeout() {
    let mock_key =
        RemotelyProvisionedKey { keyBlob: vec![1, 2, 3], encodedCertChain: vec![4, 5, 6] };
    let latency = RKPD_TIMEOUT + Duration::from_secs(1);
    let registration = get_mock_registration(&mock_key, Some(latency)).unwrap();

    let result =
        tokio_rt().block_on(get_rkpd_attestation_key_from_registration_async(&registration, 0));
    assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::RetryableTimeout);
}

#[test]
fn test_store_mock_key_success() {
    let mock_key =
        RemotelyProvisionedKey { keyBlob: vec![1, 2, 3], encodedCertChain: vec![4, 5, 6] };
    let registration = get_mock_registration(&mock_key, /*latency=*/ None).unwrap();
    tokio_rt()
        .block_on(store_rkpd_attestation_key_with_registration_async(&registration, &[], &[]))
        .unwrap();
}

#[test]
fn test_store_mock_key_timeout() {
    let mock_key =
        RemotelyProvisionedKey { keyBlob: vec![1, 2, 3], encodedCertChain: vec![4, 5, 6] };
    let latency = RKPD_TIMEOUT + Duration::from_secs(1);
    let registration = get_mock_registration(&mock_key, Some(latency)).unwrap();

    let result = tokio_rt().block_on(store_rkpd_attestation_key_with_registration_async(
        &registration,
        &[],
        &[],
    ));
    assert_eq!(result.unwrap_err().downcast::<Error>().unwrap(), Error::Timeout);
}

#[test]
fn test_get_rkpd_attestation_key() {
    binder::ProcessState::start_thread_pool();
    let key_id = get_next_key_id();
    let key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();
    assert!(!key.keyBlob.is_empty());
    assert!(!key.encodedCertChain.is_empty());
}

#[test]
fn test_get_rkpd_attestation_key_same_caller() {
    binder::ProcessState::start_thread_pool();
    let key_id = get_next_key_id();

    // Multiple calls should return the same key.
    let first_key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();
    let second_key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();

    assert_eq!(first_key.keyBlob, second_key.keyBlob);
    assert_eq!(first_key.encodedCertChain, second_key.encodedCertChain);
}

#[test]
fn test_get_rkpd_attestation_key_different_caller() {
    binder::ProcessState::start_thread_pool();
    let first_key_id = get_next_key_id();
    let second_key_id = get_next_key_id();

    // Different callers should be getting different keys.
    let first_key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, first_key_id).unwrap();
    let second_key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, second_key_id).unwrap();

    assert_ne!(first_key.keyBlob, second_key.keyBlob);
    assert_ne!(first_key.encodedCertChain, second_key.encodedCertChain);
}

#[test]
// Couple of things to note:
// 1. This test must never run with UID of keystore. Otherwise, it can mess up keys stored by
//    keystore.
// 2. Storing and reading the stored key is prone to race condition. So, we only do this in one
//    test case.
fn test_store_rkpd_attestation_key() {
    binder::ProcessState::start_thread_pool();
    let key_id = get_next_key_id();
    let key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();
    let new_blob: [u8; 8] = rand::random();

    assert!(store_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, &key.keyBlob, &new_blob).is_ok());

    let new_key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();

    // Restore original key so that we don't leave RKPD with invalid blobs.
    assert!(store_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, &new_blob, &key.keyBlob).is_ok());
    assert_eq!(new_key.keyBlob, new_blob);
}

#[test]
fn test_stress_get_rkpd_attestation_key() {
    binder::ProcessState::start_thread_pool();
    let key_id = get_next_key_id();
    let mut threads = vec![];
    const NTHREADS: u32 = 10;
    const NCALLS: u32 = 1000;

    for _ in 0..NTHREADS {
        threads.push(std::thread::spawn(move || {
            for _ in 0..NCALLS {
                let key = get_rkpd_attestation_key(DEFAULT_RPC_SERVICE_NAME, key_id).unwrap();
                assert!(!key.keyBlob.is_empty());
                assert!(!key.encodedCertChain.is_empty());
            }
        }));
    }

    for t in threads {
        assert!(t.join().is_ok());
    }
}
