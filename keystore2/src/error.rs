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

//! Keystore error provides convenience methods and types for Keystore error handling.
//!
//! Here are some important types and helper functions:
//!
//! `Error` type encapsulate Keystore, Keymint, and Binder errors. It is used internally by
//! Keystore to diagnose error conditions that need to be reported to the client.
//!
//! `SerializedError` is used send error codes on the wire.
//!
//! `into_[logged_]binder` is a convenience method used to convert `anyhow::Error` into
//! `SerializedError` wire type.
//!
//! Keystore functions should use `anyhow::Result` to return error conditions, and context should
//! be added every time an error is forwarded.

pub use android_hardware_security_keymint::aidl::android::hardware::security::keymint::ErrorCode::ErrorCode;
use android_security_rkp_aidl::aidl::android::security::rkp::IGetKeyCallback::ErrorCode::ErrorCode as GetKeyErrorCode;
pub use android_system_keystore2::aidl::android::system::keystore2::ResponseCode::ResponseCode;
use android_system_keystore2::binder::{
    ExceptionCode, Result as BinderResult, Status as BinderStatus, StatusCode,
};
use keystore2_selinux as selinux;
use rkpd_client::Error as RkpdError;
use std::cmp::PartialEq;
use std::ffi::CString;

#[cfg(test)]
pub mod tests;

/// This is the main Keystore error type. It wraps the Keystore `ResponseCode` generated
/// from AIDL in the `Rc` variant and Keymint `ErrorCode` in the Km variant.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Wraps a Keystore `ResponseCode` as defined by the Keystore AIDL interface specification.
    #[error("Error::Rc({0:?})")]
    Rc(ResponseCode),
    /// Wraps a Keymint `ErrorCode` as defined by the Keymint AIDL interface specification.
    #[error("Error::Km({0:?})")]
    Km(ErrorCode),
    /// Wraps a Binder exception code other than a service specific exception.
    #[error("Binder exception code {0:?}, {1:?}")]
    Binder(ExceptionCode, i32),
    /// Wraps a Binder status code.
    #[error("Binder transaction error {0:?}")]
    BinderTransaction(StatusCode),
}

impl Error {
    /// Short hand for `Error::Rc(ResponseCode::SYSTEM_ERROR)`
    pub fn sys() -> Self {
        Error::Rc(ResponseCode::SYSTEM_ERROR)
    }

    /// Short hand for `Error::Rc(ResponseCode::PERMISSION_DENIED)`
    pub fn perm() -> Self {
        Error::Rc(ResponseCode::PERMISSION_DENIED)
    }
}

impl From<RkpdError> for Error {
    fn from(e: RkpdError) -> Self {
        match e {
            RkpdError::RequestCancelled | RkpdError::GetRegistrationFailed => {
                Error::Rc(ResponseCode::OUT_OF_KEYS_TRANSIENT_ERROR)
            }
            RkpdError::GetKeyFailed(e) => {
                let response_code = match e {
                    GetKeyErrorCode::ERROR_UNKNOWN => ResponseCode::OUT_OF_KEYS_TRANSIENT_ERROR,
                    GetKeyErrorCode::ERROR_PERMANENT => ResponseCode::OUT_OF_KEYS_PERMANENT_ERROR,
                    GetKeyErrorCode::ERROR_PENDING_INTERNET_CONNECTIVITY => {
                        ResponseCode::OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY
                    }
                    GetKeyErrorCode::ERROR_REQUIRES_SECURITY_PATCH => {
                        ResponseCode::OUT_OF_KEYS_REQUIRES_SYSTEM_UPGRADE
                    }
                    _ => {
                        log::error!("Unexpected get key error from rkpd: {e:?}");
                        ResponseCode::OUT_OF_KEYS_TRANSIENT_ERROR
                    }
                };
                Error::Rc(response_code)
            }
            RkpdError::RetryableTimeout => Error::Rc(ResponseCode::OUT_OF_KEYS_TRANSIENT_ERROR),
            RkpdError::StoreUpgradedKeyFailed | RkpdError::Timeout => {
                Error::Rc(ResponseCode::SYSTEM_ERROR)
            }
            RkpdError::BinderTransaction(s) => Error::BinderTransaction(s),
        }
    }
}

/// Maps an `rkpd_client::Error` that is wrapped with an `anyhow::Error` to a keystore2 `Error`.
pub fn wrapped_rkpd_error_to_ks_error(e: &anyhow::Error) -> Error {
    match e.downcast_ref::<RkpdError>() {
        Some(e) => Error::from(*e),
        None => {
            log::error!("Failed to downcast the anyhow::Error to rkpd_client::Error: {e:?}");
            Error::Rc(ResponseCode::SYSTEM_ERROR)
        }
    }
}

/// Helper function to map the binder status we get from calls into KeyMint
/// to a Keystore Error. We don't create an anyhow error here to make
/// it easier to evaluate KeyMint errors, which we must do in some cases, e.g.,
/// when diagnosing authentication requirements, update requirements, and running
/// out of operation slots.
pub fn map_km_error<T>(r: BinderResult<T>) -> Result<T, Error> {
    r.map_err(|s| {
        match s.exception_code() {
            ExceptionCode::SERVICE_SPECIFIC => {
                let se = s.service_specific_error();
                if se < 0 {
                    // Negative service specific errors are KM error codes.
                    Error::Km(ErrorCode(s.service_specific_error()))
                } else {
                    // Non negative error codes cannot be KM error codes.
                    // So we create an `Error::Binder` variant to preserve
                    // the service specific error code for logging.
                    Error::Binder(ExceptionCode::SERVICE_SPECIFIC, se)
                }
            }
            // We create `Error::Binder` to preserve the exception code
            // for logging.
            e_code => Error::Binder(e_code, 0),
        }
    })
}

/// This function is similar to map_km_error only that we don't expect
/// any KeyMint error codes, we simply preserve the exception code and optional
/// service specific exception.
pub fn map_binder_status<T>(r: BinderResult<T>) -> Result<T, Error> {
    r.map_err(|s| match s.exception_code() {
        ExceptionCode::SERVICE_SPECIFIC => {
            let se = s.service_specific_error();
            Error::Binder(ExceptionCode::SERVICE_SPECIFIC, se)
        }
        ExceptionCode::TRANSACTION_FAILED => {
            let e = s.transaction_error();
            Error::BinderTransaction(e)
        }
        e_code => Error::Binder(e_code, 0),
    })
}

/// This function maps a status code onto a Keystore Error.
pub fn map_binder_status_code<T>(r: Result<T, StatusCode>) -> Result<T, Error> {
    r.map_err(Error::BinderTransaction)
}

/// Convert an [`anyhow::Error`] to a [`binder::Status`], logging the value
/// along the way (except if it is `KEY_NOT_FOUND`).
pub fn into_logged_binder(e: anyhow::Error) -> BinderStatus {
    // Log everything except key not found.
    if !matches!(
        e.root_cause().downcast_ref::<Error>(),
        Some(Error::Rc(ResponseCode::KEY_NOT_FOUND))
    ) {
        log::error!("{:?}", e);
    }
    into_binder(e)
}

/// This function turns an anyhow error into an optional CString.
/// This is especially useful to add a message string to a service specific error.
/// If the formatted string was not convertible because it contained a nul byte,
/// None is returned and a warning is logged.
pub fn anyhow_error_to_cstring(e: &anyhow::Error) -> Option<CString> {
    match CString::new(format!("{:?}", e)) {
        Ok(msg) => Some(msg),
        Err(_) => {
            log::warn!("Cannot convert error message to CStr. It contained a nul byte.");
            None
        }
    }
}

/// Convert an [`anyhow::Error`] to a [`binder::Status`].
pub fn into_binder(e: anyhow::Error) -> binder::Status {
    let rc = anyhow_error_to_serialized_error(&e);
    BinderStatus::new_service_specific_error(rc.0, anyhow_error_to_cstring(&e).as_deref())
}

/// This type is used to send error codes on the wire.
///
/// Errors are squashed into one number space using following rules:
/// - All Keystore and Keymint errors codes are identity mapped. It's possible because by
///   convention Keystore `ResponseCode` errors are positive, and Keymint `ErrorCode` errors are
///   negative.
/// - `selinux::Error::PermissionDenied` is mapped to `ResponseCode::PERMISSION_DENIED`.
/// - All other error conditions, e.g. Binder errors, are mapped to `ResponseCode::SYSTEM_ERROR`.
///
/// The type should be used to forward all error codes to clients of Keystore AIDL interface and to
/// metrics events.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct SerializedError(pub i32);

/// Returns a SerializedError given a reference to Error.
pub fn error_to_serialized_error(e: &Error) -> SerializedError {
    match e {
        Error::Rc(rcode) => SerializedError(rcode.0),
        Error::Km(ec) => SerializedError(ec.0),
        // Binder errors are reported as system error.
        Error::Binder(_, _) | Error::BinderTransaction(_) => {
            SerializedError(ResponseCode::SYSTEM_ERROR.0)
        }
    }
}

/// Returns a SerializedError given a reference to anyhow::Error.
pub fn anyhow_error_to_serialized_error(e: &anyhow::Error) -> SerializedError {
    let root_cause = e.root_cause();
    match root_cause.downcast_ref::<Error>() {
        Some(e) => error_to_serialized_error(e),
        None => match root_cause.downcast_ref::<selinux::Error>() {
            Some(selinux::Error::PermissionDenied) => {
                SerializedError(ResponseCode::PERMISSION_DENIED.0)
            }
            _ => SerializedError(ResponseCode::SYSTEM_ERROR.0),
        },
    }
}
