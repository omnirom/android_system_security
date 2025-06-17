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

use crate::metrics_store::*;
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    HardwareAuthenticatorType::HardwareAuthenticatorType as AuthType, KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel, Tag::Tag,
};
use android_security_metrics::aidl::android::security::metrics::{
    HardwareAuthenticatorType::HardwareAuthenticatorType as MetricsAuthType,
    SecurityLevel::SecurityLevel as MetricsSecurityLevel,
};

#[test]
fn test_enum_show() {
    let algo = MetricsAlgorithm::RSA;
    assert_eq!("RSA ", algo.show());
    let algo = MetricsAlgorithm(42);
    assert_eq!("Unknown(42)", algo.show());
}

#[test]
fn test_enum_bitmask_show() {
    let mut modes = 0i32;
    compute_block_mode_bitmap(&mut modes, BlockMode::ECB);
    compute_block_mode_bitmap(&mut modes, BlockMode::CTR);

    assert_eq!(show_blockmode(modes), "-T-E");

    // Add some bits not covered by the enum of valid bit positions.
    modes |= 0xa0;
    assert_eq!(show_blockmode(modes), "-T-E(full:0x000000aa)");
    modes |= 0x300;
    assert_eq!(show_blockmode(modes), "-T-E(full:0x000003aa)");
}

fn create_key_param_with_auth_type(auth_type: AuthType) -> KeyParameter {
    KeyParameter {
        tag: Tag::USER_AUTH_TYPE,
        value: KeyParameterValue::HardwareAuthenticatorType(auth_type),
    }
}

#[test]
fn test_user_auth_type() {
    let test_cases = [
        (vec![], MetricsAuthType::NO_AUTH_TYPE),
        (vec![AuthType::NONE], MetricsAuthType::NONE),
        (vec![AuthType::PASSWORD], MetricsAuthType::PASSWORD),
        (vec![AuthType::FINGERPRINT], MetricsAuthType::FINGERPRINT),
        (
            vec![AuthType(AuthType::PASSWORD.0 | AuthType::FINGERPRINT.0)],
            MetricsAuthType::PASSWORD_OR_FINGERPRINT,
        ),
        (vec![AuthType::ANY], MetricsAuthType::ANY),
        // 7 is the "next" undefined HardwareAuthenticatorType enum tag number, so
        // force this test to fail and be updated if someone adds a new enum value.
        (vec![AuthType(7)], MetricsAuthType::AUTH_TYPE_UNSPECIFIED),
        (vec![AuthType(123)], MetricsAuthType::AUTH_TYPE_UNSPECIFIED),
        (
            // In practice, Tag::USER_AUTH_TYPE isn't a repeatable tag. It's allowed
            // to appear once for auth-bound keys and contains the binary OR of the
            // applicable auth types. However, this test case repeats the tag more
            // than once in order to unit test the logic that constructs the atom.
            vec![AuthType::ANY, AuthType(123), AuthType::PASSWORD],
            // The last auth type wins.
            MetricsAuthType::PASSWORD,
        ),
    ];
    for (auth_types, expected) in test_cases {
        let key_params: Vec<_> =
            auth_types.iter().map(|a| create_key_param_with_auth_type(*a)).collect();
        let (_, atom_with_auth_info, _) = process_key_creation_event_stats(
            SecurityLevel::TRUSTED_ENVIRONMENT,
            &key_params,
            &Ok(()),
        );
        assert!(matches!(
            atom_with_auth_info,
            KeystoreAtomPayload::KeyCreationWithAuthInfo(a) if a.user_auth_type == expected
        ));
    }
}

fn create_key_param_with_auth_timeout(timeout: i32) -> KeyParameter {
    KeyParameter { tag: Tag::AUTH_TIMEOUT, value: KeyParameterValue::Integer(timeout) }
}

#[test]
fn test_log_auth_timeout_seconds() {
    let test_cases = [
        (vec![], -1),
        (vec![-1], 0),
        // The metrics code computes the value of this field for a timeout `t` with
        // `f32::log10(t as f32) as i32`. The result of f32::log10(0 as f32) is `-inf`.
        // Casting this to i32 means it gets "rounded" to i32::MIN, which is -2147483648.
        (vec![0], -2147483648),
        (vec![1], 0),
        (vec![9], 0),
        (vec![10], 1),
        (vec![999], 2),
        (
            // In practice, Tag::AUTH_TIMEOUT isn't a repeatable tag. It's allowed to
            // appear once for auth-bound keys. However, this test case repeats the
            // tag more than once in order to unit test the logic that constructs the
            // atom.
            vec![1, 0, 10],
            // The last timeout wins.
            1,
        ),
    ];
    for (timeouts, expected) in test_cases {
        let key_params: Vec<_> =
            timeouts.iter().map(|t| create_key_param_with_auth_timeout(*t)).collect();
        let (_, atom_with_auth_info, _) = process_key_creation_event_stats(
            SecurityLevel::TRUSTED_ENVIRONMENT,
            &key_params,
            &Ok(()),
        );
        assert!(matches!(
            atom_with_auth_info,
            KeystoreAtomPayload::KeyCreationWithAuthInfo(a)
                if a.log10_auth_key_timeout_seconds == expected
        ));
    }
}

#[test]
fn test_security_level() {
    let test_cases = [
        (SecurityLevel::SOFTWARE, MetricsSecurityLevel::SECURITY_LEVEL_SOFTWARE),
        (
            SecurityLevel::TRUSTED_ENVIRONMENT,
            MetricsSecurityLevel::SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
        ),
        (SecurityLevel::STRONGBOX, MetricsSecurityLevel::SECURITY_LEVEL_STRONGBOX),
        (SecurityLevel::KEYSTORE, MetricsSecurityLevel::SECURITY_LEVEL_KEYSTORE),
        (SecurityLevel(123), MetricsSecurityLevel::SECURITY_LEVEL_UNSPECIFIED),
    ];
    for (security_level, expected) in test_cases {
        let (_, atom_with_auth_info, _) =
            process_key_creation_event_stats(security_level, &[], &Ok(()));
        assert!(matches!(
            atom_with_auth_info,
            KeystoreAtomPayload::KeyCreationWithAuthInfo(a)
                if a.security_level == expected
        ));
    }
}
