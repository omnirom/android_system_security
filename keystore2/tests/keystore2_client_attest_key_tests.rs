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
    app_attest_key_feature_exists, device_id_attestation_feature_exists, get_attest_id_value,
    is_second_imei_id_attestation_required, skip_device_id_attest_tests,
};
use crate::{
    skip_device_id_attestation_tests, skip_test_if_no_app_attest_key_feature,
    skip_test_if_no_device_id_attestation_feature,
};
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
    ErrorCode::ErrorCode, KeyPurpose::KeyPurpose, PaddingMode::PaddingMode,
    SecurityLevel::SecurityLevel, Tag::Tag,
};
use android_system_keystore2::aidl::android::system::keystore2::{
    Domain::Domain, IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
    ResponseCode::ResponseCode,
};
use keystore2_test_utils::ffi_test_utils::{get_value_from_attest_record, validate_certchain};
use keystore2_test_utils::{
    authorizations, key_generations, key_generations::Error, run_as, SecLevel,
};
use nix::unistd::{getuid, Gid, Uid};
use rustutils::users::AID_USER_OFFSET;

/// Generate RSA and EC attestation keys and use them for signing RSA-signing keys.
/// Test should be able to generate attestation keys and use them successfully.
#[test]
fn keystore2_attest_rsa_signing_key_success() {
    skip_test_if_no_app_attest_key_feature!();

    let sl = SecLevel::tee();
    let att_challenge: &[u8] = b"foo";

    for algo in [Algorithm::RSA, Algorithm::EC] {
        // Create attestation key.
        let Some(attestation_key_metadata) = key_generations::map_ks_error(
            key_generations::generate_attestation_key(&sl, algo, att_challenge),
        )
        .unwrap() else {
            return;
        };

        let mut cert_chain: Vec<u8> = Vec::new();
        cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
        cert_chain.extend(attestation_key_metadata.certificateChain.as_ref().unwrap());
        validate_certchain(&cert_chain).expect("Error while validating cert chain.");

        // Create RSA signing key and use attestation key to sign it.
        let sign_key_alias = format!("ks_attest_rsa_signing_key_{}", getuid());
        let Some(sign_key_metadata) = key_generations::generate_rsa_key(
            &sl,
            Domain::APP,
            -1,
            Some(sign_key_alias),
            &key_generations::KeyParams {
                key_size: 2048,
                purpose: vec![KeyPurpose::SIGN, KeyPurpose::VERIFY],
                padding: Some(PaddingMode::RSA_PKCS1_1_5_SIGN),
                digest: Some(Digest::SHA_2_256),
                mgf_digest: None,
                block_mode: None,
                att_challenge: Some(att_challenge.to_vec()),
            },
            Some(&attestation_key_metadata.key),
        )
        .unwrap() else {
            return;
        };

        let mut cert_chain: Vec<u8> = Vec::new();
        cert_chain.extend(sign_key_metadata.certificate.as_ref().unwrap());
        cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
        cert_chain.extend(attestation_key_metadata.certificateChain.as_ref().unwrap());
        validate_certchain(&cert_chain).expect("Error while validating cert chain");
    }
}

/// Generate RSA and EC attestation keys and use them for signing RSA encrypt/decrypt keys.
/// Test should be able to generate attestation keys and use them successfully.
#[test]
fn keystore2_attest_rsa_encrypt_key_success() {
    skip_test_if_no_app_attest_key_feature!();

    let sl = SecLevel::tee();
    let att_challenge: &[u8] = b"foo";

    for algo in [Algorithm::RSA, Algorithm::EC] {
        // Create attestation key.
        let Some(attestation_key_metadata) = key_generations::map_ks_error(
            key_generations::generate_attestation_key(&sl, algo, att_challenge),
        )
        .unwrap() else {
            return;
        };

        let mut cert_chain: Vec<u8> = Vec::new();
        cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
        cert_chain.extend(attestation_key_metadata.certificateChain.as_ref().unwrap());
        validate_certchain(&cert_chain).expect("Error while validating cert chain.");

        // Create RSA encrypt/decrypt key and use attestation key to sign it.
        let decrypt_key_alias = format!("ks_attest_rsa_encrypt_key_{}", getuid());
        let Some(decrypt_key_metadata) = key_generations::generate_rsa_key(
            &sl,
            Domain::APP,
            -1,
            Some(decrypt_key_alias),
            &key_generations::KeyParams {
                key_size: 2048,
                purpose: vec![KeyPurpose::ENCRYPT, KeyPurpose::DECRYPT],
                padding: Some(PaddingMode::RSA_PKCS1_1_5_ENCRYPT),
                digest: Some(Digest::SHA_2_256),
                mgf_digest: None,
                block_mode: None,
                att_challenge: Some(att_challenge.to_vec()),
            },
            Some(&attestation_key_metadata.key),
        )
        .unwrap() else {
            return;
        };

        let mut cert_chain: Vec<u8> = Vec::new();
        cert_chain.extend(decrypt_key_metadata.certificate.as_ref().unwrap());
        cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
        cert_chain.extend(attestation_key_metadata.certificateChain.as_ref().unwrap());

        validate_certchain(&cert_chain).expect("Error while validating cert chain.");
    }
}

/// Generate RSA and EC attestation keys and use them for signing EC keys.
/// Test should be able to generate attestation keys and use them successfully.
#[test]
fn keystore2_attest_ec_key_success() {
    skip_test_if_no_app_attest_key_feature!();

    let sl = SecLevel::tee();
    let att_challenge: &[u8] = b"foo";

    for algo in [Algorithm::RSA, Algorithm::EC] {
        // Create attestation key.
        let Some(attestation_key_metadata) = key_generations::map_ks_error(
            key_generations::generate_attestation_key(&sl, algo, att_challenge),
        )
        .unwrap() else {
            return;
        };

        let mut cert_chain: Vec<u8> = Vec::new();
        cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
        cert_chain.extend(attestation_key_metadata.certificateChain.as_ref().unwrap());
        validate_certchain(&cert_chain).expect("Error while validating cert chain.");

        // Create EC key and use attestation key to sign it.
        let ec_key_alias = format!("ks_ec_attested_test_key_{}", getuid());
        let ec_key_metadata = key_generations::generate_ec_256_attested_key(
            &sl,
            Some(ec_key_alias),
            att_challenge,
            &attestation_key_metadata.key,
        )
        .unwrap();

        let mut cert_chain: Vec<u8> = Vec::new();
        cert_chain.extend(ec_key_metadata.certificate.as_ref().unwrap());
        cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
        cert_chain.extend(attestation_key_metadata.certificateChain.as_ref().unwrap());

        validate_certchain(&cert_chain).expect("Error while validating cert chain.");
    }
}

/// Generate EC-CURVE_25519 attestation key and use it for signing RSA-signing keys.
/// Test should be able to generate RSA signing key with EC-CURVE_25519 as attestation key
/// successfully.
#[test]
fn keystore2_attest_rsa_signing_key_with_ec_25519_key_success() {
    skip_test_if_no_app_attest_key_feature!();

    let sl = SecLevel::tee();
    if sl.get_keymint_version() < 2 {
        // Curve 25519 was included in version 2 of the KeyMint interface.
        // For device with KeyMint-V1 or Keymaster in backend, emulated Ed25519 key can't attest
        // to a "real" RSA key.
        return;
    }

    let att_challenge: &[u8] = b"foo";

    // Create EcCurve::CURVE_25519 attestation key.
    let Some(attestation_key_metadata) =
        key_generations::map_ks_error(key_generations::generate_ec_attestation_key(
            &sl,
            att_challenge,
            Digest::NONE,
            EcCurve::CURVE_25519,
        ))
        .unwrap()
    else {
        return;
    };

    let mut cert_chain: Vec<u8> = Vec::new();
    cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
    cert_chain.extend(attestation_key_metadata.certificateChain.as_ref().unwrap());
    validate_certchain(&cert_chain).expect("Error while validating cert chain.");

    // Create RSA signing key and use attestation key to sign it.
    let sign_key_alias = format!("ksrsa_attested_sign_test_key_{}", getuid());
    let Some(sign_key_metadata) = key_generations::generate_rsa_key(
        &sl,
        Domain::APP,
        -1,
        Some(sign_key_alias),
        &key_generations::KeyParams {
            key_size: 2048,
            purpose: vec![KeyPurpose::SIGN, KeyPurpose::VERIFY],
            padding: Some(PaddingMode::RSA_PKCS1_1_5_SIGN),
            digest: Some(Digest::SHA_2_256),
            mgf_digest: None,
            block_mode: None,
            att_challenge: Some(att_challenge.to_vec()),
        },
        Some(&attestation_key_metadata.key),
    )
    .unwrap() else {
        return;
    };

    let mut cert_chain: Vec<u8> = Vec::new();
    cert_chain.extend(sign_key_metadata.certificate.as_ref().unwrap());
    cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
    cert_chain.extend(attestation_key_metadata.certificateChain.as_ref().unwrap());
    validate_certchain(&cert_chain).expect("Error while validating cert chain");
}

/// Try to generate RSA attestation key with multiple purposes. Test should fail with error code
/// `INCOMPATIBLE_PURPOSE` to generate an attestation key.
#[test]
fn keystore2_generate_rsa_attest_key_with_multi_purpose_fail() {
    skip_test_if_no_app_attest_key_feature!();
    let sl = SecLevel::tee();
    if sl.get_keymint_version() < 2 {
        // The KeyMint v1 spec required that KeyPurpose::ATTEST_KEY not be combined
        // with other key purposes.  However, this was not checked at the time
        // so we can only be strict about checking this for implementations of KeyMint
        // version 2 and above.
        return;
    }

    let digest = Digest::SHA_2_256;
    let padding = PaddingMode::RSA_PKCS1_1_5_SIGN;
    let key_size = 2048;

    let attest_key_alias =
        format!("ksrsa_attest_multipurpose_key_{}{}{}", getuid(), key_size, digest.0);

    let attest_gen_params = authorizations::AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::RSA)
        .purpose(KeyPurpose::ATTEST_KEY)
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .digest(digest)
        .key_size(key_size)
        .rsa_public_exponent(65537)
        .padding_mode(padding);

    let result = key_generations::map_ks_error(sl.binder.generateKey(
        &KeyDescriptor {
            domain: Domain::APP,
            nspace: -1,
            alias: Some(attest_key_alias),
            blob: None,
        },
        None,
        &attest_gen_params,
        0,
        b"entropy",
    ));
    assert!(result.is_err());
    assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_PURPOSE), result.unwrap_err());
}

/// Try to generate EC attestation key with multiple purposes. Test should fail with error code
/// `INCOMPATIBLE_PURPOSE` to generate an attestation key.
#[test]
fn keystore2_ec_attest_key_with_multi_purpose_fail() {
    skip_test_if_no_app_attest_key_feature!();
    let sl = SecLevel::tee();
    if sl.get_keymint_version() < 2 {
        // The KeyMint v1 spec required that KeyPurpose::ATTEST_KEY not be combined
        // with other key purposes.  However, this was not checked at the time
        // so we can only be strict about checking this for implementations of KeyMint
        // version 2 and above.
        return;
    }

    let attest_key_alias = format!("ks_ec_attest_multipurpose_key_{}", getuid());

    let attest_gen_params = authorizations::AuthSetBuilder::new()
        .no_auth_required()
        .algorithm(Algorithm::EC)
        .purpose(KeyPurpose::ATTEST_KEY)
        .purpose(KeyPurpose::SIGN)
        .purpose(KeyPurpose::VERIFY)
        .digest(Digest::SHA_2_256)
        .ec_curve(EcCurve::P_256);

    let result = key_generations::map_ks_error(sl.binder.generateKey(
        &KeyDescriptor {
            domain: Domain::APP,
            nspace: -1,
            alias: Some(attest_key_alias),
            blob: None,
        },
        None,
        &attest_gen_params,
        0,
        b"entropy",
    ));
    assert!(result.is_err());
    assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_PURPOSE), result.unwrap_err());
}

/// Generate RSA attestation key and try to use it for signing RSA key without providing
/// attestation challenge. Test should fail to generate a key with error code
/// `ATTESTATION_CHALLENGE_MISSING`.
#[test]
fn keystore2_attest_key_fails_missing_challenge() {
    skip_test_if_no_app_attest_key_feature!();

    let sl = SecLevel::tee();
    let att_challenge: &[u8] = b"foo";

    // Create RSA attestation key.
    let Some(attestation_key_metadata) = key_generations::map_ks_error(
        key_generations::generate_attestation_key(&sl, Algorithm::RSA, att_challenge),
    )
    .unwrap() else {
        return;
    };

    let mut cert_chain: Vec<u8> = Vec::new();
    cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
    cert_chain.extend(attestation_key_metadata.certificateChain.as_ref().unwrap());
    validate_certchain(&cert_chain).expect("Error while validating cert chain.");

    // Try to attest RSA signing key without providing attestation challenge.
    let sign_key_alias = format!("ksrsa_attested_test_key_missing_challenge{}", getuid());
    let result = key_generations::map_ks_error(key_generations::generate_rsa_key(
        &sl,
        Domain::APP,
        -1,
        Some(sign_key_alias),
        &key_generations::KeyParams {
            key_size: 2048,
            purpose: vec![KeyPurpose::SIGN, KeyPurpose::VERIFY],
            padding: Some(PaddingMode::RSA_PKCS1_1_5_SIGN),
            digest: Some(Digest::SHA_2_256),
            mgf_digest: None,
            block_mode: None,
            att_challenge: None,
        },
        Some(&attestation_key_metadata.key),
    ));
    assert!(result.is_err());
    assert_eq!(Error::Km(ErrorCode::ATTESTATION_CHALLENGE_MISSING), result.unwrap_err());
}

/// Generate an asymmetric key which doesn't possess ATTEST_KEY purpose. Try to use this key as
/// attestation key while generating RSA key. Test should fail to generate a key with error
/// code `INCOMPATIBLE_PURPOSE`.
#[test]
fn keystore2_attest_rsa_key_with_non_attest_key_fails_incompat_purpose_error() {
    skip_test_if_no_app_attest_key_feature!();

    let sl = SecLevel::tee();
    let att_challenge: &[u8] = b"foo";

    let alias = format!("non_attest_key_{}", getuid());
    let non_attest_key_metadata =
        key_generations::generate_ec_p256_signing_key(&sl, Domain::APP, -1, Some(alias), None)
            .unwrap();

    // Try to generate RSA signing key with non-attestation key to sign it.
    let sign_key_alias = format!("ksrsa_attested_sign_test_key_non_attest_{}", getuid());
    let result = key_generations::map_ks_error(key_generations::generate_rsa_key(
        &sl,
        Domain::APP,
        -1,
        Some(sign_key_alias),
        &key_generations::KeyParams {
            key_size: 2048,
            purpose: vec![KeyPurpose::SIGN, KeyPurpose::VERIFY],
            padding: Some(PaddingMode::RSA_PKCS1_1_5_SIGN),
            digest: Some(Digest::SHA_2_256),
            mgf_digest: None,
            block_mode: None,
            att_challenge: Some(att_challenge.to_vec()),
        },
        Some(&non_attest_key_metadata.key),
    ));
    assert!(result.is_err());
    assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_PURPOSE), result.unwrap_err());
}

/// Generate a symmetric key. Try to use this symmetric key as attestation key while generating RSA
/// key. Test should fail to generate a key with response code `INVALID_ARGUMENT`.
#[test]
fn keystore2_attest_rsa_key_with_symmetric_key_fails_sys_error() {
    skip_test_if_no_app_attest_key_feature!();

    let sl = SecLevel::tee();
    let att_challenge: &[u8] = b"foo";

    let alias = "aes_attest_key";
    let sym_key_metadata = key_generations::generate_sym_key(
        &sl,
        Algorithm::AES,
        128,
        alias,
        &PaddingMode::NONE,
        &BlockMode::ECB,
        None,
    )
    .unwrap();

    // Try to generate RSA signing key with symmetric key as attestation key.
    let sign_key_alias = format!("ksrsa_attested_sign_test_key_sym_attest_{}", getuid());
    let result = key_generations::map_ks_error(key_generations::generate_rsa_key(
        &sl,
        Domain::APP,
        -1,
        Some(sign_key_alias),
        &key_generations::KeyParams {
            key_size: 2048,
            purpose: vec![KeyPurpose::SIGN, KeyPurpose::VERIFY],
            padding: Some(PaddingMode::RSA_PKCS1_1_5_SIGN),
            digest: Some(Digest::SHA_2_256),
            mgf_digest: None,
            block_mode: None,
            att_challenge: Some(att_challenge.to_vec()),
        },
        Some(&sym_key_metadata.key),
    ));
    assert!(result.is_err());
    assert_eq!(Error::Rc(ResponseCode::INVALID_ARGUMENT), result.unwrap_err());
}

fn get_attestation_ids(keystore2: &binder::Strong<dyn IKeystoreService>) -> Vec<(Tag, Vec<u8>)> {
    let attest_ids = vec![
        (Tag::ATTESTATION_ID_BRAND, "brand"),
        (Tag::ATTESTATION_ID_DEVICE, "device"),
        (Tag::ATTESTATION_ID_PRODUCT, "name"),
        (Tag::ATTESTATION_ID_SERIAL, "serialno"),
        (Tag::ATTESTATION_ID_MANUFACTURER, "manufacturer"),
        (Tag::ATTESTATION_ID_MODEL, "model"),
        (Tag::ATTESTATION_ID_IMEI, ""), //Get this value from Telephony service.
        (Tag::ATTESTATION_ID_SECOND_IMEI, ""), //Get this value from Telephony service.
    ];

    let mut attest_id_params: Vec<(Tag, Vec<u8>)> = vec![];
    for (attest_id, prop_name) in attest_ids {
        if attest_id == Tag::ATTESTATION_ID_SECOND_IMEI
            && !is_second_imei_id_attestation_required(keystore2)
        {
            continue;
        }

        if let Some(value) = get_attest_id_value(attest_id, prop_name) {
            if !value.is_empty() {
                attest_id_params.push((attest_id, value));
            }
        }
    }

    attest_id_params
}

/// Generate an attested key with attestation of the device's identifiers. Test should succeed in
/// generating a attested key with attestation of device identifiers. Test might fail on devices
/// which don't support device id attestation with error response code `CANNOT_ATTEST_IDS or
/// INVALID_TAG`
fn generate_attested_key_with_device_attest_ids(algorithm: Algorithm) {
    skip_test_if_no_device_id_attestation_feature!();
    skip_device_id_attestation_tests!();
    skip_test_if_no_app_attest_key_feature!();
    let sl = SecLevel::tee();

    let att_challenge: &[u8] = b"foo";
    let Some(attest_key_metadata) = key_generations::map_ks_error(
        key_generations::generate_attestation_key(&sl, algorithm, att_challenge),
    )
    .unwrap() else {
        return;
    };

    let attest_id_params = get_attestation_ids(&sl.keystore2);

    for (attest_id, value) in attest_id_params {
        // Create RSA/EC key and use attestation key to sign it.
        let key_alias = format!("ks_attested_test_key_{}", getuid());
        let key_metadata =
            key_generations::map_ks_error(key_generations::generate_key_with_attest_id(
                &sl,
                algorithm,
                Some(key_alias),
                att_challenge,
                &attest_key_metadata.key,
                attest_id,
                value.clone(),
            ))
            .unwrap();

        assert!(key_metadata.certificate.is_some());
        assert!(key_metadata.certificateChain.is_none());

        let mut cert_chain: Vec<u8> = Vec::new();
        cert_chain.extend(key_metadata.certificate.as_ref().unwrap());
        cert_chain.extend(attest_key_metadata.certificate.as_ref().unwrap());
        cert_chain.extend(attest_key_metadata.certificateChain.as_ref().unwrap());

        validate_certchain(&cert_chain).expect("Error while validating cert chain");
        let attest_id_value = get_value_from_attest_record(
            key_metadata.certificate.as_ref().unwrap(),
            attest_id,
            SecurityLevel::TRUSTED_ENVIRONMENT,
        )
        .expect("Attest id verification failed.");
        assert_eq!(attest_id_value, value);
    }
}

#[test]
fn keystore2_attest_ecdsa_attestation_id() {
    generate_attested_key_with_device_attest_ids(Algorithm::EC);
}

#[test]
fn keystore2_attest_rsa_attestation_id() {
    generate_attested_key_with_device_attest_ids(Algorithm::RSA);
}

/// Try to generate an attested key with attestation of invalid device's identifiers. Test should
/// fail with error response code `CANNOT_ATTEST_IDS`.
#[test]
fn keystore2_attest_key_fails_with_invalid_attestation_id() {
    skip_test_if_no_device_id_attestation_feature!();
    skip_device_id_attestation_tests!();
    skip_test_if_no_app_attest_key_feature!();

    let sl = SecLevel::tee();

    let digest = Digest::SHA_2_256;
    let att_challenge: &[u8] = b"foo";

    // Create EC-Attestation key.
    let Some(attest_key_metadata) = key_generations::map_ks_error(
        key_generations::generate_ec_attestation_key(&sl, att_challenge, digest, EcCurve::P_256),
    )
    .unwrap() else {
        return;
    };

    let attest_id_params = vec![
        (Tag::ATTESTATION_ID_BRAND, b"invalid-brand".to_vec()),
        (Tag::ATTESTATION_ID_DEVICE, b"invalid-device-name".to_vec()),
        (Tag::ATTESTATION_ID_PRODUCT, b"invalid-product-name".to_vec()),
        (Tag::ATTESTATION_ID_SERIAL, b"invalid-ro-serial".to_vec()),
        (Tag::ATTESTATION_ID_MANUFACTURER, b"invalid-ro-product-manufacturer".to_vec()),
        (Tag::ATTESTATION_ID_MODEL, b"invalid-ro-product-model".to_vec()),
        (Tag::ATTESTATION_ID_IMEI, b"invalid-imei".to_vec()),
    ];

    for (attest_id, value) in attest_id_params {
        // Create EC key and use attestation key to sign it.
        let ec_key_alias = format!("ks_ec_attested_test_key_fail_{}{}", getuid(), digest.0);
        let result = key_generations::map_ks_error(key_generations::generate_key_with_attest_id(
            &sl,
            Algorithm::EC,
            Some(ec_key_alias),
            att_challenge,
            &attest_key_metadata.key,
            attest_id,
            value,
        ));

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::Km(ErrorCode::CANNOT_ATTEST_IDS));
    }
}

///  If `DEVICE_ID_ATTESTATION_FEATURE` is not supported then test tries to generate an attested
///  key with attestation of valid device's identifiers. Test should fail to generate key with
///  error code `CANNOT_ATTEST_IDS`.
#[test]
fn keystore2_attest_key_without_attestation_id_support_fails_with_cannot_attest_id() {
    if device_id_attestation_feature_exists() {
        // Skip this test on device supporting `DEVICE_ID_ATTESTATION_FEATURE`.
        return;
    }

    let sl = SecLevel::tee();

    let att_challenge: &[u8] = b"foo";
    let Some(attest_key_metadata) = key_generations::map_ks_error(
        key_generations::generate_attestation_key(&sl, Algorithm::RSA, att_challenge),
    )
    .unwrap() else {
        return;
    };

    let attest_id_params = get_attestation_ids(&sl.keystore2);
    for (attest_id, value) in attest_id_params {
        // Create RSA/EC key and use attestation key to sign it.
        let key_alias = format!("ks_attested_test_key_{}", getuid());
        let result = key_generations::map_ks_error(key_generations::generate_key_with_attest_id(
            &sl,
            Algorithm::RSA,
            Some(key_alias),
            att_challenge,
            &attest_key_metadata.key,
            attest_id,
            value.clone(),
        ));
        assert!(
            result.is_err(),
            "Expected to fail as FEATURE_DEVICE_ID_ATTESTATION is not supported."
        );
        assert_eq!(result.unwrap_err(), Error::Km(ErrorCode::CANNOT_ATTEST_IDS));
    }
}

/// Try to generate an attestation key from user context with UID other than AID_SYSTEM or AID_ROOT
/// and also there is no package name associated with it. In such case key generation should fail
/// while collecting Attestation Application ID (AAID) from AAID provider service and keystore
/// should return error response code - `GET_ATTESTATION_APPLICATION_ID_FAILED`.
#[test]
fn keystore2_generate_attested_key_fail_to_get_aaid() {
    static APP_USER_CTX: &str = "u:r:untrusted_app:s0:c91,c256,c10,c20";
    const USER_ID: u32 = 99;
    const APPLICATION_ID: u32 = 19901;
    static APP_UID: u32 = USER_ID * AID_USER_OFFSET + APPLICATION_ID;
    static APP_GID: u32 = APP_UID;

    // SAFETY: The test is run in a separate process with no other threads.
    unsafe {
        run_as::run_as(APP_USER_CTX, Uid::from_raw(APP_UID), Gid::from_raw(APP_GID), || {
            skip_test_if_no_app_attest_key_feature!();
            let sl = SecLevel::tee();
            if sl.keystore2.getInterfaceVersion().unwrap() < 4 {
                // `GET_ATTESTATION_APPLICATION_ID_FAILED` is supported on devices with
                // `IKeystoreService` version >= 4.
                return;
            }
            let att_challenge: &[u8] = b"foo";
            let alias = format!("ks_attest_rsa_encrypt_key_aaid_fail{}", getuid());

            let result = key_generations::map_ks_error(key_generations::generate_rsa_key(
                &sl,
                Domain::APP,
                -1,
                Some(alias),
                &key_generations::KeyParams {
                    key_size: 2048,
                    purpose: vec![KeyPurpose::ATTEST_KEY],
                    padding: Some(PaddingMode::RSA_PKCS1_1_5_SIGN),
                    digest: Some(Digest::SHA_2_256),
                    mgf_digest: None,
                    block_mode: None,
                    att_challenge: Some(att_challenge.to_vec()),
                },
                None,
            ));

            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err(),
                Error::Rc(ResponseCode::GET_ATTESTATION_APPLICATION_ID_FAILED)
            );
        })
    };
}
