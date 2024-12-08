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

use super::*;
use android_hardware_security_keymint::aidl::android::hardware::security::keymint::TagType::TagType;

fn get_field_by_tag_type(tag: Tag) -> KmKeyParameterValue {
    let tag_type = TagType((tag.0 as u32 & 0xF0000000) as i32);
    match tag {
        Tag::ALGORITHM => return KmKeyParameterValue::Algorithm(Default::default()),
        Tag::BLOCK_MODE => return KmKeyParameterValue::BlockMode(Default::default()),
        Tag::PADDING => return KmKeyParameterValue::PaddingMode(Default::default()),
        Tag::DIGEST => return KmKeyParameterValue::Digest(Default::default()),
        Tag::RSA_OAEP_MGF_DIGEST => return KmKeyParameterValue::Digest(Default::default()),
        Tag::EC_CURVE => return KmKeyParameterValue::EcCurve(Default::default()),
        Tag::ORIGIN => return KmKeyParameterValue::Origin(Default::default()),
        Tag::PURPOSE => return KmKeyParameterValue::KeyPurpose(Default::default()),
        Tag::USER_AUTH_TYPE => {
            return KmKeyParameterValue::HardwareAuthenticatorType(Default::default())
        }
        Tag::HARDWARE_TYPE => return KmKeyParameterValue::SecurityLevel(Default::default()),
        _ => {}
    }
    match tag_type {
        TagType::INVALID => return KmKeyParameterValue::Invalid(Default::default()),
        TagType::ENUM | TagType::ENUM_REP => {}
        TagType::UINT | TagType::UINT_REP => {
            return KmKeyParameterValue::Integer(Default::default())
        }
        TagType::ULONG | TagType::ULONG_REP => {
            return KmKeyParameterValue::LongInteger(Default::default())
        }
        TagType::DATE => return KmKeyParameterValue::DateTime(Default::default()),
        TagType::BOOL => return KmKeyParameterValue::BoolValue(Default::default()),
        TagType::BIGNUM | TagType::BYTES => return KmKeyParameterValue::Blob(Default::default()),
        _ => {}
    }
    panic!("Unknown tag/tag_type: {:?} {:?}", tag, tag_type);
}

fn check_field_matches_tag_type(list_o_parameters: &[KmKeyParameter]) {
    for kp in list_o_parameters.iter() {
        match (&kp.value, get_field_by_tag_type(kp.tag)) {
            (&KmKeyParameterValue::Algorithm(_), KmKeyParameterValue::Algorithm(_))
            | (&KmKeyParameterValue::BlockMode(_), KmKeyParameterValue::BlockMode(_))
            | (&KmKeyParameterValue::PaddingMode(_), KmKeyParameterValue::PaddingMode(_))
            | (&KmKeyParameterValue::Digest(_), KmKeyParameterValue::Digest(_))
            | (&KmKeyParameterValue::EcCurve(_), KmKeyParameterValue::EcCurve(_))
            | (&KmKeyParameterValue::Origin(_), KmKeyParameterValue::Origin(_))
            | (&KmKeyParameterValue::KeyPurpose(_), KmKeyParameterValue::KeyPurpose(_))
            | (
                &KmKeyParameterValue::HardwareAuthenticatorType(_),
                KmKeyParameterValue::HardwareAuthenticatorType(_),
            )
            | (&KmKeyParameterValue::SecurityLevel(_), KmKeyParameterValue::SecurityLevel(_))
            | (&KmKeyParameterValue::Invalid(_), KmKeyParameterValue::Invalid(_))
            | (&KmKeyParameterValue::Integer(_), KmKeyParameterValue::Integer(_))
            | (&KmKeyParameterValue::LongInteger(_), KmKeyParameterValue::LongInteger(_))
            | (&KmKeyParameterValue::DateTime(_), KmKeyParameterValue::DateTime(_))
            | (&KmKeyParameterValue::BoolValue(_), KmKeyParameterValue::BoolValue(_))
            | (&KmKeyParameterValue::Blob(_), KmKeyParameterValue::Blob(_)) => {}
            (actual, expected) => panic!(
                "Tag {:?} associated with variant {:?} expected {:?}",
                kp.tag, actual, expected
            ),
        }
    }
}

#[test]
fn key_parameter_value_field_matches_tag_type() {
    check_field_matches_tag_type(&KeyParameterValue::make_field_matches_tag_type_test_vector());
}

#[test]
fn key_parameter_serialization_test() {
    let params = KeyParameterValue::make_key_parameter_defaults_vector();
    let mut out_buffer: Vec<u8> = Default::default();
    serde_cbor::to_writer(&mut out_buffer, &params).expect("Failed to serialize key parameters.");
    let deserialized_params: Vec<KeyParameter> =
        serde_cbor::from_reader(&mut out_buffer.as_slice())
            .expect("Failed to deserialize key parameters.");
    assert_eq!(params, deserialized_params);
}
