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

//! Attestation parsing.

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Algorithm::Algorithm, BlockMode::BlockMode, Digest::Digest, EcCurve::EcCurve,
    HardwareAuthenticatorType::HardwareAuthenticatorType, KeyOrigin::KeyOrigin,
    KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue as KPV,
    KeyPurpose::KeyPurpose, PaddingMode::PaddingMode, Tag::Tag, TagType::TagType,
};
use der::asn1::{Null, ObjectIdentifier, OctetStringRef, SetOfVec};
use der::{oid::AssociatedOid, DerOrd, Enumerated, Reader, Sequence, SliceReader};
use der::{Decode, EncodeValue, Length};
use std::borrow::Cow;

/// Determine the tag type for a tag, based on the top 4 bits of the tag number.
fn tag_type(tag: Tag) -> TagType {
    let raw_type = (tag.0 as u32) & 0xf0000000;
    TagType(raw_type as i32)
}

/// Determine the raw tag value with tag type information stripped out.
fn raw_tag_value(tag: Tag) -> u32 {
    (tag.0 as u32) & 0x0fffffffu32
}

/// OID value for the Android Attestation extension.
pub const ATTESTATION_EXTENSION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");

/// Attestation extension contents
#[derive(Debug, Clone, Sequence, PartialEq)]
pub struct AttestationExtension<'a> {
    /// Attestation version.
    pub attestation_version: i32,
    /// Security level that created the attestation.
    pub attestation_security_level: SecurityLevel,
    /// Keymint version.
    pub keymint_version: i32,
    /// Security level of the KeyMint instance holding the key.
    pub keymint_security_level: SecurityLevel,
    /// Attestation challenge.
    #[asn1(type = "OCTET STRING")]
    pub attestation_challenge: &'a [u8],
    /// Unique ID.
    #[asn1(type = "OCTET STRING")]
    pub unique_id: &'a [u8],
    /// Software-enforced key characteristics.
    pub sw_enforced: AuthorizationList<'a>,
    /// Hardware-enforced key characteristics.
    pub hw_enforced: AuthorizationList<'a>,
}

impl AssociatedOid for AttestationExtension<'_> {
    const OID: ObjectIdentifier = ATTESTATION_EXTENSION_OID;
}

/// Security level enumeration
#[repr(u32)]
#[derive(Debug, Clone, Copy, Enumerated, PartialEq)]
pub enum SecurityLevel {
    /// Software.
    Software = 0,
    /// TEE.
    TrustedEnvironment = 1,
    /// StrongBox.
    Strongbox = 2,
}

/// Root of Trust ASN.1 structure
#[derive(Debug, Clone, Sequence)]
pub struct RootOfTrust<'a> {
    /// Verified boot key hash.
    #[asn1(type = "OCTET STRING")]
    pub verified_boot_key: &'a [u8],
    /// Device bootloader lock state.
    pub device_locked: bool,
    /// Verified boot state.
    pub verified_boot_state: VerifiedBootState,
    /// Verified boot hash
    #[asn1(type = "OCTET STRING")]
    pub verified_boot_hash: &'a [u8],
}

/// Attestation Application ID ASN.1 structure
#[derive(Debug, Clone, Sequence)]
pub struct AttestationApplicationId<'a> {
    /// Package info.
    pub package_info_records: SetOfVec<PackageInfoRecord<'a>>,
    /// Signatures.
    pub signature_digests: SetOfVec<OctetStringRef<'a>>,
}

/// Package record
#[derive(Debug, Clone, Sequence)]
pub struct PackageInfoRecord<'a> {
    /// Package name
    pub package_name: OctetStringRef<'a>,
    /// Package version
    pub version: i64,
}

impl DerOrd for PackageInfoRecord<'_> {
    fn der_cmp(&self, other: &Self) -> Result<std::cmp::Ordering, der::Error> {
        self.package_name.der_cmp(&other.package_name)
    }
}

/// Verified Boot State as ASN.1 ENUMERATED type.
#[repr(u32)]
#[derive(Debug, Clone, Copy, Enumerated)]
pub enum VerifiedBootState {
    /// Verified.
    Verified = 0,
    /// Self-signed.
    SelfSigned = 1,
    /// Unverified.
    Unverified = 2,
    /// Failed.
    Failed = 3,
}

/// Struct corresponding to an ASN.1 DER-serialized `AuthorizationList`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthorizationList<'a> {
    /// Key authorizations.
    pub auths: Cow<'a, [KeyParameter]>,
}

impl From<Vec<KeyParameter>> for AuthorizationList<'_> {
    /// Build an `AuthorizationList` using a set of key parameters.
    fn from(auths: Vec<KeyParameter>) -> Self {
        AuthorizationList { auths: auths.into() }
    }
}

impl<'a> Sequence<'a> for AuthorizationList<'a> {}

/// Stub (non-)implementation of DER-encoding, needed to implement [`Sequence`].
impl EncodeValue for AuthorizationList<'_> {
    fn value_len(&self) -> der::Result<Length> {
        unimplemented!("Only decoding is implemented");
    }
    fn encode_value(&self, _writer: &mut impl der::Writer) -> der::Result<()> {
        unimplemented!("Only decoding is implemented");
    }
}

/// Implementation of [`der::DecodeValue`] which constructs an [`AuthorizationList`] from bytes.
impl<'a> der::DecodeValue<'a> for AuthorizationList<'a> {
    fn decode_value<R: der::Reader<'a>>(decoder: &mut R, header: der::Header) -> der::Result<Self> {
        // Decode tags in the expected order.
        let contents = decoder.read_slice(header.length)?;
        let mut reader = SliceReader::new(contents)?;
        let decoder = &mut reader;
        let mut auths = Vec::new();
        let mut next: Option<u32> = None;
        next = decode_opt_field(decoder, next, &mut auths, Tag::PURPOSE)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ALGORITHM)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::KEY_SIZE)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::BLOCK_MODE)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::DIGEST)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::PADDING)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::CALLER_NONCE)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::MIN_MAC_LENGTH)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::EC_CURVE)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::RSA_PUBLIC_EXPONENT)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::RSA_OAEP_MGF_DIGEST)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ROLLBACK_RESISTANCE)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::EARLY_BOOT_ONLY)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ACTIVE_DATETIME)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ORIGINATION_EXPIRE_DATETIME)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::USAGE_EXPIRE_DATETIME)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::USAGE_COUNT_LIMIT)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::USER_SECURE_ID)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::NO_AUTH_REQUIRED)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::USER_AUTH_TYPE)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::AUTH_TIMEOUT)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ALLOW_WHILE_ON_BODY)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::TRUSTED_USER_PRESENCE_REQUIRED)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::TRUSTED_CONFIRMATION_REQUIRED)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::UNLOCKED_DEVICE_REQUIRED)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::CREATION_DATETIME)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::CREATION_DATETIME)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ORIGIN)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ROOT_OF_TRUST)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::OS_VERSION)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::OS_PATCHLEVEL)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_APPLICATION_ID)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_BRAND)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_DEVICE)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_PRODUCT)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_SERIAL)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_SERIAL)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_SERIAL)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_IMEI)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_MEID)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_MANUFACTURER)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_MODEL)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::VENDOR_PATCHLEVEL)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::BOOT_PATCHLEVEL)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::DEVICE_UNIQUE_ATTESTATION)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::ATTESTATION_ID_SECOND_IMEI)?;
        next = decode_opt_field(decoder, next, &mut auths, Tag::MODULE_HASH)?;

        if next.is_some() {
            // Extra tag encountered.
            return Err(decoder.error(der::ErrorKind::Incomplete {
                expected_len: Length::ZERO,
                actual_len: decoder.remaining_len(),
            }));
        }

        Ok(auths.into())
    }
}

/// Attempt to decode an optional field associated with `expected_tag` from the `decoder`.
///
/// If `already_read_asn1_tag` is provided, then that ASN.1 tag has already been read from the
/// `decoder` and its associated data is next.
///
/// (Because the field is optional, we might not read the tag we expect, but instead a later tag
/// from the list.  If this happens, the actual decoded ASN.1 tag value is returned to the caller to
/// be passed in on the next call to this function.)
///
/// If the decoded or re-used ASN.1 tag is the expected one, continue on to read the associated
/// value and populate it in `auths`.
fn decode_opt_field<'a, R: der::Reader<'a>>(
    decoder: &mut R,
    already_read_asn1_tag: Option<u32>,
    auths: &mut Vec<KeyParameter>,
    expected_tag: Tag,
) -> Result<Option<u32>, der::Error> {
    // Decode the ASN.1 tag if no tag is provided
    let asn1_tag = match already_read_asn1_tag {
        Some(tag) => Some(tag),
        None => decode_explicit_tag_from_bytes(decoder)?,
    };
    let expected_asn1_tag = raw_tag_value(expected_tag);
    match asn1_tag {
        Some(v) if v == expected_asn1_tag => {
            // Decode the length of the inner encoding
            let inner_len = Length::decode(decoder)?;
            if decoder.remaining_len() < inner_len {
                return Err(der::ErrorKind::Incomplete {
                    expected_len: inner_len,
                    actual_len: decoder.remaining_len(),
                }
                .into());
            }
            let next_tlv = decoder.tlv_bytes()?;
            decode_value_from_bytes(expected_tag, next_tlv, auths)?;
            Ok(None)
        }
        Some(tag) => Ok(Some(tag)), // Return the tag for which the value is unread.
        None => Ok(None),
    }
}

/// Decode one or more `KeyParameterValue`s of the type associated with `tag` from the `decoder`,
/// and add them to `auths`.
fn decode_value_from_bytes(
    tag: Tag,
    data: &[u8],
    auths: &mut Vec<KeyParameter>,
) -> Result<(), der::Error> {
    match tag_type(tag) {
        TagType::ENUM_REP => {
            let values = SetOfVec::<i32>::from_der(data)?;
            for value in values.as_slice() {
                auths.push(KeyParameter {
                    tag,
                    value: match tag {
                        Tag::BLOCK_MODE => KPV::BlockMode(BlockMode(*value)),
                        Tag::PADDING => KPV::PaddingMode(PaddingMode(*value)),
                        Tag::DIGEST => KPV::Digest(Digest(*value)),
                        Tag::RSA_OAEP_MGF_DIGEST => KPV::Digest(Digest(*value)),
                        Tag::PURPOSE => KPV::KeyPurpose(KeyPurpose(*value)),
                        _ => return Err(der::ErrorKind::TagNumberInvalid.into()),
                    },
                });
            }
        }
        TagType::UINT_REP => {
            let values = SetOfVec::<i32>::from_der(data)?;
            for value in values.as_slice() {
                auths.push(KeyParameter { tag, value: KPV::Integer(*value) });
            }
        }
        TagType::ENUM => {
            let value = i32::from_der(data)?;
            auths.push(KeyParameter {
                tag,
                value: match tag {
                    Tag::ALGORITHM => KPV::Algorithm(Algorithm(value)),
                    Tag::EC_CURVE => KPV::EcCurve(EcCurve(value)),
                    Tag::ORIGIN => KPV::Origin(KeyOrigin(value)),
                    Tag::USER_AUTH_TYPE => {
                        KPV::HardwareAuthenticatorType(HardwareAuthenticatorType(value))
                    }
                    _ => return Err(der::ErrorKind::TagNumberInvalid.into()),
                },
            });
        }
        TagType::UINT => {
            let value = i32::from_der(data)?;
            auths.push(KeyParameter { tag, value: KPV::Integer(value) });
        }
        TagType::ULONG => {
            let value = i64::from_der(data)?;
            auths.push(KeyParameter { tag, value: KPV::LongInteger(value) });
        }
        TagType::DATE => {
            let value = i64::from_der(data)?;
            auths.push(KeyParameter { tag, value: KPV::DateTime(value) });
        }
        TagType::BOOL => {
            let _value = Null::from_der(data)?;
            auths.push(KeyParameter { tag, value: KPV::BoolValue(true) });
        }
        TagType::BYTES if tag == Tag::ROOT_OF_TRUST => {
            // Special case: root of trust is an ASN.1 `SEQUENCE` not an `OCTET STRING` so don't
            // decode the bytes.
            auths.push(KeyParameter { tag: Tag::ROOT_OF_TRUST, value: KPV::Blob(data.to_vec()) });
        }
        TagType::BYTES | TagType::BIGNUM => {
            let value = OctetStringRef::from_der(data)?.as_bytes().to_vec();
            auths.push(KeyParameter { tag, value: KPV::Blob(value) });
        }
        _ => {
            return Err(der::ErrorKind::TagNumberInvalid.into());
        }
    }
    Ok(())
}

/// Decode an explicit ASN.1 tag value, coping with large (>=31) tag values
/// (which the `der` crate doesn't deal with).  Returns `Ok(None)` if the
/// decoder is empty.
fn decode_explicit_tag_from_bytes<'a, R: der::Reader<'a>>(
    decoder: &mut R,
) -> Result<Option<u32>, der::Error> {
    if decoder.remaining_len() == Length::ZERO {
        return Ok(None);
    }
    let b1 = decoder.read_byte()?;
    let tag = if b1 & 0b00011111 == 0b00011111u8 {
        // The initial byte of 0xbf indicates a larger (>=31) value for the ASN.1 tag:
        // - 0bXY...... = class
        // - 0b..C..... = constructed/primitive bit
        // - 0b...11111 = marker indicating high tag form, tag value to follow
        //
        // The top three bits should be 0b101 = constructed context-specific
        if b1 & 0b11100000 != 0b10100000 {
            return Err(der::ErrorKind::TagNumberInvalid.into());
        }

        // The subsequent encoded tag value is broken down into 7-bit chunks (in big-endian order),
        // and each chunk gets a high bit of 1 except the last, which gets a high bit of zero.
        let mut bit_count = 0;
        let mut tag: u32 = 0;
        loop {
            let b = decoder.read_byte()?;
            let low_b = b & 0b01111111;
            if bit_count == 0 && low_b == 0 {
                // The first part of the tag number is zero, implying it is not miminally encoded.
                return Err(der::ErrorKind::TagNumberInvalid.into());
            }

            bit_count += 7;
            if bit_count > 32 {
                // Tag value has more bits than the output type can hold.
                return Err(der::ErrorKind::TagNumberInvalid.into());
            }
            tag = (tag << 7) | (low_b as u32);
            if b & 0x80u8 == 0x00u8 {
                // Top bit clear => this is the final part of the value.
                if tag < 31 {
                    // Tag is small enough that it should have been in short form.
                    return Err(der::ErrorKind::TagNumberInvalid.into());
                }
                break tag;
            }
        }
    } else {
        // Get the tag value from the low 5 bits.
        (b1 & 0b00011111u8) as u32
    };
    Ok(Some(tag))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;

    const SIG: &[u8; 32] = &[
        0xa4, 0x0d, 0xa8, 0x0a, 0x59, 0xd1, 0x70, 0xca, 0xa9, 0x50, 0xcf, 0x15, 0xc1, 0x8c, 0x45,
        0x4d, 0x47, 0xa3, 0x9b, 0x26, 0x98, 0x9d, 0x8b, 0x64, 0x0e, 0xcd, 0x74, 0x5b, 0xa7, 0x1b,
        0xf5, 0xdc,
    ];
    const VB_KEY: &[u8; 32] = &[0; 32];
    const VB_HASH: &[u8; 32] = &[
        0x6f, 0x84, 0xe6, 0x02, 0x73, 0x9d, 0x86, 0x2c, 0x93, 0x2a, 0x28, 0xf0, 0xa5, 0x27, 0x65,
        0xa4, 0xae, 0xc2, 0x27, 0x8c, 0xb6, 0x3b, 0xe9, 0xbb, 0x63, 0xc7, 0xa8, 0xc7, 0x03, 0xad,
        0x8e, 0xc1,
    ];

    /// Build a sample `AuthorizationList` suitable for use as `sw_enforced`.
    fn sw_enforced() -> AuthorizationList<'static> {
        let sig = OctetStringRef::new(SIG).unwrap();
        let package = PackageInfoRecord {
            package_name: OctetStringRef::new(b"android.keystore.cts").unwrap(),
            version: 34,
        };
        let mut package_info_records = SetOfVec::new();
        package_info_records.insert(package).unwrap();
        let mut signature_digests = SetOfVec::new();
        signature_digests.insert(sig).unwrap();
        let aaid = AttestationApplicationId { package_info_records, signature_digests };
        AuthorizationList {
            auths: vec![
                KeyParameter { tag: Tag::CREATION_DATETIME, value: KPV::DateTime(0x01903116c71f) },
                KeyParameter {
                    tag: Tag::ATTESTATION_APPLICATION_ID,
                    value: KPV::Blob(aaid.to_der().unwrap()),
                },
            ]
            .into(),
        }
    }

    /// Build a sample `AuthorizationList` suitable for use as `hw_enforced`.
    fn hw_enforced() -> AuthorizationList<'static> {
        let rot = RootOfTrust {
            verified_boot_key: VB_KEY,
            device_locked: false,
            verified_boot_state: VerifiedBootState::Unverified,
            verified_boot_hash: VB_HASH,
        };
        AuthorizationList {
            auths: vec![
                KeyParameter { tag: Tag::PURPOSE, value: KPV::KeyPurpose(KeyPurpose::AGREE_KEY) },
                KeyParameter { tag: Tag::ALGORITHM, value: KPV::Algorithm(Algorithm::EC) },
                KeyParameter { tag: Tag::KEY_SIZE, value: KPV::Integer(256) },
                KeyParameter { tag: Tag::DIGEST, value: KPV::Digest(Digest::NONE) },
                KeyParameter { tag: Tag::EC_CURVE, value: KPV::EcCurve(EcCurve::CURVE_25519) },
                KeyParameter { tag: Tag::NO_AUTH_REQUIRED, value: KPV::BoolValue(true) },
                KeyParameter { tag: Tag::ORIGIN, value: KPV::Origin(KeyOrigin::GENERATED) },
                KeyParameter { tag: Tag::ROOT_OF_TRUST, value: KPV::Blob(rot.to_der().unwrap()) },
                KeyParameter { tag: Tag::OS_VERSION, value: KPV::Integer(140000) },
                KeyParameter { tag: Tag::OS_PATCHLEVEL, value: KPV::Integer(202404) },
                KeyParameter { tag: Tag::VENDOR_PATCHLEVEL, value: KPV::Integer(20240405) },
                KeyParameter { tag: Tag::BOOT_PATCHLEVEL, value: KPV::Integer(20240405) },
            ]
            .into(),
        }
    }

    #[test]
    fn test_decode_auth_list_1() {
        let want = sw_enforced();
        let data = hex::decode(concat!(
            "3055",     //  SEQUENCE
            "bf853d08", //  [701]
            "0206",     //  INTEGER
            "01903116c71f",
            "bf854545",                                 //  [709]
            "0443",                                     //  OCTET STRING
            "3041",                                     //  SEQUENCE
            "311b",                                     //  SET
            "3019",                                     //  SEQUENCE
            "0414",                                     //  OCTET STRING
            "616e64726f69642e6b657973746f72652e637473", //  "android.keystore.cts"
            "020122",                                   //  INTEGER
            "3122",                                     //  SET
            "0420",                                     //  OCTET STRING
            "a40da80a59d170caa950cf15c18c454d",
            "47a39b26989d8b640ecd745ba71bf5dc",
        ))
        .unwrap();
        let got = AuthorizationList::from_der(&data).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn test_decode_auth_list_2() {
        let want = hw_enforced();
        let data = hex::decode(concat!(
            "3081a1",   //  SEQUENCE
            "a105",     //  [1]
            "3103",     //  SET
            "020106",   //  INTEGER
            "a203",     //  [2]
            "020103",   //  INTEGER 3
            "a304",     //  [4]
            "02020100", //  INTEGER 256
            "a505",     //  [5]
            "3103",     //  SET
            "020100",   //  INTEGER 0
            "aa03",     //  [10]
            "020104",   //  INTEGER 4
            "bf837702", //  [503]
            "0500",     //  NULL
            "bf853e03", //  [702]
            "020100",   //  INTEGER 0
            "bf85404c", //  [704]
            "304a",     //  SEQUENCE
            "0420",     //  OCTET STRING
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "010100", //  BOOLEAN
            "0a0102", //  ENUMERATED
            "0420",   //  OCTET STRING
            "6f84e602739d862c932a28f0a52765a4",
            "aec2278cb63be9bb63c7a8c703ad8ec1",
            "bf854105",     //  [705]
            "02030222e0",   //  INTEGER
            "bf854205",     //  [706]
            "02030316a4",   //  INTEGER
            "bf854e06",     //  [718]
            "02040134d815", //  INTEGER
            "bf854f06",     //  [709]
            "02040134d815", //  INTEGER
        ))
        .unwrap();
        let got = AuthorizationList::from_der(&data).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn test_decode_extension() {
        let zeroes = [0; 128];
        let want = AttestationExtension {
            attestation_version: 300,
            attestation_security_level: SecurityLevel::TrustedEnvironment,
            keymint_version: 300,
            keymint_security_level: SecurityLevel::TrustedEnvironment,
            attestation_challenge: &zeroes,
            unique_id: &[],
            sw_enforced: sw_enforced(),
            hw_enforced: hw_enforced(),
        };

        let data = hex::decode(concat!(
            // Full extension would include the following prefix:
            // "308201a2",             //  SEQUENCE
            // "060a",                 //  OBJECT IDENTIFIER
            // "2b06010401d679020111", //  Android attestation extension (1.3.6.1.4.1.11129.2.1.17)
            // "04820192",             //  OCTET STRING
            "3082018e", //  SEQUENCE
            "0202012c", //  INTEGER 300
            "0a0101",   //  ENUMERATED 1
            "0202012c", //  INTEGER 300
            "0a0101",   //  ENUMERATED 1
            "048180",   //  OCTET STRING
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "0400", //  OCTET STRING
            // softwareEnforced
            "3055",     //  SEQUENCE
            "bf853d08", //  [701]
            "0206",     //  INTEGER
            "01903116c71f",
            "bf854545",                                 //  [709]
            "0443",                                     //  OCTET STRING
            "3041",                                     //  SEQUENCE
            "311b",                                     //  SET
            "3019",                                     //  SEQUENCE
            "0414",                                     //  OCTET STRING
            "616e64726f69642e6b657973746f72652e637473", //  "android.keystore.cts"
            "020122",                                   //  INTEGER
            "3122",                                     //  SET
            "0420",                                     //  OCTET STRING
            "a40da80a59d170caa950cf15c18c454d",
            "47a39b26989d8b640ecd745ba71bf5dc",
            // softwareEnforced
            "3081a1",   //  SEQUENCE
            "a105",     //  [1]
            "3103",     //  SET
            "020106",   //  INTEGER
            "a203",     //  [2]
            "020103",   //  INTEGER 3
            "a304",     //  [4]
            "02020100", //  INTEGER 256
            "a505",     //  [5]
            "3103",     //  SET
            "020100",   //  INTEGER 0
            "aa03",     //  [10]
            "020104",   //  INTEGER 4
            "bf837702", //  [503]
            "0500",     //  NULL
            "bf853e03", //  [702]
            "020100",   //  INTEGER 0
            "bf85404c", //  [704]
            "304a",     //  SEQUENCE
            "0420",     //  OCTET STRING
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "010100", //  BOOLEAN
            "0a0102", //  ENUMERATED
            "0420",   //  OCTET STRING
            "6f84e602739d862c932a28f0a52765a4",
            "aec2278cb63be9bb63c7a8c703ad8ec1",
            "bf854105",     //  [705]
            "02030222e0",   //  INTEGER
            "bf854205",     //  [706]
            "02030316a4",   //  INTEGER
            "bf854e06",     //  [718]
            "02040134d815", //  INTEGER
            "bf854f06",     //  [719]
            "02040134d815", //  INTEGER
        ))
        .unwrap();
        let got = AttestationExtension::from_der(&data).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn test_decode_empty_auth_list() {
        let want = AuthorizationList::default();
        let data = hex::decode(
            "3000", //  SEQUENCE
        )
        .unwrap();
        let got = AuthorizationList::from_der(&data).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn test_decode_explicit_tag() {
        let err = Err(der::ErrorKind::TagNumberInvalid.into());
        let tests = [
            (vec![], Ok(None)),
            (vec![0b10100000], Ok(Some(0))),
            (vec![0b10100001], Ok(Some(1))),
            (vec![0b10100010], Ok(Some(2))),
            (vec![0b10111110], Ok(Some(30))),
            (vec![0b10111111, 0b00011111], Ok(Some(31))),
            (vec![0b10111111, 0b00100000], Ok(Some(32))),
            (vec![0b10111111, 0b01111111], Ok(Some(127))),
            (vec![0b10111111, 0b10000001, 0b00000000], Ok(Some(128))),
            (vec![0b10111111, 0b10000010, 0b00000000], Ok(Some(256))),
            (vec![0b10111111, 0b10000001, 0b10000000, 0b00000001], Ok(Some(16385))),
            (vec![0b10111111, 0b10010000, 0b10000000, 0b10000000, 0b00000000], Ok(Some(33554432))),
            // Top bits ignored for low tag numbers
            (vec![0b00000000], Ok(Some(0))),
            (vec![0b00000001], Ok(Some(1))),
            // High tag numbers should start with 0b101
            (vec![0b10011111, 0b00100000], err),
            (vec![0b11111111, 0b00100000], err),
            (vec![0b00111111, 0b00100000], err),
            // High tag numbers should be minimally encoded
            (vec![0b10111111, 0b10000000, 0b10000001, 0b00000000], err),
            (vec![0b10111111, 0b00011110], err),
            // Bigger than u32
            (
                vec![
                    0b10111111, 0b10000001, 0b10000000, 0b10000000, 0b10000000, 0b10000000,
                    0b00000000,
                ],
                err,
            ),
            // Incomplete tag
            (vec![0b10111111, 0b10000001], Err(der::Error::incomplete(der::Length::new(2)))),
        ];

        for (input, want) in tests {
            let mut reader = SliceReader::new(&input).unwrap();
            let got = decode_explicit_tag_from_bytes(&mut reader);
            assert_eq!(got, want, "for input {}", hex::encode(input));
        }
    }
}
