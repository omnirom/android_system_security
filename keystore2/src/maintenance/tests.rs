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

//! Maintenance tests.
use super::*;
use der::ErrorKind;

#[test]
fn test_encode_module_info_empty() {
    let expected = vec![0x31, 0x00];
    assert_eq!(expected, Maintenance::encode_module_info(Vec::new()).unwrap());
}

#[test]
fn test_encode_module_info_same_name() {
    // Same versions
    let module_info: Vec<ModuleInfo> = vec![
        ModuleInfo {
            name: OctetString::new("com.android.os.statsd".to_string()).unwrap(),
            version: 25,
        },
        ModuleInfo {
            name: OctetString::new("com.android.os.statsd".to_string()).unwrap(),
            version: 25,
        },
    ];
    let actual = Maintenance::encode_module_info(module_info);
    assert!(actual.is_err());
    assert_eq!(ErrorKind::SetDuplicate, actual.unwrap_err().kind());

    // Different versions
    let module_info: Vec<ModuleInfo> = vec![
        ModuleInfo {
            name: OctetString::new("com.android.os.statsd".to_string()).unwrap(),
            version: 3,
        },
        ModuleInfo {
            name: OctetString::new("com.android.os.statsd".to_string()).unwrap(),
            version: 789,
        },
    ];
    let actual = Maintenance::encode_module_info(module_info);
    assert!(actual.is_err());
    assert_eq!(ErrorKind::SetDuplicate, actual.unwrap_err().kind());
}

#[test]
fn test_encode_module_info_same_name_length() {
    let module_info: Vec<ModuleInfo> = vec![
        ModuleInfo { name: OctetString::new("com.android.wifi".to_string()).unwrap(), version: 2 },
        ModuleInfo { name: OctetString::new("com.android.virt".to_string()).unwrap(), version: 1 },
    ];
    let actual = Maintenance::encode_module_info(module_info).unwrap();
    let expected = hex::decode(concat!(
        "312e",                             // SET OF, len 46
        "3015",                             // SEQUENCE, len 21
        "0410",                             // OCTET STRING, len 16
        "636f6d2e616e64726f69642e76697274", // "com.android.virt"
        "020101",                           // INTEGER len 1 value 1
        "3015",                             // SEQUENCE, len 21
        "0410",                             // OCTET STRING, len 16
        "636f6d2e616e64726f69642e77696669", // "com.android.wifi"
        "020102",                           // INTEGER len 1 value 2
    ))
    .unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_encode_module_info_version_irrelevant() {
    // Versions of the modules are irrelevant for determining encoding order since differing names
    // guarantee a unique ascending order. See Maintenance::ModuleInfo::der_cmp for more detail.
    let module_info: Vec<ModuleInfo> = vec![
        ModuleInfo {
            name: OctetString::new("com.android.extservices".to_string()).unwrap(),
            version: 1,
        },
        ModuleInfo { name: OctetString::new("com.android.adbd".to_string()).unwrap(), version: 14 },
    ];
    let actual = Maintenance::encode_module_info(module_info).unwrap();
    let expected = hex::decode(concat!(
        "3135",                                           // SET OF, len 53
        "3015",                                           // SEQUENCE, len 21
        "0410",                                           // OCTET STRING, len 16
        "636f6d2e616e64726f69642e61646264",               // "com.android.abdb"
        "02010e",                                         // INTEGER len 2 value 14
        "301c",                                           // SEQUENCE, len 28
        "0417",                                           // OCTET STRING, len 23
        "636f6d2e616e64726f69642e6578747365727669636573", // "com.android.extservices"
        "020101",                                         // INTEGER len 1 value 1
    ))
    .unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_encode_module_info_alphaordering_irrelevant() {
    // Character ordering of the names of modules is irrelevant for determining encoding order since
    // differing name lengths guarantee a unique ascending order. See
    // Maintenance::ModuleInfo::der_cmp for more detail.
    let module_info: Vec<ModuleInfo> = vec![
        ModuleInfo {
            name: OctetString::new("com.android.crashrecovery".to_string()).unwrap(),
            version: 3,
        },
        ModuleInfo { name: OctetString::new("com.android.rkpd".to_string()).unwrap(), version: 8 },
    ];
    let actual = Maintenance::encode_module_info(module_info).unwrap();
    let expected = hex::decode(concat!(
        "3137",                                               // SET OF, len 55
        "3015",                                               // SEQUENCE, len 21
        "0410",                                               // OCTET STRING, len 16
        "636f6d2e616e64726f69642e726b7064",                   // "com.android.rkpd"
        "020108",                                             // INTEGER len 1 value 8
        "301e",                                               // SEQUENCE, len 30
        "0419",                                               // OCTET STRING, len 25
        "636f6d2e616e64726f69642e63726173687265636f76657279", // "com.android.crashrecovery"
        "020103",                                             // INTEGER len 1 value 3
    ))
    .unwrap();
    assert_eq!(expected, actual);
}

#[test]
fn test_encode_module_info() {
    // Collection of `ModuleInfo`s from a few of the other test_encode_module_info_* tests
    let module_info: Vec<ModuleInfo> = vec![
        ModuleInfo { name: OctetString::new("com.android.rkpd".to_string()).unwrap(), version: 8 },
        ModuleInfo {
            name: OctetString::new("com.android.extservices".to_string()).unwrap(),
            version: 1,
        },
        ModuleInfo {
            name: OctetString::new("com.android.crashrecovery".to_string()).unwrap(),
            version: 3,
        },
        ModuleInfo { name: OctetString::new("com.android.wifi".to_string()).unwrap(), version: 2 },
        ModuleInfo { name: OctetString::new("com.android.virt".to_string()).unwrap(), version: 1 },
        ModuleInfo { name: OctetString::new("com.android.adbd".to_string()).unwrap(), version: 14 },
    ];
    let actual = Maintenance::encode_module_info(module_info).unwrap();
    let expected = hex::decode(concat!(
        "31819a",                                             // SET OF, len 154
        "3015",                                               // SEQUENCE, len 21
        "0410",                                               // OCTET STRING, len 16
        "636f6d2e616e64726f69642e61646264",                   // "com.android.abdb"
        "02010e",                                             // INTEGER len 2 value 14
        "3015",                                               // SEQUENCE, len 21
        "0410",                                               // OCTET STRING, len 16
        "636f6d2e616e64726f69642e726b7064",                   // "com.android.rkpd"
        "020108",                                             // INTEGER len 1 value 8
        "3015",                                               // SEQUENCE, len 21
        "0410",                                               // OCTET STRING, len 16
        "636f6d2e616e64726f69642e76697274",                   // "com.android.virt"
        "020101",                                             // INTEGER len 1 value 1
        "3015",                                               // SEQUENCE, len 21
        "0410",                                               // OCTET STRING, len 16
        "636f6d2e616e64726f69642e77696669",                   // "com.android.wifi"
        "020102",                                             // INTEGER len 1 value 2
        "301c",                                               // SEQUENCE, len 28
        "0417",                                               // OCTET STRING, len 23
        "636f6d2e616e64726f69642e6578747365727669636573",     // "com.android.extservices"
        "020101",                                             // INTEGER len 1 value 1
        "301e",                                               // SEQUENCE, len 30
        "0419",                                               // OCTET STRING, len 25
        "636f6d2e616e64726f69642e63726173687265636f76657279", // "com.android.crashrecovery"
        "020103",                                             // INTEGER len 1 value 3
    ))
    .unwrap();
    assert_eq!(expected, actual);
}
