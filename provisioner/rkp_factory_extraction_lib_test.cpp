/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "rkp_factory_extraction_lib.h"

#include "gmock/gmock-matchers.h"
#include "gmock/gmock-more-matchers.h"
#include <aidl/android/hardware/security/keymint/DeviceInfo.h>
#include <aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.h>
#include <aidl/android/hardware/security/keymint/MacedPublicKey.h>
#include <aidl/android/hardware/security/keymint/RpcHardwareInfo.h>
#include <android-base/properties.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/base64.h>

#include <cstdint>
#include <memory>
#include <ostream>
#include <set>
#include <vector>

#include "aidl/android/hardware/security/keymint/ProtectedData.h"
#include "android/binder_auto_utils.h"
#include "android/binder_interface_utils.h"
#include "cppbor.h"

using ::ndk::ScopedAStatus;
using ::ndk::SharedRefBase;

using namespace ::aidl::android::hardware::security::keymint;
using namespace ::cppbor;
using namespace ::testing;

namespace cppbor {

std::ostream& operator<<(std::ostream& os, const Item& item) {
    return os << prettyPrint(&item);
}

std::ostream& operator<<(std::ostream& os, const std::unique_ptr<Item>& item) {
    return os << *item;
}

std::ostream& operator<<(std::ostream& os, const Item* item) {
    return os << *item;
}

}  // namespace cppbor

inline const std::vector<uint8_t> kCsrWithoutUdsCerts{
    0x85, 0x01, 0xa0, 0x82, 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0xb8, 0x36,
    0xbb, 0x1e, 0x07, 0x85, 0x02, 0xde, 0xdb, 0x91, 0x38, 0x5d, 0xc7, 0xf8, 0x59, 0xa9, 0x4f, 0x50,
    0xee, 0x2a, 0x3f, 0xa5, 0x5f, 0xaa, 0xa1, 0x8e, 0x46, 0x84, 0xb8, 0x3b, 0x4b, 0x6d, 0x22, 0x58,
    0x20, 0xa1, 0xc1, 0xd8, 0xa5, 0x9d, 0x1b, 0xce, 0x8c, 0x65, 0x10, 0x8d, 0xcf, 0xa1, 0xf4, 0x91,
    0x10, 0x09, 0xfb, 0xb0, 0xc5, 0xb4, 0x01, 0x75, 0x72, 0xb4, 0x44, 0xaa, 0x23, 0x13, 0xe1, 0xe9,
    0xe5, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x59, 0x01, 0x04, 0xa9, 0x01, 0x66, 0x69, 0x73, 0x73,
    0x75, 0x65, 0x72, 0x02, 0x67, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3a, 0x00, 0x47, 0x44,
    0x50, 0x58, 0x20, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x3a, 0x00, 0x47, 0x44, 0x52, 0x58, 0x20, 0xb8, 0x96, 0x54, 0xe2, 0x2c, 0xa4,
    0xd2, 0x4a, 0x9c, 0x0e, 0x45, 0x11, 0xc8, 0xf2, 0x63, 0xf0, 0x66, 0x0d, 0x2e, 0x20, 0x48, 0x96,
    0x90, 0x14, 0xf4, 0x54, 0x63, 0xc4, 0xf4, 0x39, 0x30, 0x38, 0x3a, 0x00, 0x47, 0x44, 0x53, 0x55,
    0xa1, 0x3a, 0x00, 0x01, 0x11, 0x71, 0x6e, 0x63, 0x6f, 0x6d, 0x70, 0x6f, 0x6e, 0x65, 0x6e, 0x74,
    0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x3a, 0x00, 0x47, 0x44, 0x54, 0x58, 0x20, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x3a, 0x00, 0x47, 0x44,
    0x56, 0x41, 0x01, 0x3a, 0x00, 0x47, 0x44, 0x57, 0x58, 0x4d, 0xa5, 0x01, 0x02, 0x03, 0x26, 0x20,
    0x01, 0x21, 0x58, 0x20, 0x91, 0xdc, 0x49, 0x60, 0x0d, 0x22, 0xf6, 0x28, 0x14, 0xaf, 0xab, 0xa5,
    0x9d, 0x4f, 0x26, 0xac, 0xf9, 0x99, 0xe7, 0xe1, 0xc9, 0xb7, 0x5d, 0x36, 0x21, 0x9d, 0x00, 0x47,
    0x63, 0x28, 0x79, 0xa7, 0x22, 0x58, 0x20, 0x13, 0x77, 0x51, 0x7f, 0x6a, 0xca, 0xa0, 0x50, 0x79,
    0x52, 0xb4, 0x6b, 0xd9, 0xb1, 0x3a, 0x1c, 0x9f, 0x91, 0x97, 0x60, 0xc1, 0x4b, 0x43, 0x5e, 0x45,
    0xd3, 0x0b, 0xa4, 0xbb, 0xc7, 0x27, 0x39, 0x3a, 0x00, 0x47, 0x44, 0x58, 0x41, 0x20, 0x58, 0x40,
    0x88, 0xbd, 0xf9, 0x82, 0x04, 0xfe, 0xa6, 0xfe, 0x82, 0x94, 0xa3, 0xe9, 0x10, 0x91, 0xb5, 0x2e,
    0xa1, 0x62, 0x68, 0xa5, 0x3d, 0xab, 0xdb, 0xa5, 0x87, 0x2a, 0x97, 0x26, 0xb8, 0xd4, 0x60, 0x1a,
    0xf1, 0x3a, 0x45, 0x72, 0x77, 0xd4, 0xeb, 0x2b, 0xa4, 0x48, 0x93, 0xba, 0xae, 0x79, 0x35, 0x57,
    0x66, 0x54, 0x9d, 0x8e, 0xbd, 0xb0, 0x87, 0x5f, 0x8c, 0xf9, 0x04, 0xa3, 0xa7, 0x00, 0xf1, 0x21,
    0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x59, 0x02, 0x0f, 0x82, 0x58, 0x20, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x59, 0x01, 0xe9, 0x84,
    0x03, 0x67, 0x6b, 0x65, 0x79, 0x6d, 0x69, 0x6e, 0x74, 0xae, 0x65, 0x62, 0x72, 0x61, 0x6e, 0x64,
    0x66, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x65, 0x66, 0x75, 0x73, 0x65, 0x64, 0x01, 0x65, 0x6d,
    0x6f, 0x64, 0x65, 0x6c, 0x65, 0x6d, 0x6f, 0x64, 0x65, 0x6c, 0x66, 0x64, 0x65, 0x76, 0x69, 0x63,
    0x65, 0x66, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x67, 0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74,
    0x65, 0x70, 0x69, 0x78, 0x65, 0x6c, 0x68, 0x76, 0x62, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x65,
    0x67, 0x72, 0x65, 0x65, 0x6e, 0x6a, 0x6f, 0x73, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
    0x62, 0x31, 0x32, 0x6c, 0x6d, 0x61, 0x6e, 0x75, 0x66, 0x61, 0x63, 0x74, 0x75, 0x72, 0x65, 0x72,
    0x66, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x6d, 0x76, 0x62, 0x6d, 0x65, 0x74, 0x61, 0x5f, 0x64,
    0x69, 0x67, 0x65, 0x73, 0x74, 0x4f, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
    0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x6e, 0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x5f, 0x6c,
    0x65, 0x76, 0x65, 0x6c, 0x63, 0x74, 0x65, 0x65, 0x70, 0x62, 0x6f, 0x6f, 0x74, 0x5f, 0x70, 0x61,
    0x74, 0x63, 0x68, 0x5f, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x1a, 0x01, 0x34, 0x8c, 0x62, 0x70, 0x62,
    0x6f, 0x6f, 0x74, 0x6c, 0x6f, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x66,
    0x6c, 0x6f, 0x63, 0x6b, 0x65, 0x64, 0x72, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x70, 0x61,
    0x74, 0x63, 0x68, 0x5f, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x1a, 0x01, 0x34, 0x8c, 0x61, 0x72, 0x76,
    0x65, 0x6e, 0x64, 0x6f, 0x72, 0x5f, 0x70, 0x61, 0x74, 0x63, 0x68, 0x5f, 0x6c, 0x65, 0x76, 0x65,
    0x6c, 0x1a, 0x01, 0x34, 0x8c, 0x63, 0x82, 0xa6, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58,
    0x20, 0x85, 0xcd, 0xd8, 0x8c, 0x35, 0x50, 0x11, 0x9c, 0x44, 0x24, 0xa7, 0xf1, 0xbf, 0x75, 0x6e,
    0x7c, 0xab, 0x8c, 0x86, 0xfa, 0x23, 0x95, 0x2c, 0x11, 0xaf, 0xf9, 0x52, 0x80, 0x8f, 0x45, 0x43,
    0x40, 0x22, 0x58, 0x20, 0xec, 0x4e, 0x0d, 0x5a, 0x81, 0xe8, 0x06, 0x12, 0x18, 0xa8, 0x10, 0x74,
    0x6e, 0x56, 0x33, 0x11, 0x7d, 0x74, 0xff, 0x49, 0xf7, 0x38, 0x32, 0xda, 0xf4, 0x60, 0xaa, 0x19,
    0x64, 0x29, 0x58, 0xbe, 0x23, 0x58, 0x21, 0x00, 0xa6, 0xd1, 0x85, 0xdb, 0x8b, 0x15, 0x84, 0xde,
    0x34, 0xf2, 0xe3, 0xee, 0x73, 0x8b, 0x85, 0x57, 0xc1, 0xa3, 0x5d, 0x3f, 0x95, 0x14, 0xd3, 0x74,
    0xfc, 0x73, 0x51, 0x7f, 0xe7, 0x1b, 0x30, 0xbb, 0xa6, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21,
    0x58, 0x20, 0x96, 0x6c, 0x16, 0x6c, 0x4c, 0xa7, 0x73, 0x64, 0x9a, 0x34, 0x88, 0x75, 0xf4, 0xdc,
    0xf3, 0x93, 0xb2, 0xf1, 0xd7, 0xfd, 0xe3, 0x11, 0xcf, 0x6b, 0xee, 0x26, 0xa4, 0xc5, 0xeb, 0xa5,
    0x33, 0x24, 0x22, 0x58, 0x20, 0xe0, 0x33, 0xe8, 0x53, 0xb2, 0x65, 0x1e, 0x33, 0x2a, 0x61, 0x9a,
    0x7a, 0xf4, 0x5f, 0x40, 0x0f, 0x80, 0x4a, 0x38, 0xff, 0x5d, 0x3c, 0xa3, 0x82, 0x36, 0x1e, 0x9d,
    0x93, 0xd9, 0x48, 0xaa, 0x0a, 0x23, 0x58, 0x20, 0x5e, 0xe5, 0x8f, 0x9a, 0x8c, 0xd3, 0xf4, 0xc0,
    0xf7, 0x08, 0x27, 0x5f, 0x8f, 0x77, 0x12, 0x36, 0x7b, 0x6d, 0xf7, 0x65, 0xd4, 0xcc, 0x63, 0xdc,
    0x28, 0x35, 0x33, 0x27, 0x5d, 0x28, 0xc9, 0x9d, 0x58, 0x40, 0x6c, 0xfa, 0xc9, 0xc0, 0xdf, 0x0e,
    0xe4, 0x17, 0x58, 0x06, 0xea, 0xf9, 0x88, 0x9e, 0x27, 0xa0, 0x89, 0x17, 0xa8, 0x1a, 0xe6, 0x0c,
    0x5e, 0x85, 0xa1, 0x13, 0x20, 0x86, 0x14, 0x2e, 0xd6, 0xae, 0xfb, 0xc1, 0xb6, 0x59, 0x66, 0x83,
    0xd2, 0xf4, 0xc8, 0x7a, 0x30, 0x0c, 0x6b, 0x53, 0x8b, 0x76, 0x06, 0xcb, 0x1b, 0x0f, 0xc3, 0x51,
    0x71, 0x52, 0xd1, 0xe3, 0x2a, 0xbc, 0x53, 0x16, 0x46, 0x49, 0xa1, 0x6b, 0x66, 0x69, 0x6e, 0x67,
    0x65, 0x72, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x78, 0x3b, 0x62, 0x72, 0x61, 0x6e, 0x64, 0x31, 0x2f,
    0x70, 0x72, 0x6f, 0x64, 0x75, 0x63, 0x74, 0x31, 0x2f, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x31,
    0x3a, 0x31, 0x31, 0x2f, 0x69, 0x64, 0x2f, 0x32, 0x30, 0x32, 0x31, 0x30, 0x38, 0x30, 0x35, 0x2e,
    0x34, 0x32, 0x3a, 0x75, 0x73, 0x65, 0x72, 0x2f, 0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2d,
    0x6b, 0x65, 0x79, 0x73};

std::string toBase64(const std::vector<uint8_t>& buffer) {
    size_t base64Length;
    int rc = EVP_EncodedLength(&base64Length, buffer.size());
    if (!rc) {
        std::cerr << "Error getting base64 length. Size overflow?" << std::endl;
        exit(-1);
    }

    std::string base64(base64Length, ' ');
    rc = EVP_EncodeBlock(reinterpret_cast<uint8_t*>(base64.data()), buffer.data(), buffer.size());
    ++rc;  // Account for NUL, which BoringSSL does not for some reason.
    if (rc != base64Length) {
        std::cerr << "Error writing base64. Expected " << base64Length
                  << " bytes to be written, but " << rc << " bytes were actually written."
                  << std::endl;
        exit(-1);
    }

    // BoringSSL automatically adds a NUL -- remove it from the string data
    base64.pop_back();

    return base64;
}

class MockIRemotelyProvisionedComponent : public IRemotelyProvisionedComponentDefault {
  public:
    MOCK_METHOD(ScopedAStatus, getHardwareInfo, (RpcHardwareInfo * _aidl_return), (override));
    MOCK_METHOD(ScopedAStatus, generateEcdsaP256KeyPair,
                (bool in_testMode, MacedPublicKey* out_macedPublicKey,
                 std::vector<uint8_t>* _aidl_return),
                (override));
    MOCK_METHOD(ScopedAStatus, generateCertificateRequest,
                (bool in_testMode, const std::vector<MacedPublicKey>& in_keysToSign,
                 const std::vector<uint8_t>& in_endpointEncryptionCertChain,
                 const std::vector<uint8_t>& in_challenge, DeviceInfo* out_deviceInfo,
                 ProtectedData* out_protectedData, std::vector<uint8_t>* _aidl_return),
                (override));
    MOCK_METHOD(ScopedAStatus, generateCertificateRequestV2,
                (const std::vector<MacedPublicKey>& in_keysToSign,
                 const std::vector<uint8_t>& in_challenge, std::vector<uint8_t>* _aidl_return),
                (override));
    MOCK_METHOD(ScopedAStatus, getInterfaceVersion, (int32_t* _aidl_return), (override));
    MOCK_METHOD(ScopedAStatus, getInterfaceHash, (std::string * _aidl_return), (override));
};

TEST(LibRkpFactoryExtractionTests, ToBase64) {
    std::vector<uint8_t> input(UINT8_MAX + 1);
    for (int i = 0; i < input.size(); ++i) {
        input[i] = i;
    }

    // Test three lengths so we get all the different padding options
    EXPECT_EQ("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4"
              "vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV"
              "5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMj"
              "Y6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8"
              "vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uv"
              "s7e7v8PHy8/T19vf4+fr7/P3+/w==",
              toBase64(input));

    input.push_back(42);
    EXPECT_EQ("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4"
              "vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV"
              "5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMj"
              "Y6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8"
              "vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uv"
              "s7e7v8PHy8/T19vf4+fr7/P3+/yo=",
              toBase64(input));

    input.push_back(42);
    EXPECT_EQ("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4"
              "vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV"
              "5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMj"
              "Y6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8"
              "vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uv"
              "s7e7v8PHy8/T19vf4+fr7/P3+/yoq",
              toBase64(input));
}

TEST(LibRkpFactoryExtractionTests, UniqueChallengeSmokeTest) {
    // This will at least catch VERY broken implementations.
    constexpr size_t NUM_CHALLENGES = 32;
    std::set<std::vector<uint8_t>> challenges;
    for (size_t i = 0; i < NUM_CHALLENGES; ++i) {
        const std::vector<uint8_t> challenge = generateChallenge();
        const auto [_, wasInserted] = challenges.insert(generateChallenge());
        EXPECT_TRUE(wasInserted) << "Duplicate challenge: " << toBase64(challenge);
    }
}

TEST(LibRkpFactoryExtractionTests, GetCsrWithV2Hal) {
    ASSERT_TRUE(true);

    const std::vector<uint8_t> kFakeMac = {1, 2, 3, 4};

    Map cborDeviceInfo;
    cborDeviceInfo.add("product", "gShoe");
    cborDeviceInfo.add("version", 2);
    cborDeviceInfo.add("brand", "Fake Brand");
    cborDeviceInfo.add("manufacturer", "Fake Mfr");
    cborDeviceInfo.add("model", "Fake Model");
    cborDeviceInfo.add("device", "Fake Device");
    cborDeviceInfo.add("vb_state", "orange");
    cborDeviceInfo.add("bootloader_state", "unlocked");
    cborDeviceInfo.add("vbmeta_digest", std::vector<uint8_t>{1, 2, 3, 4});
    cborDeviceInfo.add("system_patch_level", 42);
    cborDeviceInfo.add("boot_patch_level", 31415);
    cborDeviceInfo.add("vendor_patch_level", 0);
    cborDeviceInfo.add("fused", 0);
    cborDeviceInfo.add("security_level", "tee");
    cborDeviceInfo.add("os_version", "the best version");
    const DeviceInfo kVerifiedDeviceInfo = {cborDeviceInfo.canonicalize().encode()};

    Array cborProtectedData;
    cborProtectedData.add(Bstr());   // protected
    cborProtectedData.add(Map());    // unprotected
    cborProtectedData.add(Bstr());   // ciphertext
    cborProtectedData.add(Array());  // recipients
    const ProtectedData kProtectedData = {cborProtectedData.encode()};

    std::vector<uint8_t> eekChain;
    std::vector<uint8_t> challenge;

    // Set up mock, then call getCsr
    auto mockRpc = SharedRefBase::make<MockIRemotelyProvisionedComponent>();
    EXPECT_CALL(*mockRpc, getHardwareInfo(NotNull())).WillRepeatedly([](RpcHardwareInfo* hwInfo) {
        hwInfo->versionNumber = 2;
        return ScopedAStatus::ok();
    });
    EXPECT_CALL(*mockRpc,
                generateCertificateRequest(false,               // testMode
                                           IsEmpty(),           // keysToSign
                                           _,                   // endpointEncryptionCertChain
                                           _,                   // challenge
                                           NotNull(),           // deviceInfo
                                           NotNull(),           // protectedData
                                           NotNull()))          // _aidl_return
        .WillOnce(DoAll(SaveArg<2>(&eekChain),                  //
                        SaveArg<3>(&challenge),                 //
                        SetArgPointee<4>(kVerifiedDeviceInfo),  //
                        SetArgPointee<5>(kProtectedData),       //
                        SetArgPointee<6>(kFakeMac),             //
                        Return(ByMove(ScopedAStatus::ok()))));  //

    auto [csr, csrErrMsg] =
        getCsr("mock component name", mockRpc.get(),
               /*selfTest=*/false, /*allowDegenerate=*/true, /*requireUdsCerts=*/false);
    ASSERT_THAT(csr, NotNull()) << csrErrMsg;
    ASSERT_THAT(csr->asArray(), Pointee(Property(&Array::size, Eq(4))));

    // Verify the input parameters that we received
    auto [parsedEek, ignore1, eekParseError] = parse(eekChain);
    ASSERT_THAT(parsedEek, NotNull()) << eekParseError;
    EXPECT_THAT(parsedEek->asArray(), Pointee(Property(&Array::size, Gt(1))));
    EXPECT_THAT(challenge, Property(&std::vector<uint8_t>::size, Eq(kChallengeSize)));

    // Device info consists of (verified info, unverified info)
    const Array* deviceInfoArray = csr->get(0)->asArray();
    EXPECT_THAT(deviceInfoArray, Pointee(Property(&Array::size, 2)));

    // Verified device info must match our mock value
    const Map* actualVerifiedDeviceInfo = deviceInfoArray->get(0)->asMap();
    EXPECT_THAT(actualVerifiedDeviceInfo, Pointee(Property(&Map::size, Eq(cborDeviceInfo.size()))));
    EXPECT_THAT(actualVerifiedDeviceInfo->get("product"), Pointee(Eq(Tstr("gShoe"))));
    EXPECT_THAT(actualVerifiedDeviceInfo->get("version"), Pointee(Eq(Uint(2))));

    // Empty unverified device info
    const Map* actualUnverifiedDeviceInfo = deviceInfoArray->get(1)->asMap();
    EXPECT_THAT(actualUnverifiedDeviceInfo, Pointee(Property(&Map::size, Eq(0))));

    // Challenge must match the call to generateCertificateRequest
    const Bstr* actualChallenge = csr->get(1)->asBstr();
    EXPECT_THAT(actualChallenge, Pointee(Property(&Bstr::value, Eq(challenge))));

    // Protected data must match the mock value
    const Array* actualProtectedData = csr->get(2)->asArray();
    EXPECT_THAT(actualProtectedData, Pointee(Eq(ByRef(cborProtectedData))));

    // Ensure the maced public key matches the expected COSE_mac0
    const Array* actualMacedKeys = csr->get(3)->asArray();
    ASSERT_THAT(actualMacedKeys, Pointee(Property(&Array::size, Eq(4))));
    ASSERT_THAT(actualMacedKeys->get(0)->asBstr(), NotNull());
    auto [macProtectedParams, ignore2, macParamParseError] =
        parse(actualMacedKeys->get(0)->asBstr());
    ASSERT_THAT(macProtectedParams, NotNull()) << macParamParseError;
    Map expectedMacProtectedParams;
    expectedMacProtectedParams.add(1, 5);
    EXPECT_THAT(macProtectedParams, Pointee(Eq(ByRef(expectedMacProtectedParams))));
    EXPECT_THAT(actualMacedKeys->get(1)->asMap(), Pointee(Property(&Map::size, Eq(0))));
    EXPECT_THAT(actualMacedKeys->get(2)->asNull(), NotNull());
    EXPECT_THAT(actualMacedKeys->get(3)->asBstr(), Pointee(Eq(Bstr(kFakeMac))));
}

TEST(LibRkpFactoryExtractionTests, GetCsrWithV3Hal) {
    const std::vector<uint8_t> kCsr = Array()
                                          .add(1 /* version */)
                                          .add(Map() /* UdsCerts */)
                                          .add(Array() /* DiceCertChain */)
                                          .add(Array() /* SignedData */)
                                          .encode();
    std::vector<uint8_t> challenge;

    // Set up mock, then call getCsr
    auto mockRpc = SharedRefBase::make<MockIRemotelyProvisionedComponent>();
    EXPECT_CALL(*mockRpc, getHardwareInfo(NotNull())).WillRepeatedly([](RpcHardwareInfo* hwInfo) {
        hwInfo->versionNumber = 3;
        return ScopedAStatus::ok();
    });
    EXPECT_CALL(*mockRpc,
                generateCertificateRequestV2(IsEmpty(),   // keysToSign
                                             _,           // challenge
                                             NotNull()))  // _aidl_return
        .WillOnce(DoAll(SaveArg<1>(&challenge), SetArgPointee<2>(kCsr),
                        Return(ByMove(ScopedAStatus::ok()))));

    auto [csr, csrErrMsg] =
        getCsr("mock component name", mockRpc.get(),
               /*selfTest=*/false, /*allowDegenerate=*/true, /*requireUdsCerts=*/false);
    ASSERT_THAT(csr, NotNull()) << csrErrMsg;
    ASSERT_THAT(csr, Pointee(Property(&Array::size, Eq(5))));

    EXPECT_THAT(csr->get(0 /* version */), Pointee(Eq(Uint(1))));
    EXPECT_THAT(csr->get(1)->asMap(), NotNull());
    EXPECT_THAT(csr->get(2)->asArray(), NotNull());
    EXPECT_THAT(csr->get(3)->asArray(), NotNull());

    const Map* unverifedDeviceInfo = csr->get(4)->asMap();
    ASSERT_THAT(unverifedDeviceInfo, NotNull());
    EXPECT_THAT(unverifedDeviceInfo->get("fingerprint"), NotNull());
    const Tstr fingerprint(android::base::GetProperty("ro.build.fingerprint", ""));
    EXPECT_THAT(*unverifedDeviceInfo->get("fingerprint")->asTstr(), Eq(fingerprint));
}

TEST(LibRkpFactoryExtractionTests, requireUdsCerts) {
    const std::vector<uint8_t> csrEncoded = kCsrWithoutUdsCerts;
    std::vector<uint8_t> challenge;

    // Set up mock, then call getCsr
    auto mockRpc = SharedRefBase::make<MockIRemotelyProvisionedComponent>();
    EXPECT_CALL(*mockRpc, getHardwareInfo(NotNull())).WillRepeatedly([](RpcHardwareInfo* hwInfo) {
        hwInfo->versionNumber = 3;
        return ScopedAStatus::ok();
    });
    EXPECT_CALL(*mockRpc,
                generateCertificateRequestV2(IsEmpty(),   // keysToSign
                                             _,           // challenge
                                             NotNull()))  // _aidl_return
        .WillOnce(DoAll(SaveArg<1>(&challenge), SetArgPointee<2>(csrEncoded),
                        Return(ByMove(ScopedAStatus::ok()))));

    auto [csr, csrErrMsg] =
        getCsr("default", mockRpc.get(),
               /*selfTest=*/true, /*allowDegenerate=*/false, /*requireUdsCerts=*/true);
    ASSERT_EQ(csr, nullptr);
    ASSERT_THAT(csrErrMsg, testing::HasSubstr("UdsCerts are required"));
}

TEST(LibRkpFactoryExtractionTests, dontRequireUdsCerts) {
    const std::vector<uint8_t> csrEncoded = kCsrWithoutUdsCerts;
    std::vector<uint8_t> challenge;

    // Set up mock, then call getCsr
    auto mockRpc = SharedRefBase::make<MockIRemotelyProvisionedComponent>();
    EXPECT_CALL(*mockRpc, getHardwareInfo(NotNull())).WillRepeatedly([](RpcHardwareInfo* hwInfo) {
        hwInfo->versionNumber = 3;
        return ScopedAStatus::ok();
    });
    EXPECT_CALL(*mockRpc,
                generateCertificateRequestV2(IsEmpty(),   // keysToSign
                                             _,           // challenge
                                             NotNull()))  // _aidl_return
        .WillOnce(DoAll(SaveArg<1>(&challenge), SetArgPointee<2>(csrEncoded),
                        Return(ByMove(ScopedAStatus::ok()))));

    auto [csr, csrErrMsg] =
        getCsr("default", mockRpc.get(),
               /*selfTest=*/true, /*allowDegenerate=*/false, /*requireUdsCerts=*/false);
    ASSERT_EQ(csr, nullptr);
    ASSERT_THAT(csrErrMsg, testing::HasSubstr("challenges do not match"));
}

TEST(LibRkpFactoryExtractionTests, parseCommaDelimitedString) {
    const auto& rpcNames = "default,avf,,default,Strongbox,strongbox,,";
    const auto& rpcSet = parseCommaDelimited(rpcNames);

    ASSERT_EQ(rpcSet.size(), 4);
    ASSERT_TRUE(rpcSet.count("") == 0);
    ASSERT_TRUE(rpcSet.count("default") == 1);
    ASSERT_TRUE(rpcSet.count("avf") == 1);
    ASSERT_TRUE(rpcSet.count("strongbox") == 1);
    ASSERT_TRUE(rpcSet.count("Strongbox") == 1);
}
