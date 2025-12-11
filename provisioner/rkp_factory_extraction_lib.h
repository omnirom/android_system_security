/*
 * Copyright 2022 The Android Open Source Project
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

#include <aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.h>
#include <android/binder_manager.h>
#include <cppbor.h>
#include <keymaster/cppcose/cppcose.h>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

// Parse a comma-delimited string.
// Ignores any empty strings.
std::unordered_set<std::string> parseCommaDelimited(const std::string& input);

// Challenge size must be between 32 and 64 bytes inclusive.
constexpr size_t kChallengeSize = 64;

// Contains a the result of an operation that should return cborData on success.
// Returns an an error message and null cborData on error.
template <typename T> struct CborResult {
    std::unique_ptr<T> cborData;
    std::string errMsg;
};

// Generate a random challenge containing `kChallengeSize` bytes.
std::vector<uint8_t> generateChallenge();

// Get a certificate signing request for the given IRemotelyProvisionedComponent.
// On error, the csr Array is null, and the string field contains a description of
// what went wrong.
CborResult<cppbor::Array>
getCsr(std::string_view componentName,
       aidl::android::hardware::security::keymint::IRemotelyProvisionedComponent* irpc,
       bool selfTest, bool allowDegenerate, bool requireUdsCerts);