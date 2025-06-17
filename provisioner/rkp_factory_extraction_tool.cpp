/*
 * Copyright 2021 The Android Open Source Project
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

#include <aidl/android/hardware/drm/IDrmFactory.h>
#include <aidl/android/hardware/security/keymint/IRemotelyProvisionedComponent.h>
#include <android/binder_manager.h>
#include <cppbor.h>
#include <gflags/gflags.h>
#include <keymaster/cppcose/cppcose.h>
#include <openssl/base64.h>
#include <remote_prov/remote_prov_utils.h>
#include <sys/random.h>

#include <future>
#include <string>
#include <unordered_set>
#include <vector>

#include "DrmRkpAdapter.h"
#include "rkp_factory_extraction_lib.h"

using aidl::android::hardware::drm::IDrmFactory;
using aidl::android::hardware::security::keymint::IRemotelyProvisionedComponent;
using aidl::android::hardware::security::keymint::RpcHardwareInfo;
using aidl::android::hardware::security::keymint::remote_prov::jsonEncodeCsrWithBuild;
using aidl::android::hardware::security::keymint::remote_prov::RKPVM_INSTANCE_NAME;

DEFINE_string(output_format, "build+csr", "How to format the output. Defaults to 'build+csr'.");
DEFINE_bool(self_test, true,
            "Whether to validate the output for correctness. If enabled, this checks that the "
            "device on the factory line is producing valid output before attempting to upload the "
            "output to the device info service. Defaults to true.");
DEFINE_string(allow_degenerate, "",
              "Comma-delimited list of names of IRemotelyProvisionedComponent instances for which "
              "self_test validation allows degenerate DICE chains in the CSR. Example: "
              "avf,default,strongbox. Defaults to the empty string.");
DEFINE_string(serialno_prop, "ro.serialno",
              "System property from which the serial number should be retrieved. Defaults to "
              "'ro.serialno'.");
DEFINE_string(require_uds_certs, "",
              "Comma-delimited list of names of IRemotelyProvisionedComponent instances for which "
              "UDS certificate chains are required to be present in the CSR. Example: "
              "avf,default,strongbox. Defaults to the empty string.");

namespace {

// Various supported --output_format values.
constexpr std::string_view kBinaryCsrOutput = "csr";     // Just the raw csr as binary
constexpr std::string_view kBuildPlusCsr = "build+csr";  // Text-encoded (JSON) build
                                                         // fingerprint plus CSR.

std::string getFullServiceName(const char* descriptor, const char* name) {
    return  std::string(descriptor) + "/" + name;
}

void writeOutput(const std::string instance_name, const cppbor::Array& csr) {
    if (FLAGS_output_format == kBinaryCsrOutput) {
        auto bytes = csr.encode();
        std::copy(bytes.begin(), bytes.end(), std::ostream_iterator<char>(std::cout));
    } else if (FLAGS_output_format == kBuildPlusCsr) {
        auto [json, error] = jsonEncodeCsrWithBuild(instance_name, csr, FLAGS_serialno_prop);
        if (!error.empty()) {
            std::cerr << "Error JSON encoding the output: " << error << std::endl;
            exit(-1);
        }
        std::cout << json << std::endl;
    } else {
        std::cerr << "Unexpected output_format '" << FLAGS_output_format << "'" << std::endl;
        std::cerr << "Valid formats:" << std::endl;
        std::cerr << "  " << kBinaryCsrOutput << std::endl;
        std::cerr << "  " << kBuildPlusCsr << std::endl;
        exit(-1);
    }
}

void getCsrForIRpc(const char* descriptor, const char* name, IRemotelyProvisionedComponent* irpc,
                   bool allowDegenerate, bool requireUdsCerts) {
    auto fullName = getFullServiceName(descriptor, name);
    // AVF RKP HAL is not always supported, so we need to check if it is supported before
    // generating the CSR.
    if (fullName == RKPVM_INSTANCE_NAME) {
        RpcHardwareInfo hwInfo;
        auto status = irpc->getHardwareInfo(&hwInfo);
        if (!status.isOk()) {
            return;
        }
    }

    auto [request, errMsg] = getCsr(name, irpc, FLAGS_self_test, allowDegenerate, requireUdsCerts);
    if (!request) {
        std::cerr << "Unable to build CSR for '" << fullName << "': " << errMsg << ", exiting."
                  << std::endl;
        exit(-1);
    }

    writeOutput(std::string(name), *request);
}

// Callback for AServiceManager_forEachDeclaredInstance that writes out a CSR
// for every IRemotelyProvisionedComponent.
void getCsrForInstance(const char* name, void* context) {
    auto fullName = getFullServiceName(IRemotelyProvisionedComponent::descriptor, name);
    std::future<AIBinder*> waitForServiceFunc =
        std::async(std::launch::async, AServiceManager_waitForService, fullName.c_str());
    if (waitForServiceFunc.wait_for(std::chrono::seconds(10)) == std::future_status::timeout) {
        std::cerr << "Wait for service timed out after 10 seconds: '" << fullName << "', exiting."
                  << std::endl;
        exit(-1);
    }
    AIBinder* rkpAiBinder = waitForServiceFunc.get();
    ::ndk::SpAIBinder rkp_binder(rkpAiBinder);
    auto rkpService = IRemotelyProvisionedComponent::fromBinder(rkp_binder);
    if (!rkpService) {
        std::cerr << "Unable to get binder object for '" << fullName << "', exiting." << std::endl;
        exit(-1);
    }

    if (context == nullptr) {
        std::cerr << "Unable to get context for '" << fullName << "', exiting." << std::endl;
        exit(-1);
    }

    auto csrValidationConfig = static_cast<CsrValidationConfig*>(context);
    bool allowDegenerateFieldNotNull = csrValidationConfig->allow_degenerate_irpc_names != nullptr;
    bool allowDegenerate = allowDegenerateFieldNotNull &&
                           csrValidationConfig->allow_degenerate_irpc_names->count(name) > 0;
    bool requireUdsCertsFieldNotNull = csrValidationConfig->require_uds_certs_irpc_names != nullptr;
    bool requireUdsCerts = requireUdsCertsFieldNotNull &&
                           csrValidationConfig->require_uds_certs_irpc_names->count(name) > 0;

    // Record the fact that this IRemotelyProvisionedComponent instance was found by removing it
    // from the sets in the context.
    if (allowDegenerateFieldNotNull) {
        csrValidationConfig->allow_degenerate_irpc_names->erase(name);
    }
    if (requireUdsCertsFieldNotNull) {
        csrValidationConfig->require_uds_certs_irpc_names->erase(name);
    }

    getCsrForIRpc(IRemotelyProvisionedComponent::descriptor, name, rkpService.get(),
                  allowDegenerate, requireUdsCerts);
}

}  // namespace

int main(int argc, char** argv) {
    gflags::ParseCommandLineFlags(&argc, &argv, /*remove_flags=*/true);

    auto allowDegenerateIRpcNames = parseCommaDelimited(FLAGS_allow_degenerate);
    auto requireUdsCertsIRpcNames = parseCommaDelimited(FLAGS_require_uds_certs);
    CsrValidationConfig csrValidationConfig = {
        .allow_degenerate_irpc_names = &allowDegenerateIRpcNames,
        .require_uds_certs_irpc_names = &requireUdsCertsIRpcNames,
    };

    AServiceManager_forEachDeclaredInstance(IRemotelyProvisionedComponent::descriptor,
                                            &csrValidationConfig, getCsrForInstance);

    // Append drm CSRs
    for (auto const& [name, irpc] : android::mediadrm::getDrmRemotelyProvisionedComponents()) {
        bool allowDegenerate = allowDegenerateIRpcNames.count(name) != 0;
        allowDegenerateIRpcNames.erase(name);
        auto requireUdsCerts = requireUdsCertsIRpcNames.count(name) != 0;
        requireUdsCertsIRpcNames.erase(name);
        getCsrForIRpc(IDrmFactory::descriptor, name.c_str(), irpc.get(), allowDegenerate,
                      requireUdsCerts);
    }

    // Print a warning for IRemotelyProvisionedComponent instance names that were passed
    // in as parameters to the "require_uds_certs" and "allow_degenerate" flags but were
    // ignored because no instances with those names were found.
    for (const auto& irpcName : allowDegenerateIRpcNames) {
        std::cerr << "WARNING: You requested special handling of 'self_test' validation checks "
                  << "for '" << irpcName << "' via the 'allow_degenerate' flag but no such "
                  << "IRemotelyProvisionedComponent instance exists." << std::endl;
    }
    for (const auto& irpcName : requireUdsCertsIRpcNames) {
        std::cerr << "WARNING: You requested special handling of 'self_test' validation checks "
                  << "for '" << irpcName << "' via the 'require_uds_certs' flag but no such "
                  << "IRemotelyProvisionedComponent instance exists." << std::endl;
    }

    return 0;
}
