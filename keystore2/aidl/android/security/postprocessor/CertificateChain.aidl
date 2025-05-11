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

package android.security.postprocessor;

/**
 * General parcelable for holding the encoded certificates to be used in Keystore. This parcelable
 * is returned by `IKeystoreCertificatePostProcessor::processKeystoreCertificates`.
 * @hide
 */
@RustDerive(Clone=true)
parcelable CertificateChain {
    /**
     * Holds the DER-encoded representation of the leaf certificate.
     */
    byte[] leafCertificate;
    /**
     * Holds a byte array containing the concatenation of all the remaining elements of the
     * certificate chain with root certificate as the last with each certificate represented in
     * DER-encoded format.
     */
    byte[] remainingChain;
}
