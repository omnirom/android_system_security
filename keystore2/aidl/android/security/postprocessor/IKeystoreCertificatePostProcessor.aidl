/*
 * Copyright (C) 2024 The Android Open Source Project
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

package android.security.postprocessor;

import android.security.postprocessor.CertificateChain;

interface IKeystoreCertificatePostProcessor {
    /**
     * Allows implementing services to process the keystore certificates after the certificate
     * chain has been generated.
     *
     * certificateChain holds the chain associated with a newly generated Keystore asymmetric
     * keypair, where the leafCertificate is the certificate for the public key of generated key.
     * The remaining attestation certificates are stored as a concatenated byte array of the
     * encoded certificates with root certificate as the last element.
     *
     * Successful calls would get the processed certificate chain which then replaces the original
     * certificate chain. In case of any failures/exceptions, keystore would fallback to the
     * original certificate chain.
     *
     * @hide
     */
    CertificateChain processKeystoreCertificates(in CertificateChain certificateChain);
}
