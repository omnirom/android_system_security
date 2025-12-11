#include "ffi_engine.hpp"

#include <android-base/logging.h>
#include <keymaster/km_openssl/openssl_err.h>
#include <keymaster/km_openssl/openssl_utils.h>

#include <openssl/mem.h>

/* EVP_PKEY_from_keystore is from system/security/keystore-engine. */
extern "C" EVP_PKEY* EVP_PKEY_from_keystore(const char* key_id);

namespace {

const std::string keystore2_grant_id_prefix("ks2_keystore-engine_grant_id:");

/**
 * Perform EC/RSA verify operation using `EVP_PKEY`.
 */
int performVerifySignature(const char* data, size_t data_len, EVP_PKEY* pkey,
                           const unsigned char* signature, size_t signature_len) {
    // Create the verification context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        LOG(ERROR) << "Failed to create verification context";
        return false;
    }

    // Initialize the verification operation
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        LOG(ERROR) << "Failed to initialize verification operation";
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    // Verify the data
    if (EVP_DigestVerifyUpdate(md_ctx, data, data_len) != 1) {
        LOG(ERROR) << "Failed to verify data";
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    // Perform the verification operation
    int ret = EVP_DigestVerifyFinal(md_ctx, signature, signature_len);
    EVP_MD_CTX_free(md_ctx);

    return ret == 1;
}

/**
 * Perform EC/RSA sign operation using `EVP_PKEY`.
 */
bool performSignData(const char* data, size_t data_len, EVP_PKEY* pkey, unsigned char** signature,
                     size_t* signature_len) {
    // Create the signing context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        LOG(ERROR) << "Failed to create signing context";
        return false;
    }

    // Initialize the signing operation
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        LOG(ERROR) << "Failed to initialize signing operation";
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    // Sign the data
    if (EVP_DigestSignUpdate(md_ctx, data, data_len) != 1) {
        LOG(ERROR) << "Failed to sign data";
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    // Determine the length of the signature
    if (EVP_DigestSignFinal(md_ctx, NULL, signature_len) != 1) {
        LOG(ERROR) << "Failed to determine signature length";
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    // Allocate memory for the signature
    *signature = (unsigned char*)malloc(*signature_len);
    if (*signature == NULL) {
        LOG(ERROR) << "Failed to allocate memory for the signature";
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    // Perform the final signing operation
    if (EVP_DigestSignFinal(md_ctx, *signature, signature_len) != 1) {
        LOG(ERROR) << "Failed to perform signing operation";
        free(*signature);
        EVP_MD_CTX_free(md_ctx);
        return false;
    }

    EVP_MD_CTX_free(md_ctx);
    return true;
}

}  // namespace

/**
 * Extract the `EVP_PKEY` for the given KeyMint Key and perform Sign/Verify operations
 * using extracted `EVP_PKEY`.
 */
extern "C" bool performCryptoOpUsingKeystoreEngine(int64_t grant_id) {
    const int KEY_ID_LEN = 20;
    char key_id[KEY_ID_LEN] = "";
    snprintf(key_id, KEY_ID_LEN, "%" PRIx64, grant_id);
    std::string str_key = std::string(keystore2_grant_id_prefix) + key_id;
    bool result = false;

    EVP_PKEY* evp = EVP_PKEY_from_keystore(str_key.c_str());
    if (!evp) {
        LOG(ERROR) << "Error while loading a key from keystore-engine";
        return false;
    }

    int algo_type = EVP_PKEY_id(evp);
    if (algo_type != EVP_PKEY_RSA && algo_type != EVP_PKEY_EC) {
        LOG(ERROR) << "Unsupported Algorithm. Only RSA and EC are allowed.";
        EVP_PKEY_free(evp);
        return false;
    }

    unsigned char* signature = NULL;
    size_t signature_len = 0;
    const char* INPUT_DATA = "MY MESSAGE FOR SIGN";
    size_t data_len = strlen(INPUT_DATA);
    if (!performSignData(INPUT_DATA, data_len, evp, &signature, &signature_len)) {
        LOG(ERROR) << "Failed to sign data";
        EVP_PKEY_free(evp);
        return false;
    }

    result = performVerifySignature(INPUT_DATA, data_len, evp, signature, signature_len);
    if (!result) {
        LOG(ERROR) << "Signature verification failed";
    } else {
        LOG(INFO) << "Signature verification success";
    }

    free(signature);
    EVP_PKEY_free(evp);

    return result;
}
