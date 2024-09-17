/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An function to process any assets (only certificates at the moment)
 */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/md5.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/store.h>
#if _WIN32
#include <openssl/applink.c>
#endif // #if _WIN32
#endif // #if OPENSSL_VERSION_NUMBER

#include "log.hpp"
#include "utils.hpp"
#include "ssl_wrapper.hpp"
#include "dasslcompat.h"

bool SSLWrapper::m_use_custom_storage_provider{false};

SSLWrapper::SSLWrapper()
{
}

SSLWrapper::~SSLWrapper()
{
}

void SSLWrapper::freeAll(void *x509_req, void *pKey, void *bne, void *r, void *bio_key, void *bio_csr)
{
    if (x509_req)
    {
        Log::getInstance()->printf(Log::Debug, " %s Free x509_req", __func__);
        X509_REQ_free((X509_REQ *)x509_req);
        x509_req = nullptr;
    }
    if (pKey)
    {
        EVP_PKEY_free((EVP_PKEY *)pKey);
        pKey = nullptr;
    }
    if (bne)
    {
        BN_free((BIGNUM *)bne);
        bne = nullptr;
    }
    if (r)
    {
        RSA_free((RSA *)r);
        r = nullptr;
    }
    if (bio_key)
    {
        BIO_free_all((BIO *)bio_key);
        bio_key = nullptr;
    }
    if (bio_csr)
    {
        BIO_free_all((BIO *)bio_csr);
        bio_csr = nullptr;
    }
}

int add_ext_csr(STACK_OF(X509_EXTENSION)* sk, X509_REQ* req, int nid, char* value) {

    X509_EXTENSION* ex = nullptr;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, NULL, NULL, req, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
    {
        return 0;
    }
    sk_X509_EXTENSION_push(sk, ex);
    return 1;
}

bool SSLWrapper::generateCSR(const CsrInstructions& csr_info, const std::string& key, const std::string& iv, const std::string& key_id, std::string& csr, std::string& private_key)
{
    std::string priv_str;
    EVP_PKEY *p_public_key = nullptr;
    if (!generateKeyPair(key, iv, priv_str, &p_public_key))
    {
        Log::getInstance()->printf(Log::Error, " %s Failed to generate private key", __func__);
        return false;
    }

    // Set the out value to the private key string
    private_key = priv_str;

    return createX509Request(csr_info, p_public_key, csr);
} //end of generateCSR

bool SSLWrapper::generateKeyPair(const std::string& key, const std::string& iv, std::string &private_key, EVP_PKEY** p_public_key)
{
    Log *p_logger = Log::getInstance();

    const unsigned long e = RSA_F4;
    const int bits = 2048;

    /*Seed the Random number generator.*/
    const std::string rand_str = key + iv;

    RAND_seed(rand_str.c_str(), rand_str.size());
    BIGNUM *bne = BN_new();
    if (!BN_set_word(bne, e))
    {
        p_logger->printf(Log::Error, " %s BN_set_word failed", __func__);
        freeAll(nullptr, nullptr, bne, nullptr, nullptr, nullptr);

        return false;
    }
    // Generate RSA key pair
    RSA *p_rsa = RSA_new();
    if ((p_rsa == NULL) || !RSA_generate_key_ex(p_rsa, bits, bne, NULL))
    {
        p_logger->printf(Log::Error, " %s Generation of RSA key pair failed", __func__);
        freeAll(nullptr, nullptr, bne, p_rsa, nullptr, nullptr);

        return false;
    }
    // Get RSA private key in the memory
    BIO *key_p = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSAPrivateKey(key_p, p_rsa, NULL, NULL, 0, NULL, NULL))
    {
        p_logger->printf(Log::Error, " %s Writing of RSA private key to the memory failed", __func__);
        freeAll(nullptr, nullptr, bne, p_rsa, key_p, nullptr);

        return false;
    }

    // Get public key of x509 req
    *p_public_key = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(*p_public_key, p_rsa))
    {
        p_logger->printf(Log::Error, " %s Failed getting public key from RSA pair", __func__);
        p_rsa = nullptr; // p_key owns p_rsa now
        freeAll(nullptr, *p_public_key, bne, p_rsa, key_p, nullptr);

        return false;
    }
    p_rsa = nullptr; // p_key owns p_rsa now

    // Encrypt and Store
    size_t pri_len = BIO_pending(key_p);
    char *pri_key = new char[pri_len + 1];

    BIO_read(key_p, pri_key, pri_len);
    pri_key[pri_len] = '\0';

    // Set out value to private key
    private_key = std::string(pri_key);

    // No longer need the buffer
    delete [] pri_key;

    // Tidy up
    freeAll(nullptr, nullptr, bne, nullptr, key_p, nullptr);

    return true;
}

bool SSLWrapper::createX509Request(const CsrInstructions& csr_info, EVP_PKEY* public_key, std::string &csr_out_str)
{
    Log *p_logger = Log::getInstance();

    const char* sz_country = "US";
    const char* sz_organization = "Device Authority Ltd";

    // Create a new X509 request and set its version
    X509_REQ *x509_req = X509_REQ_new();
    if (!X509_REQ_set_version(x509_req, 0))
    {
        p_logger->printf(Log::Error, " %s Failed setting X509 version value '%d'", __func__, 0);
        freeAll(x509_req, public_key, nullptr, nullptr, nullptr, nullptr);

        return false;
    }

    // Set subject(Country,Organisation and common name) of x509 req
    X509_NAME* x509_name = X509_REQ_get_subject_name(x509_req);
    if (!X509_NAME_add_entry_by_txt(x509_name, "C", MBSTRING_ASC, (const unsigned char *)sz_country, -1, -1, 0))
    {
        p_logger->printf(Log::Error, " %s Failed setting X509 country value to '%s'", __func__, sz_country);
        freeAll(x509_req, public_key, nullptr, nullptr, nullptr, nullptr);

        return false;
    }
    if (!X509_NAME_add_entry_by_txt(x509_name, "O", MBSTRING_ASC, (const unsigned char *)sz_organization, -1, -1, 0))
    {
        p_logger->printf(Log::Error, " %s Failed setting X509 organization value to '%s'", __func__, sz_organization);
        freeAll(x509_req, public_key, nullptr, nullptr, nullptr, nullptr);

        return false;
    }
    if (!X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC, (const unsigned char *)csr_info.getCommonName().c_str(), -1, -1, 0))
    {
        p_logger->printf(Log::Error, " %s Failed setting X509 common name value to '%s'", __func__, csr_info.getCommonName().c_str());
        freeAll(x509_req, public_key, nullptr, nullptr, nullptr, nullptr);

        return false;
    }

    if (csr_info.applyCaExtension())
    {
        STACK_OF(X509_EXTENSION)* exts = nullptr;
        exts = sk_X509_EXTENSION_new_null();
        add_ext_csr(exts, x509_req, NID_basic_constraints, (char*)"critical,CA:TRUE");
        X509_REQ_add_extensions(x509_req, exts);
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }

    if (!X509_REQ_set_pubkey(x509_req, public_key))
    {
        p_logger->printf(Log::Error, " %s Failed setting public key value in CSR", __func__);
        freeAll(x509_req, public_key, nullptr, nullptr, nullptr, nullptr);

        return false;
    }
    if (!X509_REQ_sign(x509_req, public_key, EVP_sha256()))
    {
        p_logger->printf(Log::Error, " %s Failed signing of CSR", __func__);
        freeAll(x509_req, public_key, nullptr, nullptr, nullptr, nullptr);

        return false;
    }
    // Instead of storing CSR keep it in memory
    BIO* csr_p = BIO_new(BIO_s_mem());
    int ret = PEM_write_bio_X509_REQ(csr_p, x509_req);
    if (ret != 1)
    {
        p_logger->printf(Log::Error, " %s Failed writing of CSR to memory", __func__);
        freeAll(x509_req, public_key, nullptr, nullptr, nullptr, csr_p);

        return false;
    }

    size_t pri_len = BIO_pending(csr_p);
    char *csr = new char[pri_len + 1];
    BIO_read(csr_p, csr, pri_len);
    csr[pri_len] = '\0';
    csr_out_str.assign(csr);
    delete [] csr;

    freeAll(x509_req, public_key, nullptr, nullptr, nullptr, csr_p);

    return true;
}

bool IsNullString(const char * s)
{
    return (s == 0 ? true : false);
}

const std::string SSLWrapper::md5hashstring(const std::string& md5_hash)
{
    const char* const hex_chars = "0123456789abcdef";
    unsigned char digest[16];
    MD5_CTX  context;
    MD5_Init(&context);
    MD5_Update(&context, md5_hash.c_str(), md5_hash.length());
    MD5_Final(digest, &context);

#define NULL_STRING(x)                  IsNullString(x)

    ::std::string value;
    if (!NULL_STRING((char *)&digest[0]))
    {
        for (int i = 0; i < 16; i++)
        {
            value += hex_chars[(digest[i] >> 4) & 0x0f];
            value += hex_chars[digest[i] & 0x0f];
        }
    }

    return value;
}

RSA* createRsaFromPrivateKey(const std::string &key)
{
    BIO* p_keybio = BIO_new_mem_buf((void*)key.c_str(), -1);
    if (p_keybio == nullptr)
    {
        Log::getInstance()->printf(Log::Error, "Keybio failed");
        return nullptr;
    }

    return PEM_read_bio_RSAPrivateKey(p_keybio, nullptr, nullptr, nullptr);
}

X509* createX509FromCertificate(const std::string &cert)
{
    BIO* p_certbio = BIO_new_mem_buf((void*)cert.c_str(), -1);
    if (p_certbio == nullptr)
    {
        Log::getInstance()->printf(Log::Error, "Certbio failed");
        return nullptr;
    }

    return PEM_read_bio_X509(p_certbio, nullptr, nullptr, nullptr);
}

X509* generate_x509(const std::string &common_name, EVP_PKEY* pkey)
{
    Log* p_logger = Log::getInstance();

    const char* sz_country = "US";
    const char* sz_organization = "Device Authority Ltd";
    X509* x509 = X509_new();

    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 3153600L);

    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);

    if (!X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)sz_country, -1, -1, 0))
    {
        p_logger->printf(Log::Error, " %s Failed setting X509 country value to '%s'", __func__, sz_country);

        return 0;
    }
    if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)sz_organization, -1, -1, 0))
    {
        p_logger->printf(Log::Error, " %s Failed setting X509 organization value to '%s'", __func__, sz_organization);

        return 0;
    }
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)common_name.c_str(), -1, -1, 0))
    {
        p_logger->printf(Log::Error, " %s Failed setting X509 common name value to '%s'", __func__, common_name.c_str());

        return 0;
    }

    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_sha256());

    return x509;
}

const std::string SSLWrapper::createSelfSignedCert(
    const std::string &private_key,
    const std::string &common_name)
{
    RSA* p_rsa = createRsaFromPrivateKey(private_key);
    if (p_rsa == nullptr)
    {
        Log* p_logger = Log::getInstance();
        p_logger->printf(Log::Error, "Failed to create private key");
    }

    EVP_PKEY* p_pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(p_pkey, p_rsa);

    BIO* p_bio = BIO_new(BIO_s_mem());
    if (p_bio == nullptr)
    {
        Log* p_logger = Log::getInstance();
        p_logger->printf(Log::Error, "Failed to create bio object");
        return nullptr;
    }

    X509* p_cert = generate_x509(common_name, p_pkey);
    if (PEM_write_bio_X509(p_bio, p_cert) == 0)
    {
        BIO_free(p_bio);
        return nullptr;
    }

    uint64_t num_write = BIO_num_write(p_bio);
    char* pem = new char[(num_write + 1)];
	memset(pem, 0, num_write);
    if (pem == nullptr)
    {
        BIO_free(p_bio);
        return nullptr;
    }

    BIO_read(p_bio, pem, num_write);
    BIO_free(p_bio);

    const std::string certificate(pem);
    delete[] pem;

    return certificate;
}

void SSLWrapper::setUsingCustomStorageProvider(bool state)
{
    m_use_custom_storage_provider = state;
}

bool SSLWrapper::isUsingCustomStorageProvider()
{
    return m_use_custom_storage_provider;
}

bool SSLWrapper::writePrivateKeyToStorageProvider(const std::string &private_key, const std::string &key_id, bool store_encrypted)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    Log::getInstance()->printf(Log::Debug, "%s Writing private key to storage provider. Id: %s", __func__, key_id.c_str());

    RSA* p_rsa = createRsaFromPrivateKey(private_key);
    if (!p_rsa)
    {
        Log::getInstance()->printf(Log::Error, "Failed to create RSA object from private key");
        return false;
    }

    EVP_PKEY* p_private_key = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(p_private_key, p_rsa))
    {
        Log::getInstance()->printf(Log::Error, "Failed to generate EVP_PKEY from RSA object");
        return false;
    }            

    BIO *p_bio = BIO_new(BIO_s_mem());    
    if (!PEM_write_bio_PrivateKey(p_bio, p_private_key, nullptr, (unsigned char *)"", 0, nullptr, (char *)""))
    {
        BIO_free(p_bio);
        return false;
    }

    const OSSL_PARAM params[] =
    {
        {"id", OSSL_PARAM_UTF8_STRING, (void*)key_id.c_str(), key_id.size(), 0},
        {"store_encrypted", OSSL_PARAM_UNSIGNED_INTEGER, &store_encrypted, sizeof(store_encrypted), 0},
        OSSL_PARAM_END
    };
    OSSL_STORE_CTX *p_store_ctx = OSSL_STORE_attach(p_bio, "file", NULL, NULL, NULL, NULL, params, NULL, NULL);
    if (!p_store_ctx)
    {
        BIO_free(p_bio);
        return false;
    }

    bool success = false;
    while (!OSSL_STORE_eof(p_store_ctx))
    {
        OSSL_STORE_INFO *p_store_info = OSSL_STORE_load(p_store_ctx);
        if (p_store_info)
        {
            switch (OSSL_STORE_INFO_get_type(p_store_info))
            {
                case OSSL_STORE_INFO_PKEY:
                    Log::getInstance()->printf(Log::Debug, "Received private key object from storage provider");
#if defined(ENABLE_VERBOSE_LOG)
                    /* Print the private key output */
                    PEM_write_PrivateKey(stdout, OSSL_STORE_INFO_get0_PKEY(p_store_info), NULL, (const unsigned char*)"", 0, NULL, NULL);
#endif // # defined(ENABLE_VERBOSE_LOG)
                    success = true;
                    break;
                default:
                    printf("Unknown type %d\n", OSSL_STORE_INFO_get_type(p_store_info));
                    break;
            }
        }
        else
        {
            Log::getInstance()->printf(Log::Error, "%s Received invalid response from OSSL_STORE_load", __func__);
            ERR_print_errors_fp(stdout);
        }
    }

    OSSL_STORE_close(p_store_ctx);
    BIO_free(p_bio);
    return success;
#else
    return false;
#endif
}

bool SSLWrapper::writeCertificateToStorageProvider(const std::string &certificate, const std::string &cert_id, bool store_encrypted)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    Log::getInstance()->printf(Log::Debug, "%s Writing certificate to storage provider. Id: %s", __func__, cert_id.c_str());
    X509* p_x509 = createX509FromCertificate(certificate);
    if (!p_x509)
    {
        Log::getInstance()->printf(Log::Error, "Failed to create X509 object from certificate");
        return false;
    }

    BIO *p_bio = BIO_new(BIO_s_mem());    
    if (!PEM_write_bio_X509(p_bio, p_x509))
    {
        X509_free(p_x509);
        BIO_free(p_bio);
        return false;
    }
    X509_free(p_x509);
    p_x509 = nullptr;
    
    const OSSL_PARAM params[] =
    {
        {"id", OSSL_PARAM_UTF8_STRING, (void*)cert_id.c_str(), cert_id.size(), 0},
        {"store_encrypted", OSSL_PARAM_UNSIGNED_INTEGER, &store_encrypted, sizeof(store_encrypted), 0},
        OSSL_PARAM_END
    };
    OSSL_STORE_CTX *p_store_ctx = OSSL_STORE_attach(p_bio, "file", NULL, NULL, NULL, NULL, params, NULL, NULL);
    if (!p_store_ctx)
    {
        BIO_free(p_bio);
        return false;
    }

    bool success = false;
    while (!OSSL_STORE_eof(p_store_ctx))
    {
        OSSL_STORE_INFO *p_store_info = OSSL_STORE_load(p_store_ctx);
        if (p_store_info)
        {
            switch (OSSL_STORE_INFO_get_type(p_store_info))
            {
                case OSSL_STORE_INFO_CERT:
                    Log::getInstance()->printf(Log::Debug, "Received certificate object from storage provider");
#if defined(ENABLE_VERBOSE_LOG)
                    /* Print the X.509 certificate text */
                    X509_print_fp(stdout, OSSL_STORE_INFO_get0_CERT(p_store_info));
                    /* Print the X.509 certificate PEM output */
                    PEM_write_X509(stdout, OSSL_STORE_INFO_get0_CERT(p_store_info));
#endif // # defined(ENABLE_VERBOSE_LOG)
                    success = true;
                    break;
                default:
                    printf("Unknown type %d\n", OSSL_STORE_INFO_get_type(p_store_info));
                    break;
            }
        }
        else
        {
            Log::getInstance()->printf(Log::Error, "%s Received invalid response from OSSL_STORE_load", __func__);
            ERR_print_errors_fp(stdout);
        }
    }

    OSSL_STORE_close(p_store_ctx);
    BIO_free(p_bio);
    return success;
#else
    return false;
#endif
}