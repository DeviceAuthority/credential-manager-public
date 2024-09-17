
/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Implementation of the win cert store that writes to the Windows Certificate Store using the Wincrypt API
 */

#ifdef _WIN32
#include <Windows.h>
#include <iostream>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <tchar.h>
#include <stdio.h>
#include "log.hpp"
#include "ssl_wrapper.hpp"
#include "wincrypt_cert_store.hpp"

#pragma comment(lib, "crypt32.lib")

bool WincryptCertStore::initialize()
{
    // Verifies that we have access to the certificate store through the wincrypt API
    HCERTSTORE system_cert_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, m_system_store_location, L"My");
    bool success = system_cert_store != nullptr;
    if (system_cert_store)
    {
        Log::getInstance()->printf(Log::Debug, "Using Microsoft Enhanced Cryptographic Provider");
        CertCloseStore(system_cert_store, 0);
    }
    else
    {
        Log::getInstance()->printf(Log::Error, "Failed to access system store \"My\"");
    }
    return success;
}

bool WincryptCertStore::shutdown()
{
    return true;
}

bool WincryptCertStore::importPrivateKey(const std::string& private_key, const std::string& key_id)
{
    Log* p_logger = Log::getInstance();

    LPBYTE p_buffer = NULL;
    ULONG buffer_len = cryptCertificateToBinary(private_key, p_buffer);

    if (buffer_len == 0 || p_buffer == NULL)
    {
        return false;
    }

    LPBYTE key_blob = NULL;
    DWORD key_blob_len = decodePrivateKey(p_buffer, buffer_len, PKCS_RSA_PRIVATE_KEY, key_blob);
    LocalFree(p_buffer);
    p_buffer = nullptr;

    if (key_blob_len == 0 || key_blob == NULL)
    {
        return false;
    }

    // Acquire the cryptographic service provider: microsoft enhanced provider context
    HCRYPTPROV hcrypt_prov = NULL;
    if (!CryptAcquireContext(&hcrypt_prov, nullptr, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET | CRYPT_VERIFYCONTEXT))
    {
        p_logger->printf(Log::Error, "Failed CryptAcquireContext");
        LocalFree(key_blob);
        return false;
    }

    // Import key blob into the cryptographic service provider
    HCRYPTKEY hcrypt_key = NULL;
    if (!CryptImportKey(hcrypt_prov, key_blob, key_blob_len, NULL, 0, &hcrypt_key))
    {
        p_logger->printf(Log::Error, "Failed CryptImportKey");
        LocalFree(key_blob);
        return false;
    }
    LocalFree(key_blob);
    key_blob = nullptr;

    // Import temporary certificate

    SSLWrapper testing;
    std::string certificate = testing.createSelfSignedCert(private_key, key_id);

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_PKEY* p_evp_private_key = nullptr;
    if ((p_evp_private_key = EVP_PKEY_new()) == nullptr)
    {
        p_logger->printf(Log::Error, "Error Creating EVP_PKEY structure.");
    }

    BIO* p_private_key_bio = BIO_new_mem_buf((void*)private_key.c_str(), -1);
    if (!(p_evp_private_key = PEM_read_bio_PrivateKey(p_private_key_bio, nullptr, nullptr, nullptr)))
    {
        p_logger->printf(Log::Error, "Error Loading privatekey");
    }

    X509* p_cert_x509 = nullptr;
    BIO* p_certificate_bio = BIO_new_mem_buf((void*)certificate.c_str(), -1);
    if (!(p_cert_x509 = PEM_read_bio_X509(p_certificate_bio, nullptr, nullptr, nullptr)))
    {
        p_logger->printf(Log::Error, "Error Loading cert in to BIO");
    }

    STACK_OF(X509)* p_stack = nullptr;
    BIO* p_ca_bio = nullptr;
    X509* p_ca_x509 = nullptr;

    PKCS12* p_pkcs12_bundle = nullptr;
    if ((p_pkcs12_bundle = PKCS12_new()) == nullptr)
    {
        p_logger->printf(Log::Error, "Error creating pkcs bundle.");
    }

    p_pkcs12_bundle = PKCS12_create("", "pkcs12test", p_evp_private_key, p_cert_x509, p_stack, 0, 0, 0, 0, 0);
    if (p_pkcs12_bundle == nullptr)
    {
        p_logger->printf(Log::Error, "Failed to create PKCS12 bundle");
    }

    unsigned char* buf = nullptr;
    int buf_len = i2d_PKCS12(p_pkcs12_bundle, &buf);
    if (buf_len <= 0)
    {
        p_logger->printf(Log::Error, "Error reading the PKCS12 bundle as a DER encoded format");
    }

    // From here it uses wincrypt API
    CRYPT_DATA_BLOB crypt_blob;
    crypt_blob.cbData = buf_len;
    crypt_blob.pbData = buf;

    bool retval = false;
    HCERTSTORE import_cert_store = PFXImportCertStore(&crypt_blob, L"", CRYPT_EXPORTABLE);
    if (import_cert_store == nullptr)
    {
        p_logger->printf(Log::Error, "Failed to open store");
    }
    else
    {
        int i = 0;
        PCCERT_CONTEXT pfx_cert_context = nullptr;
        while (nullptr != (pfx_cert_context = CertEnumCertificatesInStore(import_cert_store, pfx_cert_context)))
        {
            std::wstring wide_subject_name{};
            if (!getSubjectNameFromCertificateContext(pfx_cert_context, wide_subject_name))
            {
                break;
            }

            // Delete existing certificate, if it exists
            deleteCertFromCertStore({ wide_subject_name.begin(), wide_subject_name.end() });

            // Set the certificate property ID
            if (!CertSetCertificateContextProperty(pfx_cert_context, CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID, 0, &hcrypt_prov))
            {
                p_logger->printf(Log::Error, "Failed CertSetCertificateContextProperty");
                break;
            }

            // Open the personal certificate store
            HCERTSTORE user_cert_store;
            if (!(user_cert_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, m_system_store_location, L"My")))
            {
                p_logger->printf(Log::Error, "Error: CertOpenStore(MY) failed");
                break;
            }

            // Add certificate to the personal certificate store
            if (CertAddCertificateContextToStore(user_cert_store, pfx_cert_context, CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES, nullptr))
            {
                retval = true;
            }
            CertCloseStore(user_cert_store, 0);
        }
        CertCloseStore(import_cert_store, 0);
    }

    return retval;
}

bool WincryptCertStore::importCertChain(const std::vector<std::string>& certs)
{
    Log* p_logger = Log::getInstance();

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    const std::string leaf_certificate = certs.back();

    std::string subject_name;
    if (!getSubjectNameFromCertificate(leaf_certificate, subject_name))
    {
        return false;
    }

    // Extract private key using subject name to lookup private key associated with certificate
    std::string private_key;
    if (!exportPrivateKeyPfxFromStore(subject_name, private_key))
    {
        return false;
    }

    EVP_PKEY* p_evp_private_key = nullptr;
    if ((p_evp_private_key = EVP_PKEY_new()) == nullptr)
    {
        p_logger->printf(Log::Error, "Error Creating EVP_PKEY structure.");
    }

    BIO* p_private_key_bio = BIO_new_mem_buf((void*)private_key.c_str(), -1);
    if (!(p_evp_private_key = PEM_read_bio_PrivateKey(p_private_key_bio, nullptr, nullptr, nullptr)))
    {
        p_logger->printf(Log::Error, "Error Loading privatekey");
    }

    X509* p_cert_x509 = nullptr;
    BIO* p_certificate_bio = BIO_new_mem_buf((void*)leaf_certificate.c_str(), -1);
    if (!(p_cert_x509 = PEM_read_bio_X509(p_certificate_bio, nullptr, nullptr, nullptr)))
    {
        p_logger->printf(Log::Error, "Error Loading cert in to BIO");
    }

    STACK_OF(X509)* p_stack = nullptr;
    if ((p_stack = sk_X509_new_null()) == nullptr)
    {
        p_logger->printf(Log::Error, "Error creating p_stack of x509 structure.");
        return false;
    }

    int total_certs = 1;
    for (const auto &cert : certs) // Check if we have some CA certs to import
    {
        if (total_certs == certs.size())
        {
            // Skip the leaf certificate as we are only appending CA certs
            continue;
        }
        const std::string ca_cert = cert;

        BIO* p_ca_bio = BIO_new_mem_buf((void*)ca_cert.c_str(), -1);

        X509* p_ca_x509 = nullptr;
        if (!(p_ca_x509 = PEM_read_bio_X509(p_ca_bio, nullptr, nullptr, nullptr)))
        {
            p_logger->printf(Log::Error, "Error Loading ca in to BIO");
        }

        sk_X509_push(p_stack, p_ca_x509);
        total_certs++;
    }

    PKCS12* p_pkcs12_bundle = nullptr;
    if ((p_pkcs12_bundle = PKCS12_new()) == nullptr)
    {
        p_logger->printf(Log::Error, "Error creating pkcs bundle.");
    }

    p_pkcs12_bundle = PKCS12_create("", "pkcs12test", p_evp_private_key, p_cert_x509, p_stack, 0, 0, 0, 0, 0);
    if (p_pkcs12_bundle == nullptr)
    {
        p_logger->printf(Log::Error, "Failed to create PKCS12 bundle");
    }

    unsigned char* buf = nullptr;
    int buf_len = i2d_PKCS12(p_pkcs12_bundle, &buf);
    if (buf_len <= 0)
    {
        p_logger->printf(Log::Error, "Error reading the PKCS12 bundle as a DER encoded format");
    }

    // From here it uses wincrypt API
    CRYPT_DATA_BLOB crypt_blob;
    crypt_blob.cbData = buf_len;
    crypt_blob.pbData = buf;

    bool retval = false;
    if (FALSE == PFXIsPFXBlob(&crypt_blob))
    {
        p_logger->printf(Log::Error, "Failed to read blob as a PFX packet.");
    }
    else
    {
        HCERTSTORE import_cert_store = PFXImportCertStore(&crypt_blob, L"", CRYPT_EXPORTABLE);
        if (import_cert_store == nullptr)
        {
            p_logger->printf(Log::Error, "Failed to open store");
        }
        else
        {
            int i = 1;
            PCCERT_CONTEXT pfx_cert_context = nullptr;
            while (nullptr != (pfx_cert_context = CertEnumCertificatesInStore(import_cert_store, pfx_cert_context)))
            {
                if (m_leaf_only)
                {
                    if (i < total_certs) // Skips the CA certs (if present)
                    {
                        i++;
                        continue;
                    }
                }

                LPBYTE p_buffer = NULL;
                ULONG buffer_len = cryptPrivateKeyToBinary(private_key, p_buffer);

                if (buffer_len == 0 || p_buffer == NULL)
                {
                    break;
                }

                LPBYTE key_blob = NULL;
                DWORD key_blob_len = decodePrivateKey(p_buffer, buffer_len, PKCS_RSA_PRIVATE_KEY, key_blob);
                LocalFree(p_buffer);
                p_buffer = nullptr;

                // Acquire the cryptographic service provider: microsoft enhanced provider context
                HCRYPTPROV hcrypt_prov = NULL;
                if (!CryptAcquireContext(&hcrypt_prov, nullptr, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET | CRYPT_VERIFYCONTEXT))
                {
                    p_logger->printf(Log::Error, "Failed CryptAcquireContext");
                    LocalFree(key_blob);
                    break;
                }

                // Import key blob into the cryptographic service provider
                HCRYPTKEY hcrypt_key = NULL;
                if (!CryptImportKey(hcrypt_prov, key_blob, key_blob_len, NULL, 0, &hcrypt_key))
                {
                    p_logger->printf(Log::Error, "Failed CryptImportKey");
                    LocalFree(key_blob);
                    break;
                }
                LocalFree(key_blob);
                key_blob = nullptr;

                std::wstring wide_subject_name{};
                if (!getSubjectNameFromCertificateContext(pfx_cert_context, wide_subject_name))
                {
                    break;
                }

                // Delete existing certificate, if it exists
                deleteCertFromCertStore({ wide_subject_name.begin(), wide_subject_name.end() });

                // Set the certificate property ID
                if (!CertSetCertificateContextProperty(pfx_cert_context, CERT_HCRYPTPROV_OR_NCRYPT_KEY_HANDLE_PROP_ID, 0, &hcrypt_prov))
                {
                    p_logger->printf(Log::Error, "Failed CertSetCertificateContextProperty");
                    break;
                }

                // Open the personal certificate store
                HCERTSTORE user_cert_store;
                if (!(user_cert_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, m_system_store_location, L"My")))
                {
                    p_logger->printf(Log::Error, "Error: CertOpenStore(MY) failed");
                    break;
                }

                // Add certificate to the personal certificate store
                if (CertAddCertificateContextToStore(user_cert_store, pfx_cert_context, CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES, nullptr))
                {
                    retval = true;
                }
                CertCloseStore(user_cert_store, 0);
            }
        }
        CertCloseStore(import_cert_store, 0);

        X509_free(p_cert_x509);
        sk_X509_pop_free(p_stack, X509_free);
        PKCS12_free(p_pkcs12_bundle);
        BIO_free(p_private_key_bio);
        BIO_free(p_certificate_bio);
    }
    return retval;
}

int WincryptCertStore::exportPrivateKeyPfxFromStore(const std::string subject_name, std::string &private_key) const
{
    Log* p_logger = Log::getInstance();

    bool found = false;
    PCCERT_CONTEXT p_cert_context = nullptr;
    HCERTSTORE system_cert_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, m_system_store_location, L"My");
    while (p_cert_context = CertEnumCertificatesInStore(system_cert_store, p_cert_context))
    {
        std::wstring wide_subject_name{};
        if (!getSubjectNameFromCertificateContext(p_cert_context, wide_subject_name))
        {
            break;
        }
        if ((strcmp(std::string(wide_subject_name.begin(), wide_subject_name.end()).c_str(), subject_name.c_str()) == 0))
        {
            found = true;
            break;
        }
    }

    if (!found)
    {
        Log::getInstance()->printf(Log::Error, "Failed to export private key. Private key not found.");
        private_key = "";
    }
    else
    {
        HCERTSTORE h_mem_store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, 0);

        CertAddCertificateContextToStore(h_mem_store, p_cert_context, CERT_STORE_ADD_NEW, 0);

        CRYPT_DATA_BLOB crypt_blob = {0};

        if (PFXExportCertStoreEx(h_mem_store, &crypt_blob, L"", 0, EXPORT_PRIVATE_KEYS))
        {
            crypt_blob.pbData = (BYTE *)malloc(crypt_blob.cbData);

            if (PFXExportCertStoreEx(h_mem_store, &crypt_blob, L"", 0, EXPORT_PRIVATE_KEYS))
            {
                EVP_PKEY *pkey = nullptr;
                X509 *cert = nullptr;
                STACK_OF(X509) *ca = nullptr;
                PKCS12 *p12 = nullptr;

                BIO *input = BIO_new_mem_buf((void *)crypt_blob.pbData, crypt_blob.cbData);
                p12 = d2i_PKCS12_bio(input, nullptr);

                PKCS12_parse(p12, "", &pkey, &cert, &ca);
                PKCS12_free(p12);

                if (pkey)
                {
                    BIO *bo = BIO_new(BIO_s_mem());
                    if (PEM_write_bio_PrivateKey(bo, pkey, nullptr, (unsigned char *)"", 0, nullptr, (char *)""))
                    {
                        char *pem = (char *)malloc(BIO_number_written(bo) + 1);
                        if (nullptr == pem)
                        {
                            BIO_free(bo);
                            return NULL;
                        }
                        memset(pem, 0, BIO_number_written(bo) + 1);
                        BIO_read(bo, pem, BIO_number_written(bo));
                        BIO_free(bo);

                        private_key = pem;

                        unsigned char *rsa_private_key_char = (unsigned char *)private_key.c_str();

                        BIO *p_rsa_private_bio = BIO_new_mem_buf(rsa_private_key_char, -1);
                        RSA *p_rsa_private_key = NULL;
                        PEM_read_bio_RSAPrivateKey(p_rsa_private_bio, &p_rsa_private_key, nullptr, nullptr);
                        BIO *p_key = BIO_new(BIO_s_mem());
                        if (!PEM_write_bio_RSAPrivateKey(p_key, p_rsa_private_key, nullptr, nullptr, 0, nullptr, nullptr))
                        {
                            return false;
                        }
                        else
                        {
                            char *key_buffer = (char *)malloc(BIO_number_written(p_key) + 1);
                            if (nullptr == key_buffer)
                            {
                                BIO_free(p_key);
                            }
                            memset(key_buffer, 0, BIO_number_written(p_key) + 1);
                            BIO_read(p_key, key_buffer, BIO_number_written(p_key));
                            BIO_free(p_key);
                            private_key = key_buffer;
                        }
                        free(pem);
                    }
                }
            }
        }
        else
        {
            DWORD error_message_id = ::GetLastError();
            LPSTR message_buffer = nullptr;
            size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error_message_id, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&message_buffer, 0, nullptr);
            std::string message(message_buffer, size);
        }
    }

    if (system_cert_store)
    {
        CertCloseStore(system_cert_store, 0);
    }

    return (int)private_key.length();
}

bool WincryptCertStore::deleteCertFromCertStore(const std::string &subject_name) const
{
    Log* p_logger = Log::getInstance();

    bool success = false;

    HCERTSTORE system_cert_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, m_system_store_location, L"My");
    if (system_cert_store)
    {
        PCCERT_CONTEXT p_store_context = nullptr;
        while (p_store_context = CertEnumCertificatesInStore(system_cert_store, p_store_context))
        {
            std::wstring wide_subject_name{};
            if (!getSubjectNameFromCertificateContext(p_store_context, wide_subject_name))
            {
                break;
            }

            if ((strcmp(std::string(wide_subject_name.begin(), wide_subject_name.end()).c_str(), subject_name.c_str()) == 0))
            {
                PCCERT_CONTEXT p_delete_context = CertDuplicateCertificateContext(p_store_context);
                success = CertDeleteCertificateFromStore(p_delete_context) == TRUE;
            }
        }

        CertCloseStore(system_cert_store, 0);
    }

    return success;
}

#endif // #ifdef _WIN32
