
/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Base class for implementations that write to the Windows Certificate Store
 */
#ifndef WIN_CERT_STORE_BASE_HPP
#define WIN_CERT_STORE_BASE_HPP

#ifdef _WIN32

#include <Windows.h>
#include <string>
#include <vector>
#include <wincrypt.h>
#include "log.hpp"

class WinCertStoreBase
{
public:

    static bool extractCertsFromCertificateChain(std::string cert_chain, std::vector<std::string> &certs)
    {
        static const std::string BEGIN_CERTIFICATE_STRING = "-----BEGIN CERTIFICATE-----";

        // Ensure we clear any old contents before appending new
        certs.clear();

        size_t pos = cert_chain.rfind(BEGIN_CERTIFICATE_STRING);
        if (pos == std::string::npos)
        {
            Log::getInstance()->printf(Log::Error, " %s %s", __func__ "Invalid certificate file");
            return false;
        }

        while (pos != std::string::npos)
        {
            const std::string cert = cert_chain.substr(pos);
            certs.push_back(cert);

            if (pos == 0) // last certificate has been processed, exit loop
            {
                break;
            }

            cert_chain = cert_chain.substr(0, pos - 1);
            pos = cert_chain.rfind(BEGIN_CERTIFICATE_STRING);
        }

        return true;
    }

    /// @brief Constructor
    /// @param use_user_store Flag which, when set to true, forces the use of the local user certificate store
    /// @param leaf_only Flag indicating if we should only import the leaf certificate
    WinCertStoreBase(bool use_user_store, bool leaf_only)
        : m_leaf_only{leaf_only}
    {
        if (use_user_store)
        {
            useUserStorage();
        }
    }

    /// @brief Destructor
    virtual ~WinCertStoreBase()
    {
        shutdown();
    }

    /// @brief Initialise the Windows Certificate Store resources
    /// @return True if initialisation successful, else false
    virtual bool initialize() = 0;

    /// @brief Shutdown the Windows Certificate Store resources
    /// @return false if resources not released successfully, else true
    virtual bool shutdown() { return true; };

    /// @brief Indicates whether the TPM is supported by the windows certificate store implementation
    /// @return True if TPM supported, else False
    virtual bool isTpmSupported() = 0;

    /// @brief Returns the name of the provider used by the imlementation of the win cert store
    /// @return The name of the provider, e.g., MS ENHANCED
    virtual const std::string getProviderName() const = 0;

    /// @brief Import the private key into the Windows Certificate Store.
    /// @details Creates a temporary certificate linked to the private key to ensure key
    /// persists in the key store.
    /// @param private_key The private key to store
    /// @param key_id A unique key identifier for this key-pair
    /// @return True on success, else false
    virtual bool importPrivateKey(const std::string &private_key, const std::string &key_id) = 0;

    /// @brief Import a certificate chain PEM string into the Windows Certificate Store
    /// @param cert_chain The certificate chain to import
    /// @return True on success, else false
    virtual bool importCertChain(const std::vector<std::string>& certs) = 0;

    /// @brief Get a subject name from a certificate PEM file
    /// @param certificate The certificate to import
    /// @param subject_name The subject name is returned in this object on success
    /// @return True if success, else false
    bool getSubjectNameFromCertificate(const std::string& certificate, std::string& subject_name) const
    {
        LPBYTE p_cert = NULL;
        ULONG cert_len = cryptCertificateToBinary(certificate, p_cert);

        if (cert_len == 0 || p_cert == NULL)
        {
            return false;
        }

        PCCERT_CONTEXT p_cert_context = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, p_cert, cert_len);
        if (!p_cert_context)
        {
            LocalFree(p_cert);
            return false;
        }

        bool success = false;
        std::wstring wide_subject_name{};
        if (getSubjectNameFromCertificateContext(p_cert_context, wide_subject_name))
        {
            success = true;
        }
        LocalFree(p_cert);

        subject_name = { wide_subject_name.begin(), wide_subject_name.end() };
        return true;
    }

    /// @brief Delete a certificate from the Windows Certificate Store
    /// @param subject_name The subject name of the certificate to delete
    /// @return True on successful deletion, else false
    virtual bool deleteCertFromCertStore(const std::string &subject_name) const = 0;

protected:
    /// The storage location for keys and certificates
    int m_system_store_location = CERT_SYSTEM_STORE_LOCAL_MACHINE;

    /// Flag indicating whether to only store the leaf certificate - if true only leaf is stored
    const bool m_leaf_only;

    /// @brief Get the subject name from a certificate context
    /// @param p_cert_context The certificate context
    /// @param wide_subject_name The wide subject name is stored on success
    /// @return True on success, else false
    bool getSubjectNameFromCertificateContext(PCCERT_CONTEXT p_cert_context, std::wstring& wide_subject_name) const
    {
        DWORD subject_size = CertGetNameString(p_cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
        LPTSTR subject_name = NULL;
        if (!(subject_name = (LPTSTR)malloc(subject_size * sizeof(TCHAR))))
        {
            Log::getInstance()->printf(Log::Error, "MEM alloc failed");
            return false;
        }

        if (!CertGetNameString(p_cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subject_name, subject_size))
        {
            free(subject_name);
            return false;
        }
        wide_subject_name = { subject_name };
        free(subject_name);

        return true;
    }

    ULONG cryptCertificateToBinary(const std::string &certificate, LPBYTE &p_cert) const
    {
        return cryptStringToBinary(certificate, CRYPT_STRING_ANY, p_cert);
    }

    ULONG cryptPrivateKeyToBinary(const std::string &private_key, LPBYTE &p_key) const
    {
        return cryptStringToBinary(private_key, CRYPT_STRING_BASE64HEADER, p_key);
    }

    DWORD decodePrivateKey(LPBYTE p_buffer, ULONG buffer_len, LPCSTR struct_type, LPBYTE& key_blob) const
    {
        // Get size of buffer required to store a decoded key blob
        DWORD key_blob_len = 0;
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, struct_type, p_buffer, buffer_len, 0, nullptr, nullptr, &key_blob_len))
        {
            Log::getInstance()->printf(Log::Error, "Failed CryptDecodeObjectEx");
            key_blob = NULL;
            return 0;
        }

        // Allocate buffer and decode blob as key
        key_blob = (LPBYTE)LocalAlloc(0, key_blob_len);
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, struct_type, p_buffer, buffer_len, 0, nullptr, key_blob, &key_blob_len))
        {
            Log::getInstance()->printf(Log::Error, "Failed CryptDecodeObjectEx");
            LocalFree(key_blob);
            key_blob = NULL;
            return 0;
        }

        return key_blob_len;
    }

    private:
    /// @brief Set the win cert store to the local user certificate store
    void useUserStorage()
    {
        m_system_store_location = CERT_SYSTEM_STORE_CURRENT_USER;
    }

    ULONG cryptStringToBinary(const std::string &str, DWORD crypt_flags, LPBYTE &p_bin) const
    {
        // Get size of the buffer required to crypt public key string to binary
        ULONG bin_len = 0;
        if (!CryptStringToBinaryA(str.c_str(), str.length(), crypt_flags, nullptr, &bin_len, nullptr, nullptr))
        {
            Log::getInstance()->printf(Log::Error, "Failed CryptStringToBinaryA");
            p_bin = NULL;
            return 0;
        }

        // Allocate buffer and crypt public key string to binary
        p_bin = (LPBYTE)LocalAlloc(0, bin_len);
        if (!CryptStringToBinaryA(str.c_str(), str.length(), crypt_flags, p_bin, &bin_len, nullptr, nullptr))
        {
            Log::getInstance()->printf(Log::Error, "Failed CryptStringToBinaryA");
            LocalFree(p_bin);
            p_bin = NULL;
            return 0;
        }

        return bin_len;
    }
};

#endif // #ifdef _WIN32

#endif // #ifndef WIN_CERT_STORE_BASE_HPP
