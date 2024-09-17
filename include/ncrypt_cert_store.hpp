
/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Implementation of the win cert store that writes to the Windows Certificate Store using the Ncrypt API
 */
#ifndef NCRYPT_CERT_STORE_HPP
#define NCRYPT_CERT_STORE_HPP

#ifdef _WIN32

#include <string>
#include <wincrypt.h>
#include <ncrypt.h>
#include "win_cert_store_base.hpp"

class NcryptCertStore : public WinCertStoreBase
{
public:
    NcryptCertStore(bool use_user_store, bool leaf_only) : WinCertStoreBase(use_user_store, leaf_only)
    {

    }

    bool initialize() override;

    bool shutdown() override;

    bool isTpmSupported() override
    {
        return true;
    }

    const std::string getProviderName() const
    {
        const std::wstring crypto_provider{ MS_PLATFORM_CRYPTO_PROVIDER };
        return { crypto_provider.begin(), crypto_provider.end() };
    }

    bool importPrivateKey(const std::string &private_key, const std::string& key_id) override;
    
    bool importCertChain(const std::vector<std::string>& certs) override;

    bool deleteCertFromCertStore(const std::string &subject_name) const override;

private:
    /// @brief Import a certificate into the certificate store
    /// @param certificate The certificate to import
    /// @return True on import success, else false
    bool importCertificate(const std::string& certificate) const;


    /// @brief Get a handle for the private key associated with a certificate whose subject name matches the certificate
    /// @param subject_name The subject name used to search for the certificate
    /// @param private_key_handle The key handle for the private key associated with the certificate
    /// @return True on success, else false
    bool getPrivateKeyHandleByCertificateSubjectName(const std::string& subject_name, NCRYPT_KEY_HANDLE& private_key_handle) const;

    /// @brief Create a self-signed certificate
    /// @param key_handle The key handle used to generate the self-signed certificate
    /// @param subject_name The subject name to use for the self-signed certificate
    /// @return True on success, else false
    bool createSelfSignedCertificate(NCRYPT_KEY_HANDLE key_handle, const std::string& subject_name) const;
};

#endif // #ifdef _WIN32

#endif // #ifndef NCRYPT_CERT_STORE_HPP
