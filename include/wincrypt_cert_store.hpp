
/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Implementation of the win cert store that writes to the Windows Certificate Store using the Wincrypt API
 */
#ifndef WINCRYPT_CERT_STORE_HPP
#define WINCRYPT_CERT_STORE_HPP

#ifdef _WIN32

#include <Windows.h>
#include <string>
#include <wincrypt.h>
#include "win_cert_store_base.hpp"

class WincryptCertStore : public WinCertStoreBase
{
public:
    WincryptCertStore(bool use_user_store, bool leaf_only) : WinCertStoreBase(use_user_store, leaf_only)
    {

    }

    bool initialize() override;

    bool shutdown() override;

    bool isTpmSupported() override
    {
        return false;
    }

    const std::string getProviderName() const
    {
        return { MS_ENHANCED_PROV_A };
    }

    bool importPrivateKey(const std::string& private_key, const std::string& key_id) override;

    bool importCertChain(const std::vector<std::string>& certs) override;

    bool deleteCertFromCertStore(const std::string &subject_name) const override;

private:
    int exportPrivateKeyPfxFromStore(const std::string subject_name, std::string& private_key) const;
};

#endif // #ifdef _WIN32

#endif // #ifndef WINCRYPT_CERT_STORE_HPP
