
/*
 * Copyright (c) 2024 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Factory class for the Windows Certificate Store instance to be used on a platform
 */
#ifndef WIN_CERT_STORE_FACTORY_HPP
#define WIN_CERT_STORE_FACTORY_HPP

#if defined(WIN32)

#include "win_cert_store_base.hpp"
#include "wincrypt_cert_store.hpp"
#include "ncrypt_cert_store.hpp"

class WinCertStoreFactory
{
public:
    static WinCertStoreBase* getInstance();

    static void useUserStore(bool use_user_store)
    {
        m_use_user_store = use_user_store;
    }

private:
    // Cannot instantiate this class
    WinCertStoreFactory() = delete;
    ~WinCertStoreFactory() = delete;

    /// @brief The static instance of the Windows certificate store
    static WinCertStoreBase* mp_instance;

    /// @brief Flag indicating whether to use the local user certificate store
    static bool m_use_user_store;
};

#endif // WIN32

#endif // #ifndef WIN_CERT_STORE_FACTORY_HPP
