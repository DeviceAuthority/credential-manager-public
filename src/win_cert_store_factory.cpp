#ifdef WIN32

#include "constants.hpp"
#include "configuration.hpp"
#include "win_cert_store_factory.hpp"

WinCertStoreBase* WinCertStoreFactory::mp_instance = nullptr;
bool WinCertStoreFactory::m_use_user_store = false;

WinCertStoreBase* WinCertStoreFactory::getInstance()
{
    if (mp_instance == nullptr)
    {
        const bool store_leaf_only = config.lookup(CFG_STORE_FULL_CERTIFICATE_CHAIN) == "TRUE" ? false : true;
        if (config.lookup(CFG_FORCE_MS_ENHANCED_PROVIDER) == "TRUE")
        {
            mp_instance = new WincryptCertStore(m_use_user_store, store_leaf_only);
            mp_instance->initialize();
        }
        else
        {
            mp_instance = new NcryptCertStore(m_use_user_store, store_leaf_only);
            if (!mp_instance->initialize())
            {
                // Failed to initialise CNG store so we fall back to legacy wincrypt store
                delete mp_instance;
                mp_instance = new WincryptCertStore(m_use_user_store, store_leaf_only);
                mp_instance->initialize();
            }
        }
    }

    return mp_instance;
}

#endif // #ifdef WIN32
