#if defined(WIN32)
#include <Windows.h>
#else
#endif // #if defined(WIN32)
#include <pthread.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif
#include <string>
#include "log.hpp"


// We have this global to let the callback get easy access to it
static pthread_mutex_t *lockarray;

#ifdef __cplusplus

bool openssl_load_provider(const std::string &provider_name)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    return false;
#else
    if (!provider_name.empty())
    {
        OSSL_PROVIDER* p_custom_provider = OSSL_PROVIDER_load(NULL, provider_name.c_str());
        if (!p_custom_provider)
        {
            ERR_print_errors_fp(stdout);
            Log::getInstance()->printf(Log::Error, "Provider %s failed to load", provider_name.c_str());
            return false;
        }
        else
        {
            Log::getInstance()->printf(Log::Information, "Loaded custom provider: %s", provider_name.c_str());
        }
    }

    OSSL_PROVIDER* p_default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!p_default_provider)
    {
        ERR_print_errors_fp(stdout);
        Log::getInstance()->printf(Log::Error, "Default Provider failed to load");
        return false;
    }

    return true;
#endif // #if OPENSSL_VERSION_NUMBER < 0x30000000L
}

extern "C" {
#endif // #ifdef __cplusplus

static void lock_callback(int mode, int type, char *file, int line)
{
    (void)file;
    (void)line;
    if (mode & CRYPTO_LOCK)
    {
        pthread_mutex_lock(&(lockarray[type]));
    }
    else
    {
        pthread_mutex_unlock(&(lockarray[type]));
    }
}

static unsigned long thread_id(void)
{
    unsigned long ret;

#if defined(WIN32)
    pthread_t pt = pthread_self();

    ret = (DWORDLONG)pt.p;
#else
    ret = (unsigned long)pthread_self();
#endif // #if defined(WIN32)

    return ret;
}

void openssl_init_locks(void)
{
    lockarray = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() *  sizeof(pthread_mutex_t));
    for (int i = 0; i < CRYPTO_num_locks(); i++)
    {
        pthread_mutex_init(&(lockarray[i]), NULL);
    }
    CRYPTO_set_id_callback((unsigned long (*)())thread_id);
    CRYPTO_set_locking_callback((void (*)(int, int, const char*, int))lock_callback);
}

void openssl_kill_locks(void)
{
    CRYPTO_set_locking_callback(NULL);
    for (int i = 0; i < CRYPTO_num_locks(); i++)
    {
        pthread_mutex_destroy(&(lockarray[i]));
    }
    OPENSSL_free(lockarray);
}

// SSL cleanup (https://wiki.openssl.org/index.php/Library_Initialization)
void openssl_cleanup(void)
{
    CONF_modules_free();
    ERR_remove_state(0);
    ENGINE_cleanup();
    CONF_modules_unload(1);
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
#if OPENSSL_VERSION_NUMBER < 0x10200000L
    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
#else
    // Safe version of the above free of COMP_get_compression_methods which protects
    // from a double free error. Only available in openssl 1.0.2x and greater
    SSL_COMP_free_compression_methods();
#endif
}

#ifdef __cplusplus
}
#endif // #ifdef __cplusplus
