   /*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * A wrapper for the Device Authority security calls
 */

#include <algorithm>
#include <string>
#if defined(WIN32)
#include <codecvt>
#else
#include <dlfcn.h>
#endif // #if defined(WIN32)
#include "configuration.hpp"
#include "log.hpp"
#include "utils.hpp"
#include "constants.hpp"
#include "dahttpclient.hpp"
#include "deviceauthority.hpp"
#include "DeviceKeyDef.h"
#include "log.hpp"

using namespace rapidjson;


#if defined(WIN32)
#if !defined(strdup)
#define strdup  _strdup
#endif // #if !defined(strdup)
#endif // #if defined(WIN32)

#if defined(USETHREADING)
#if !defined(PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP)
pthread_mutex_t DeviceAuthority::mutexDA_;
bool mutexDA_initialised = false;
#else
pthread_mutex_t DeviceAuthority::mutexDA_ = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
#endif // #if !defined(PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP)
#endif // #if defined(USETHREADING)
DeviceAuthorityBase *DeviceAuthority::mp_da_instance = nullptr;

/// @brief Lock the thread if threading is enabled
void DeviceAuthority::mutex_lock()
{
#if defined(USETHREADING)
#if !defined(PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP)
    if (!mutexDA_initialised)
    {
        // Initialise a custom recursive mutex object as the macro 
        // PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP is unavailable
        pthread_mutexattr_t mut_attr = {0};
        pthread_mutexattr_init(&mut_attr);
        pthread_mutexattr_settype(&mut_attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&mutexDA_, &mut_attr);
        pthread_mutexattr_destroy(&mut_attr);
        mutexDA_initialised = true;
    }
#endif // PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP
    pthread_mutex_lock(&mutexDA_);
#endif // #if defined(USETHREADING)
}

/// @brief Unlock the thread if threading is enabled
void DeviceAuthority::mutex_unlock()
{
#if defined(USETHREADING)
    pthread_mutex_unlock(&mutexDA_);
#endif // #if defined(USETHREADING)
}

typedef union
{
    NAUDADDK_GETDEVICEKEYWITHCHALLENGE_WITHDEVICEROLE_PROC pfnaudaddk_getdevicekeywithchallenge_withdevicerole;
    NAUDADDK_GETDEVICEKEYWITHCHALLENGE_WITHDEVICEMETA_PROC pfnaudaddk_getdevicekeywithchallenge_withdevicemeta;
    NAUDADDK_DOCIPHER_AES_CFB128_PROC pfnaudaddk_docipher_aes_cfb128;
    NAUDADDK_DODIGEST_SHA256_PROC pfnaudaddk_dodigest_sha256;
    NAUDADDK_GETDEVICEKEY_PROC pfnaudaddk_getdevicekey;
    NAUDADDK_GETDEVICETID_PROC pfnaudaddk_getdevicetid;
    NAUDADDK_GETDEVICEKEYOAEP_PROC pfnaudaddk_getdevicekeyoaep;
    NAUDADDK_GETDEVICEKEY_FOREDGE_PROC pfnaudaddk_getdevicekey_foredge;
    NAUDADDK_FREEDEVICEKEY_PROC pfnaudaddk_freedevicekey;
    NAUDADDK_GETDEVICEKEYVERSION_PROC pfnaudaddk_getdevicekeyversion;
    NAUDADDK_GETUSERAGENTSTRING_PROC pfnaudaddk_getuseragentstring;
    NAUDADDK_GETPLATFORMSTRING_PROC pfnaudaddk_getplatformstring;
    NAUDADDK_FREEBUFFER_PROC pfnaudaddk_freebuffer;
    NAUDADDK_GLOBALINIT_PROC pfnaudaddk_globalinit;
    NAUDADDK_GLOBALCLEANUP_PROC  pfnaudaddk_globalcleanup;
    NAUDADDK_SETUDI_PROC pfnaudaddk_setudi;
    NAUDADDK_GETUDI_PROC pfnaudaddk_getudi;
    NAUDADDK_EXTDDKG_SETUDIPROPERTYNAME pfnaudaddk_extddkg_setudipropertyname;
    NAUDADDK_SETROOTFS_PROC pfnaudaddk_setrootfs;
    void *obj;
} uNAUDADDKFuncPtrAlias;

string processError(const string& apiurl,  rapidjson::Document& json, DAErrorCode errorcode)
{
    ostringstream oss;

    //if (json.apiMismatched())
    //{
    //    oss << "Incompatible API version caused request to fail.";
    //}
    //else
    if (errorcode == ERR_CURL)
    {
        oss << "Connect to API '" << apiurl << "' failed (cURL code " << errorcode << ").";
    }
    else
    {
        oss << "Connect to API '" << apiurl << "' failed (code " << errorcode << ").";
    }
    return oss.str();
}

void processStatusCode(const std::string& action, const rapidjson::Document& json, std::string& message)
{
    if (json.HasMember("message"))
    {
        const rapidjson::Value& msg_val = json["message"];
        if (msg_val.HasMember("errorMessage"))
        {
            const rapidjson::Value& errMsgVal = msg_val["errorMessage"];

            std::string errorCode = "";
            if (json.HasMember("statusCode"))
            {
                int daeErrorCode = json["statusCode"].GetInt();
                std::ostringstream oss;
                oss << "(DAE code " << daeErrorCode << ")";
                errorCode = oss.str();
            }

            if (!errMsgVal.IsNull())
            {
                const std::string& data = errMsgVal.GetString();
                if (!data.empty())
                {
                    message = action + " failed with error: " + data + " " + errorCode;
                }
            }
        }
    }
    else
    {
        message = action + " failed with unexpected error";
    }
    Log::getInstance()->printf(Log::Debug, " %s Got errorMessage: %s", __func__, message.c_str());
}

const char* DeviceAuthority::CHTYPEAUTH_TEXT = "auth";
const char* DeviceAuthority::CHTYPEFULL_TEXT = "full";

/*Not to be called by agents..only for libda.so*/
DeviceAuthorityBase *DeviceAuthority::getInstanceForApp(const std::string& DAUser,const std::string& DAAPIURL, const std::string& deviceName, const std::string& cryptoProvider)
{
    mutex_lock();

    Log *logger = Log::getInstance();
    if (logger)
    {
        logger->printf(Log::Information, " %s Enter", __func__);
    }

    if (!mp_da_instance)
    {
        mp_da_instance = new DeviceAuthority(DAUser, DAAPIURL, deviceName, cryptoProvider);
        if (logger)
        {
            logger->printf(Log::Information, " %s Created DA instance with DAUser: %s, DAAPIURL: %s, userAgent: %s", __func__, DAUser.c_str(), DAAPIURL.c_str(), mp_da_instance->userAgentString().c_str());
        }
    }
    else
    {
        // Setting APIURL and user so that the instance always has valid API URL and user Id for the case of LD_PRELOAD
        mp_da_instance->setAPIURL(DAAPIURL);
        mp_da_instance->setUserId(DAUser);
        if (logger)
        {
            logger->printf(Log::Debug, " %s Return existing DeviceAuthority singleton object", __func__);
        }
        logger->printf(Log::Information, " %s DAUser: %s, DAAPIURL: %s, userAgent: %s", __func__, DAUser.c_str(), DAAPIURL.c_str(), mp_da_instance->userAgentString().c_str());
    }
    mutex_unlock();

    return mp_da_instance;
}

DeviceAuthorityBase *DeviceAuthority::getInstanceForEdge(const std::string& DAUser, const std::string& DAAPIURL, const std::string& deviceName, const std::string& cryptoProvider, const std::string& edgePublicKeyJSON)
{
    mutex_lock();

    Log *logger = Log::getInstance();

    if (logger)
    {
        logger->printf(Log::Information, " %s Enter", __func__);
    }
    if (!mp_da_instance )
    {
        mp_da_instance = new DeviceAuthority(DAUser, DAAPIURL, deviceName, cryptoProvider);
        if (logger)
        {
            logger->printf(Log::Information, " %s Created DA instance with DAUser: %s, DAAPIURL: %s, userAgent: %s", __func__, DAUser.c_str(), DAAPIURL.c_str(), mp_da_instance->userAgentString().c_str());
        }
    }
    
    mutex_unlock();

    return mp_da_instance;
}

void DeviceAuthority::setInstance(DeviceAuthorityBase* pDeviceAuthority)
{
    if (mp_da_instance)
    {
        mp_da_instance->destroyInstance();
    }

    mp_da_instance = pDeviceAuthority;
}

DeviceAuthorityBase *DeviceAuthority::getInstance()
{
    mutex_lock();

    Log *p_logger = Log::getInstance();

    //if (logger)
    //{
    //    logger->printf(Log::Debug, " %s Enter", __func__);
    //}
    if (!mp_da_instance)
    {
        static const std::string DAUser = config.lookup(CFG_DAUSERID);
        static const std::string DAAPIURL = config.lookup(CFG_DAAPIURL);
        static const std::string deviceName = config.lookup(CFG_DEVICENAME);
        static const std::string cryptoProvider = config.lookup(CFG_KEYSTORE_PROVIDER);
#if defined(WIN32)
        static const std::string libDir = config.lookup(CFG_LIBDIR);
        static const std::string ddkgLib = config.lookup(CFG_DDKGLIB);

        mp_da_instance = new DeviceAuthority(DAUser, DAAPIURL, deviceName, cryptoProvider, ddkgLib, libDir);
#else
        mp_da_instance = new DeviceAuthority(DAUser, DAAPIURL, deviceName, cryptoProvider);
#endif // #if defined(WIN32)
    }
    
    mutex_unlock();

    return mp_da_instance;
}

bool DeviceAuthority::destroyInstance()
{
    mutex_lock();

    if (mp_da_instance)
    {
        if (pfnaudaddk_globalcleanup)
        {
            Log::getInstance()->printf(Log::Debug, " %s Calling pfnaudaddk_globalcleanup", __func__);
            pfnaudaddk_globalcleanup();
            Log::getInstance()->printf(Log::Debug, " %s Calling pfnaudaddk_globalcleanup Done", __func__);
        }
        // Calls DeviceAuthority destructor
        delete mp_da_instance;
        mp_da_instance = nullptr;
    }
    
    mutex_unlock();

    return true;
}

void DeviceAuthority::setAPIURL(const std::string& APIURL)
{
    m_APIURL = APIURL;
}

void DeviceAuthority::setUserId(const std::string& user)
{
    m_user = user;
}

const std::string& DeviceAuthority::userAgentString() const
{
    return m_user_agent;
}

const std::string& DeviceAuthority::platformString() const
{
    return m_platform;
}

bool DeviceAuthority::setUDI(const std::string &udi) const
{
    if (!udi.empty() && pfnaudaddk_setudi != nullptr)
    {
        const auto result = pfnaudaddk_setudi(udi.c_str(), udi.length());
        if (result == 0)
        {
            return true;
        }

        Log::getInstance()->printf(Log::Error, " %s Failed to set UDI: rc %d", __func__, result);
    }

    return false;
}

const std::string DeviceAuthority::getUDI() const
{
    if (pfnaudaddk_getudi == nullptr)
    {
        return "";
    }

    char *raw_udi = NULL;
    int result = pfnaudaddk_getudi(&raw_udi);
    if (result != kDDKStatusSuccess)
    {
        Log::getInstance()->printf(Log::Error, " %s Failed to get UDI: rc %d", __func__, result);
        return "";
    }
    
    std::string udi = "";
    if (raw_udi)
    {
        udi.append(raw_udi);
        pfnaudaddk_freebuffer(&raw_udi);
    }
    return udi;
}

bool DeviceAuthority::setExtDdkgUDIPropertyName(const std::string &udi_property) const
{
    if (!udi_property.empty() && pfnaudaddk_extddkg_setudipropertyname != nullptr)
    {
        const auto result = pfnaudaddk_extddkg_setudipropertyname(udi_property.c_str(), udi_property.length());
        if (result == 0)
        {
            return true;
        }

        Log::getInstance()->printf(Log::Error, " %s Failed to set ExtDDKG UDI property name: rc %d", __func__, result);
    }

    return false;
}

bool DeviceAuthority::setDdkgRootFilepath(const std::string &ddkg_root_fs) const
{
    if (!ddkg_root_fs.empty() && pfnaudaddk_setrootfs != nullptr)
    {
        const auto result = pfnaudaddk_setrootfs(ddkg_root_fs.c_str(), ddkg_root_fs.length());
        if (result == 0)
        {
            return true;
        }

        Log::getInstance()->printf(Log::Error, " %s Failed to set DDKG root filesystem path: rc %d", __func__, result);
    }

    return false;
}

DeviceAuthority::DeviceAuthority(const std::string& user, const std::string& APIURL, const std::string& deviceName, const std::string& cryptoProvider) 
    : mp_event_manager(nullptr)
    , m_registered(false)
    , m_user(user)
    , m_APIURL(APIURL)
    , m_user_agent("")
    , m_platform("")
    , m_device_name(deviceName)
    , m_crypto_provider(cryptoProvider)
#if defined(WIN32)
    , ddkgLib_("")
    , libDir_("")
#endif // #if defined(WIN32)
    , pfnaudaddk_getdevicekeywithchallenge_withdevicerole(NULL)
    , pfnaudaddk_getdevicekeywithchallenge_withdevicemeta(NULL)
    , pfnaudaddk_docipher_aes_cfb128(NULL)
    , pfnaudaddk_dodigest_sha256(NULL)
    , pfnaudaddk_getdevicekey(NULL)
    , pfnaudaddk_getdevicekeyoaep(NULL)
    , pfnaudaddk_getdevicekey_foredge(NULL)
    , pfnaudaddk_freedevicekey(NULL)
    , pfnaudaddk_getdevicekeyversion(NULL)
    , pfnaudaddk_getuseragentstring(NULL)
    , pfnaudaddk_getplatformstring(NULL)
    , pfnaudaddk_freebuffer(NULL)
    , pfnaudaddk_globalinit(NULL)
    , pfnaudaddk_globalcleanup(NULL)
    , pfnaudaddk_setudi(NULL)
    , pfnaudaddk_getudi(NULL)
    , pfnaudaddk_extddkg_setudipropertyname(NULL)
    , pfnaudaddk_setrootfs(NULL)
    , m_deviceTID("")
    , m_hdll(NULL)
    , m_is_edge_node(false)
{
    // m_device_name may be blank and if so use the hostname of the device to provide a name
    if (m_device_name.empty())
    {
#if __STDC_WANT_SECURE_LIB__
        size_t requiredSize = 0;
        char *libvar = NULL;

        getenv_s(&requiredSize, NULL, 0, "COMPUTERNAME");
        if (requiredSize > 0)
        {
            libvar = new char[(requiredSize * sizeof(char)) + 1];
            if (libvar)
            {
                // Get the value of the COMPUTERNAME environment variable
                getenv_s(&requiredSize, libvar, requiredSize, "COMPUTERNAME");
                m_device_name = libvar;
                delete [] libvar;
                libvar = NULL;
            }
            else
            {
                Log::getInstance()->printf(Log::Error, " Unable to allocate memory", __func__);
            }
        }
        else
        {
            Log::getInstance()->printf(Log::Debug, " environment variable 'COMPUTERNAME' not defined", __func__);
        }
#else
        if (getenv("HOSTNAME") != NULL)
        {
            m_device_name = getenv("HOSTNAME");
        }
#endif // #if __STDC_WANT_SECURE_LIB__
    }
    
    // m_user may be blank for authorisationless authentication and registration
    // If log is passed in then also log lib errors to it.  Done this way because for the http proxy
    // nginx does not use our logger (it has its own)
    if (!loadLibrary())
    {
        static const char* error = "Unable to find functions in ddk library, exiting...";

        std::cerr << error << std::endl;
        Log::getInstance()->printf(Log::Critical, " %s %s", __func__, error);
        exit(1);
    }
    else
    {
        //Log::getInstance()->printf(Log::Debug, " %s Calling pfnaudaddk_globalinit", __func__);
        if (pfnaudaddk_globalinit)
        {
            pfnaudaddk_globalinit();
        }
    }
}

#if defined(WIN32)
DeviceAuthority::DeviceAuthority(const std::string& user, const std::string& APIURL, const std::string& deviceName, const std::string& cryptoProvider, const std::string& ddkgLib, const std::string& libDir) : 
    mp_event_manager(nullptr),
    m_registered(false),
    m_user(user), 
    m_APIURL(APIURL), 
    m_user_agent(""), 
    m_platform(""), 
    m_device_name(deviceName), 
    m_crypto_provider(cryptoProvider), 
    ddkgLib_(ddkgLib), 
    libDir_(libDir),
    pfnaudaddk_getdevicekeywithchallenge_withdevicerole(NULL),
    pfnaudaddk_getdevicekeywithchallenge_withdevicemeta(NULL),
    pfnaudaddk_docipher_aes_cfb128(NULL),
    pfnaudaddk_dodigest_sha256(NULL),
    pfnaudaddk_getdevicekey(NULL),
    pfnaudaddk_getdevicekeyoaep(NULL),
    pfnaudaddk_getdevicekey_foredge(NULL),
    pfnaudaddk_freedevicekey(NULL),
    pfnaudaddk_getdevicekeyversion(NULL),
    pfnaudaddk_getuseragentstring(NULL),
    pfnaudaddk_getplatformstring(NULL),
    pfnaudaddk_freebuffer(NULL),
    pfnaudaddk_globalinit(NULL),
    pfnaudaddk_globalcleanup(NULL),
    pfnaudaddk_setudi(NULL),
    pfnaudaddk_getudi(NULL),
    pfnaudaddk_extddkg_setudipropertyname(NULL),
    pfnaudaddk_setrootfs(NULL),
    m_deviceTID(""),
    m_hdll(NULL),
    m_is_edge_node(false)
{
    // m_device_name may be blank and if so use the hostname of the device to provide a name
    if (m_device_name.empty())
    {
#if __STDC_WANT_SECURE_LIB__
        size_t requiredSize = 0;
        char *libvar = NULL;

        getenv_s(&requiredSize, NULL, 0, "COMPUTERNAME");
        if (requiredSize > 0)
        {
            libvar = new char[(requiredSize * sizeof(char)) + 1];
            if (libvar)
            {
                // Get the value of the COMPUTERNAME environment variable
                getenv_s(&requiredSize, libvar, requiredSize, "COMPUTERNAME");
                m_device_name = libvar;
                delete [] libvar;
                libvar = NULL;
            }
            else
            {
                Log::getInstance()->printf(Log::Error, " Unable to allocate memory", __func__);
            }
        }
        else
        {
            Log::getInstance()->printf(Log::Debug, " environment variable 'COMPUTERNAME' not defined", __func__);
        }
#else
        if (getenv("HOSTNAME") != NULL)
        {
            m_device_name = getenv("HOSTNAME");
        }
#endif // #if __STDC_WANT_SECURE_LIB__
    }
    
    // m_user may be blank for authorisationless authentication and registration
    // If log is passed in then also log lib errors to it.  Done this way because for the http proxy
    // nginx does not use our logger (it has its own)
    if (!loadLibrary())
    {
        static const char* error = "Unable to find functions in ddk library, exiting...";

        std::cerr << error << std::endl;
        Log::getInstance()->printf(Log::Critical, " %s %s", __func__, error);
        exit(1);
    }
    else
    {
        //Log::getInstance()->printf(Log::Debug, " %s Calling pfnaudaddk_globalinit", __func__);
        if (pfnaudaddk_globalinit)
        {
            pfnaudaddk_globalinit();
        }
    }
}
#endif // #if defined(WIN32)

DeviceAuthority::~DeviceAuthority()
{
    mutex_lock();

    //Log::getInstance()->printf( Log::Debug, "%s destructor called  ",__func__);
    if (m_hdll != NULL)
    {
#if defined(WIN32)
#else
        dlclose(m_hdll);
#endif // #if defined(WIN32)
        m_hdll = NULL;
    }
    
    mutex_unlock();
}

bool DeviceAuthority::loadLibrary()
{
    Log *logger = Log::getInstance();

#ifdef _WIN32
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;

    // Windows platform
    if (!libDir_.empty())
    {
        // Convert string to wide-string
        std::wstring sLibDir = conv.from_bytes(libDir_.c_str());

        SetDllDirectory(sLibDir.c_str());
    }
    if (!ddkgLib_.empty())
    {
        // Convert string to wide-string
        std::wstring sDdkgLib = conv.from_bytes(ddkgLib_.c_str());

        // Dynamically load DDKG shared library
        m_hdll = LoadLibrary(sDdkgLib.c_str());
    }
    if (m_hdll == NULL)
    {
        Log::getInstance()->printf(Log::Warning, "Unable to load %s, exiting...", ddkgLib_.c_str());
        // Dynamically load DDKG shared library
        m_hdll = LoadLibrary(NPUDADDK_DLL);
    }
    if (m_hdll == NULL)
    {
        DWORD err = GetLastError();

        std::cerr << "Unable to load " << NPUDADDK_DLL << std::endl;
        Log::getInstance()->printf(Log::Critical, "Unable to load %S, exiting...", NPUDADDK_DLL);
        exit(err);
    }
#if DDKGLIB_STATIC_LINK
    // Statically linked DDKG static libraries
    pfnaudaddk_globalinit = naudaddk_globalinit;
    pfnaudaddk_globalcleanup = naudaddk_globalcleanup;
    pfnaudaddk_getdevicekeywithchallenge_withdevicerole = naudaddk_getdevicekeywithchallenge_withdevicerole;
    pfnaudaddk_getdevicekeywithchallenge_withdevicemeta = naudaddk_getdevicekeywithchallenge_withdevicemeta;
    pfnaudaddk_docipher_aes_cfb128 = naudaddk_docipher_aes_cfb128;
    pfnaudaddk_dodigest_sha256 = naudaddk_dodigest_sha256;
    pfnaudaddk_getdevicekey = naudaddk_getdevicekey;
    pfnaudaddk_getdevicekeyoaep = naudaddk_getdevicekeyoaep;
    pfnaudaddk_getdevicetid = naudaddk_getdevicetid;
    pfnaudaddk_getdevicekey_foredge = naudaddk_getdevicekey_foredge;
    //pfnaudaddk_getdevicetid = naudaddk_getdevicetid;
    pfnaudaddk_freedevicekey = naudaddk_freedevicekey;
    pfnaudaddk_getdevicekeyversion = naudaddk_getdevicekeystring;
    pfnaudaddk_getuseragentstring = naudaddk_getuseragentstring;
    pfnaudaddk_getplatformstring = naudaddk_getplatformstring;
    pfnaudaddk_freebuffer = naudaddk_freebuffer;
    pfnaudaddk_setudi = naudaddk_setudi;
    pfnaudaddk_getudi = naudaddk_getudi;
    pfnaudaddk_extddkg_setudipropertyname = naudaddk_extddkg_setudipropertyname;
    pfnaudaddk_setrootfs = naudaddk_setrootfs;
#else
    // Dynamically load DDKG shared library
    pfnaudaddk_globalinit = (NAUDADDK_GLOBALINIT_PROC)GetProcAddress(m_hdll, "naudaddk_globalinit");
    pfnaudaddk_globalcleanup = (NAUDADDK_GLOBALCLEANUP_PROC)GetProcAddress(m_hdll, "naudaddk_globalcleanup");
    pfnaudaddk_getdevicekeywithchallenge_withdevicerole = (NAUDADDK_GETDEVICEKEYWITHCHALLENGE_WITHDEVICEROLE_PROC)GetProcAddress(m_hdll, "naudaddk_getdevicekeywithchallenge_withdevicerole");
    pfnaudaddk_getdevicekeywithchallenge_withdevicemeta = (NAUDADDK_GETDEVICEKEYWITHCHALLENGE_WITHDEVICEMETA_PROC)GetProcAddress(m_hdll, "naudaddk_getdevicekeywithchallenge_withdevicemeta");
    pfnaudaddk_docipher_aes_cfb128 = (NAUDADDK_DOCIPHER_AES_CFB128_PROC)GetProcAddress(m_hdll, "naudaddk_docipher_aes_cfb128");
    pfnaudaddk_dodigest_sha256 = (NAUDADDK_DODIGEST_SHA256_PROC)GetProcAddress(m_hdll, "naudaddk_dodigest_sha256");
    pfnaudaddk_getdevicekey = (NAUDADDK_GETDEVICEKEY_PROC)GetProcAddress(m_hdll, "naudaddk_getdevicekey");
    pfnaudaddk_getdevicekeyoaep = (NAUDADDK_GETDEVICEKEYOAEP_PROC)GetProcAddress(m_hdll, "naudaddk_getdevicekeyoaep");
    pfnaudaddk_getdevicetid = (NAUDADDK_GETDEVICETID_PROC)GetProcAddress(m_hdll, "naudaddk_getdevicetid");
    pfnaudaddk_getdevicekey_foredge = (NAUDADDK_GETDEVICEKEY_FOREDGE_PROC)GetProcAddress(m_hdll, "naudaddk_getdevicekey_foredge");
    //pfnaudaddk_getdevicetid = (LPFNDLLNAUDADDK)GetProcAddress(m_hdll, "naudaddk_getdevicetid");
    pfnaudaddk_freedevicekey = (NAUDADDK_FREEDEVICEKEY_PROC)GetProcAddress(m_hdll, "naudaddk_freedevicekey");
    pfnaudaddk_getdevicekeyversion = (NAUDADDK_GETDEVICEKEYVERSION_PROC)GetProcAddress(m_hdll, "naudaddk_getdevicekeyversion");
    pfnaudaddk_getuseragentstring = (NAUDADDK_GETUSERAGENTSTRING_PROC)GetProcAddress(m_hdll, "naudaddk_getuseragentstring");
    pfnaudaddk_getplatformstring = (NAUDADDK_GETPLATFORMSTRING_PROC)GetProcAddress(m_hdll, "naudaddk_getplatformstring");
    pfnaudaddk_freebuffer = (NAUDADDK_FREEBUFFER_PROC)GetProcAddress(m_hdll, "naudaddk_freebuffer");
    pfnaudaddk_setudi = (NAUDADDK_SETUDI_PROC)GetProcAddress(m_hdll, "naudaddk_setudi");
    pfnaudaddk_getudi = (NAUDADDK_GETUDI_PROC)GetProcAddress(m_hdll, "naudaddk_getudi");
    pfnaudaddk_extddkg_setudipropertyname = (NAUDADDK_EXTDDKG_SETUDIPROPERTYNAME)GetProcAddress(m_hdll, "naudaddk_extddkg_setudipropertyname");
    pfnaudaddk_setrootfs = (NAUDADDK_SETROOTFS_PROC)GetProcAddress(m_hdll, "naudaddk_setrootfs");
#endif // #if DDKGLIB_STATIC_LINK
#else
    // Non Windows platform
#if DDKGLIB_STATIC_LINK
    // Statically linked DDKG static libraries
    pfnaudaddk_getdevicekeywithchallenge_withdevicerole = naudaddk_getdevicekeywithchallenge_withdevicerole;
    pfnaudaddk_getdevicekeywithchallenge_withdevicemeta = naudaddk_getdevicekeywithchallenge_withdevicemeta;
    pfnaudaddk_docipher_aes_cfb128 = naudaddk_docipher_aes_cfb128;
    pfnaudaddk_dodigest_sha256 = naudaddk_dodigest_sha256;
    pfnaudaddk_getdevicekey = naudaddk_getdevicekey;
    pfnaudaddk_getdevicekeyoaep = naudaddk_getdevicekeyoaep;
    pfnaudaddk_getdevicetid = naudaddk_getdevicetid;
    pfnaudaddk_getdevicekey_foredge = naudaddk_getdevicekey_foredge;
    pfnaudaddk_freedevicekey = naudaddk_freedevicekey;
    pfnaudaddk_getdevicekeyversion = naudaddk_getdevicekeyversion;
    pfnaudaddk_getuseragentstring = naudaddk_getuseragentstring;
    pfnaudaddk_getplatformstring = naudaddk_getplatformstring;
    pfnaudaddk_freebuffer = naudaddk_freebuffer;
    pfnaudaddk_setudi = naudaddk_setudi;
    pfnaudaddk_getudi = naudaddk_getudi;
    pfnaudaddk_extddkg_setudipropertyname = naudaddk_extddkg_setudipropertyname;
    pfnaudaddk_setrootfs = naudaddk_setrootfs;
#else
#if defined(linux) || defined(__linux__)
    // Linux platform
#define NPUADADDK_LIB "libnaudaddk_shared.so"
#elif defined(__APPLE__) || defined(__MACH__)
    // OSX platform
#define NPUADADDK_LIB "libnaudaddk_shared.dylib"
#endif // #if defined(linux) || defined(__linux__)
    Log *log = Log::getInstance();

    // Dynamically load DDKG shared library
    m_hdll = dlopen(NPUADADDK_LIB, RTLD_LAZY);
    if (m_hdll)
    {
        uNAUDADDKFuncPtrAlias alias;
        alias.obj = dlsym(m_hdll, "naudaddk_getdevicekeywithchallenge_withdevicerole");
        pfnaudaddk_getdevicekeywithchallenge_withdevicerole = alias.pfnaudaddk_getdevicekeywithchallenge_withdevicerole;
        alias.obj = dlsym(m_hdll, "naudaddk_getdevicekeywithchallenge_withdevicemeta");
        pfnaudaddk_getdevicekeywithchallenge_withdevicemeta = alias.pfnaudaddk_getdevicekeywithchallenge_withdevicemeta;
        alias.obj = dlsym(m_hdll, "naudaddk_docipher_aes_cfb128");
        pfnaudaddk_docipher_aes_cfb128 = alias.pfnaudaddk_docipher_aes_cfb128;
        alias.obj = dlsym(m_hdll, "naudaddk_dodigest_sha256");
        pfnaudaddk_dodigest_sha256 = alias.pfnaudaddk_dodigest_sha256;
        alias.obj = dlsym(m_hdll, "naudaddk_getdevicekey");
        pfnaudaddk_getdevicekey = alias.pfnaudaddk_getdevicekey;
        alias.obj = dlsym(m_hdll, "naudaddk_getdevicekeyoaep");
        pfnaudaddk_getdevicekeyoaep = alias.pfnaudaddk_getdevicekeyoaep;
        alias.obj = dlsym(m_hdll, "naudaddk_getdevicetid");
        pfnaudaddk_getdevicetid = alias.pfnaudaddk_getdevicetid;
        alias.obj = dlsym(m_hdll, "naudaddk_getdevicekey_foredge");
        pfnaudaddk_getdevicekey_foredge = alias.pfnaudaddk_getdevicekey_foredge;
        //alias.obj = dlsym(m_hdll, "naudaddk_getdevicetid");
        //pfnaudaddk_getdevicetid = alias.pfnaudaddk_getdevicetid;
        alias.obj = dlsym(m_hdll, "naudaddk_freedevicekey");
        pfnaudaddk_freedevicekey = alias.pfnaudaddk_freedevicekey;
        alias.obj = dlsym(m_hdll, "naudaddk_getdevicekeyversion");
        pfnaudaddk_getdevicekeyversion = alias.pfnaudaddk_getdevicekeyversion;
        alias.obj = dlsym(m_hdll, "naudaddk_getuseragentstring");
        pfnaudaddk_getuseragentstring = alias.pfnaudaddk_getuseragentstring;
        alias.obj = dlsym(m_hdll, "naudaddk_getplatformstring");
        pfnaudaddk_getplatformstring = alias.pfnaudaddk_getplatformstring;
        alias.obj = dlsym(m_hdll, "naudaddk_freebuffer");
        pfnaudaddk_freebuffer = alias.pfnaudaddk_freebuffer;
        alias.obj = dlsym(m_hdll, "naudaddk_globalinit");
        pfnaudaddk_globalinit = alias.pfnaudaddk_globalinit;
        alias.obj = dlsym(m_hdll, "naudaddk_globalcleanup");
        pfnaudaddk_globalcleanup = alias.pfnaudaddk_globalcleanup;
        alias.obj = dlsym(m_hdll, "naudaddk_setudi");
        pfnaudaddk_setudi = alias.pfnaudaddk_setudi;
        alias.obj = dlsym(m_hdll, "naudaddk_setudi");
        pfnaudaddk_setudi = alias.pfnaudaddk_setudi;
        alias.obj = dlsym(m_hdll, "naudaddk_getudi");
        pfnaudaddk_getudi = alias.pfnaudaddk_getudi;
        alias.obj = dlsym(m_hdll, "naudaddk_extddkg_setudipropertyname");
        pfnaudaddk_extddkg_setudipropertyname = alias.pfnaudaddk_extddkg_setudipropertyname;
        alias.obj = dlsym(m_hdll, "naudaddk_setrootfs");
        pfnaudaddk_setrootfs = alias.pfnaudaddk_setrootfs;
    }
    else
    {
        static const char *errMsg = "This program requires DA DDKG (shared) library to register and authenticate device to DAE Service.";
#if defined(APPLE) || defined(__MACH__)
        static const char *error = "Unable to open libnaudaddk_shared.dylib!";
#else
        static const char *error = "Unable to open libnaudaddk_shared.so!";
#endif // #if defined(APPLE) || defined(__MACH__)
        std::cerr << error << std::endl;

        if (logger)
        {
            logger->printf(Log::Alert, error);
        }
        std::cerr << errMsg << std::endl;
        if (logger)
        {
            logger->printf(Log::Alert, "%s, exiting...", errMsg);
        }

        exit(1);
    }
#endif // #if DDKGLIB_STATIC_LINK
#endif // #ifdef _WIN32

    // Sanity check to make sure we have all required APIs
    if (pfnaudaddk_globalinit == NULL)
    {
        static const char *error = "Unable to find symbol naudaddk_globalinit!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Alert, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_globalcleanup == NULL)
    {
        static const char *error = "Unable to find symbol naudaddk_globalcleanup!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Alert, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_getdevicekeywithchallenge_withdevicerole == NULL)
    {
        static const char *error = "Unable to find symbol naudaddk_getdevicekeywithchallenge_withdevicerole!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Alert, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_getdevicekeywithchallenge_withdevicemeta == NULL)
    {
        static const char *error = "Unable to find symbol naudaddk_getdevicekeywithchallenge_withdevicemeta!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Alert, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_docipher_aes_cfb128 == NULL)
    {
        static const char *error = "Unable to find symbol naudaddk_docipher_aes_cfb128!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Alert, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_dodigest_sha256 == NULL)
    {
        static const char *error = "Unable to find symbol naudaddk_dodigest_sha256!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Alert, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_getdevicekey == NULL)
    {
        static const char *error = "Unable to find symbol naudaddk_getdevicekey!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Alert, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_getdevicekeyoaep == NULL)
    {
        static const char *error = "Unable to find symbol naudaddk_getdevicekeyoaep!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Alert, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_getdevicekey_foredge == NULL)
    {
        static const char *error = "Unable to find symbol naudaddk_getdevicekey_foredge!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Alert, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_getdevicetid == NULL)
    {
        static const char *error = "Unable to find symbol naudaddk_getdevicetid!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Alert, error);
        }
    }
    if (pfnaudaddk_freedevicekey == NULL)
    {
        static const char *error = "Unable to find symbol naudaddk_freedevicekey!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Alert, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_getuseragentstring == NULL)
    {
        static const char *error = "Unable to find symbol naudaddk_getuseragentstring!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Alert, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_getplatformstring == NULL)
    {
        static const char *error = "Unable to find symbol naudaddk_getplatformstring!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Alert, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_freebuffer == NULL)
    {
        static const char *error = "Unable to find symbol naudaddk_freebuffer!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Alert, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_getdevicekeyversion == NULL)
    {
        static const char *error = "WARN: Unable to find symbol naudaddk_getdevicekeyversion!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Notice, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_setudi == nullptr)
    {
        static const char *error = "WARN: Unable to find symbol naudaddk_setudi!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Notice, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_getudi == nullptr)
    {
        static const char *error = "WARN: Unable to find symbol naudaddk_getudi!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Notice, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_extddkg_setudipropertyname == nullptr)
    {
        static const char *error = "WARN: Unable to find symbol naudaddk_extddkg_setudipropertyname!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Notice, " %s %s", __func__, error);
        }
    }
    if (pfnaudaddk_setrootfs == nullptr)
    {
        static const char *error = "WARN: Unable to find symbol naudaddk_setrootfs!";

        std::cerr << error << std::endl;
        if (logger)
        {
            logger->printf(Log::Notice, " %s %s", __func__, error);
        }
    }

    // Get Platform String
    m_platform = config.lookup(CFG_DAPLATFORM);
    logger->printf(Log::Notice, " %s platform from config:%s", __func__, m_platform.c_str() );
    if (m_platform.empty())
    {
        logger->printf(Log::Notice, " %s getting platform from ddkg...", __func__ );

        char *ddkstring = NULL;
        int result = pfnaudaddk_getplatformstring(&ddkstring);

        logger->printf(Log::Notice, " %s done get platform", __func__);
        if ((result == kDDKStatusSuccess) && ddkstring)
        {
            logger->printf(Log::Information, " %s Platform string: %s", __func__, ddkstring);
            m_platform = ddkstring;
        }
        else
        {
            logger->printf(Log::Critical, " %s Unable to get platform string, status: %d", __func__, result);
        }
        pfnaudaddk_freebuffer(&ddkstring);
    }
    std::cout << "Platform: " << m_platform << std::endl;

    // Get User Agent String
    m_user_agent = config.lookup(CFG_USERAGENT);
    logger->printf(Log::Notice, " %s user agent from config:%s", __func__, m_user_agent.c_str() );
    if (m_user_agent.empty())
    {
        logger->printf(Log::Notice, " %s getting user agent from ddkg...", __func__ );

        char *ddkstring = NULL;
        int result = pfnaudaddk_getuseragentstring(&ddkstring);

        logger->printf(Log::Notice, " %s done get user agent", __func__);
        if ((result == kDDKStatusSuccess) && ddkstring)
        {
            logger->printf(Log::Information, " %s User Agent string: %s", __func__, ddkstring);
            m_user_agent = ddkstring;
        }
        else
        {
            logger->printf(Log::Critical, " %s Unable to get userAgent string, status: %d", __func__, result);
        }
        pfnaudaddk_freebuffer(&ddkstring);
    }
    std::cout << "User-Agent: " << m_user_agent << std::endl;

    // Get DeviceKey Version String
    if (m_version.empty())
    {
        char *ddkstring = NULL;
        int result = pfnaudaddk_getdevicekeyversion(&ddkstring);

        logger->printf(Log::Notice, " %s done get devicekey version", __func__);
        if ((result == kDDKStatusSuccess) && ddkstring)
        {
            logger->printf(Log::Information, " %s devicekey version string: %s", __func__, ddkstring);
            m_version = ddkstring;
        }
        else
        {
            logger->printf(Log::Critical, " %s Unable to get devicekey version string, status: %d", __func__, result);
        }
        pfnaudaddk_freebuffer(&ddkstring);
    }
    std::cout << "DDKG Version: " << m_version << std::endl;

    return !m_user_agent.empty() && !m_platform.empty();
}

void DeviceAuthority::setEventManager(EventManagerBase *p_event_manager)
{
    mp_event_manager = p_event_manager;
}

std::string DeviceAuthority::authoriseTheApp(std::string& key_id, std::string& key, std::string& iv, std::string& message, const std::string& apphash, const std::string& asset_id_str, void *p_client_obj)
{
    return DeviceAuthority::authoriseTheApp(key_id, key, iv, message, apphash, false, asset_id_str, p_client_obj);
}

std::string DeviceAuthority::authoriseTheApp(std::string& key_id, std::string& key, std::string& iv, std::string& message, const std::string& apphash, bool sign_apphash, const std::string& asset_id_str, void *p_client_obj)
{
    mutex_lock();

#if defined(ENABLE_VERBOSE_LOG)
    Log::getInstance()->printf(Log::Debug, " %s:%d: appHash=%s, assetId=%s", __func__, __LINE__, appHash.c_str(), assetIdStr.c_str());
#endif // #if defined(ENABLE_VERBOSE_LOG)

    const std::string node = config.lookup(CFG_NODE);
    m_is_edge_node = node.compare(EDGE_NODE) == 0;

    std::string result;
    bool registered = true;
    DAHttpClient *p_client_ptr = NULL;

    if (p_client_obj)
    {
        p_client_ptr = (DAHttpClient *)p_client_obj;
    }
    else
    {
        p_client_ptr = new DAHttpClient(m_user_agent);
    }

    int status_code = 0;
    const std::string challenge = authorisationChallenge(message, registered, (void *)p_client_ptr, status_code);
    if (!registered)
    {
        Log::getInstance()->printf(Log::Error," Device is not registered ");
        message = "Device is not registered";
    }
    else if (!challenge.empty())
    {
        //printf("%s: registered:%d  ", __func__, registered);
        // The SAC will inform if registration is needed first
        result = getBodyJSONForAPICall(challenge, key_id, key, iv, apphash, sign_apphash, asset_id_str, message);
    }
    
    mutex_unlock();

    return result;
}

// Perform the steps needed to authorise the use of the policy gateway API
std::string DeviceAuthority::identifyAndAuthorise(std::string &key_id, std::string& key, std::string& iv, std::string& message, void *p_client_ptr, std::string policy_id)
{
    std::string metadata;

    return identifyAndAuthorise(key_id, key, iv, message, metadata, p_client_ptr, policy_id);
}

std::string DeviceAuthority::identifyAndAuthorise(std::string& key_id, std::string& key, std::string& iv, std::string& message, std::string& metadata, void *p_client_ptr, std::string policy_id)
{
    Log *p_logger = Log::getInstance();

#if defined(ENABLE_VERBOSE_LOG)
    logger->printf(Log::Debug, " %s:%d: lock wait called", __func__, __LINE__);
#endif // #if defined(ENABLE_VERBOSE_LOG)

    mutex_lock();

#if defined(ENABLE_VERBOSE_LOG)
    logger->printf(Log::Debug, " %s:%d: lock acquired called", __func__, __LINE__);
#endif // #if defined(ENABLE_VERBOSE_LOG)

    const std::string node = config.lookup(CFG_NODE);

    m_is_edge_node = node.compare(EDGE_NODE) == 0;

    std::string result;
    bool registered = true; // Assume true for now
    int status_code = 0;
    std::string challenge = authorisationChallenge(message, registered, (void *)p_client_ptr, status_code, policy_id);
#if defined(ENABLE_VERBOSE_LOG)
    logger->printf(Log::Debug, " %s:%d: authorisationChallenge returned %d", __func__, __LINE__, challenge.size());
#endif // #if defined(ENABLE_VERBOSE_LOG)

    // Smart registration does not allow for re-registration in an Edge based system currently so we need
    // to force a registration attempt if the provided synthetic material is not found by the Edge service
    if (m_is_edge_node && status_code == CHALLENGE_NO_DEVICE_WITH_ID_KEY)
    {
        challenge = registrationChallenge(message, (void*)p_client_ptr);
        registered = false; // Force registration in the event of this failure on an Edge system
    }

    if (!challenge.empty())
    {
        // The SAC will inform if registration is needed first
        if (registered)
        {
            result = getBodyJSONForAPICall(challenge, key_id, key, iv, "", "", message);
        }
        else
        {
            // Need to register first
            p_logger->printf(Log::Information, "Device registration required");
            if (mp_event_manager) 
            {
                mp_event_manager->notifyRegistrationRequired();
            }
            
            registered = registration(challenge, message, metadata);

            if (registered)
            {
                if (!message.empty())
                {
                    p_logger->printf(Log::Information, message.c_str());
                }
                result = identifyAndAuthorise(key_id, key, iv, message, p_client_ptr, policy_id);
            }
        }
    }
    
    mutex_unlock();

#if defined(ENABLE_VERBOSE_LOG)
    //logger->printf(Log::Debug, " %s:%d: lock released called, size=%d, error=%s", __func__, __LINE__, result.size(), message.c_str());
#endif // #if defined(ENABLE_VERBOSE_LOG)

    return result;
}

bool DeviceAuthority::registration(const std::string& challengeID, std::string& message)
{
    std::string metadata;

    return registration(challengeID, message, metadata);
}

bool DeviceAuthority::registration(const std::string& challengeID, std::string& message, std::string& metadata)
{
    bool registered = false;  // Assume it is not registered
    std::string apiurl = m_APIURL + REGISTER_PATH;
    rapidjson::Document json;
    DAErrorCode rc = ERR_OK;

    if (!challengeID.empty())
    {
        if (mp_event_manager)
        {
            mp_event_manager->notifyRegistrationInProgress();
        }
        
        std::string deviceKey = getDeviceKey(challengeID, message);

        if (!deviceKey.empty())
        {
            std::string json_response;
            std::string bodytext = "{";

            bodytext.append("\"deviceKey\":\"" + deviceKey + "\"");
            bodytext.append(",\"userAgent\":\"");
            bodytext.append(m_user_agent + "\"");
            bodytext.append(",\"displayName\":\"" + m_device_name + "\"");
            if (!m_user.empty())
            {
                // Add userId into the json string
                bodytext.append(",\"userId\":\"" + m_user + "\"");
            }
            bodytext.append("}");
            //if (!APIKey_.empty() || !APISecret_.empty())
            //{
            //    json.setSSLUserPass( APIKey_.c_str(), APISecret_.c_str());
            //}

            DAHttpClient p_http_client_obj(m_user_agent);

            rc = p_http_client_obj.sendRequest(DAHttp::ReqType::ePOST, apiurl, json_response, bodytext);

            if ((rc == ERR_OK) && !json_response.empty())
            {
                json.Parse(json_response.c_str());
                if (json.HasParseError())
                {
                    Log::getInstance()->printf(Log::Error, " %s:%d: Bad responseData=%s", __func__, __LINE__, json_response.c_str());
                    rc =  ERR_BAD_DATA;
                }
            }
        }

        /*
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        json.Accept(writer);
        std::string jsonStr = buffer.GetString();
        */
#if defined(ENABLE_VERBOSE_LOG)
        Log::getInstance()->printf(Log::Debug, " %s:%d: input=%s, rc=%d", __func__, __LINE__, json_response.c_str(), rc);
        //Log::getInstance()->printf(Log::Debug," %s %d rc: %d ", __func__, __LINE__, rc);
#endif // #if defined(ENABLE_VERBOSE_LOG)
        if (rc != ERR_OK)
        {
            message = processError(apiurl, json, rc);
        }
        else if (!json.IsNull())
        {
            if (json.HasMember("httpCode"))
            {
                const rapidjson::Value& http_code_val = json["httpCode"];
                int httpCode = http_code_val.GetInt();

                Log::getInstance()->printf(Log::Debug, " %s Registration returned code: %d", __func__, httpCode);
            }
            if (json.HasMember("statusCode"))
            {
                const rapidjson::Value& statusCodeVal = json["statusCode"];
                int status_code = statusCodeVal.GetInt();
                if (status_code == 0)
                {
                    if (json.HasMember("message"))
                    {
                        Log::getInstance()->printf(Log::Information, "Device registration successful");
                        if (mp_event_manager) 
                        {
                            mp_event_manager->notifyRegistrationSuccess();
                        }
    
                        const rapidjson::Value& msg_val = json["message"];
                        if (msg_val.HasMember("metadata"))
                        {
                            const rapidjson::Value& metadataVal = msg_val["metadata"];
                            // Get the number of metadata
                            unsigned int metadata_size = metadataVal.Size();

                            if (metadata_size > 0)
                            {
                                for (unsigned int i = 0; i < metadata_size; ++i)
                                {
                                    const rapidjson::Value& sVal = metadataVal[i];

                                    metadata = sVal.GetString();
                                }
                            }
                        }

                    }
                    registered = true;
                }
                else
                {
                    if (mp_event_manager) 
                    {
                        mp_event_manager->notifyRegistrationFailure(message);
                    }

                    // It failed so tell the log why
                    processStatusCode("Registration", json, message);
                }
            }
        }
    }

    return registered;
}

std::string getChallengeStringFromJson(const rapidjson::Document &json, std::string &message)
{
    if (json.HasMember("statusCode"))
    {
        const rapidjson::Value& statusCodeVal = json["statusCode"];
        int status_code = statusCodeVal.GetInt();

        // Log::getInstance()->printf(Log::Debug, " %s status_code is %d", __func__, status_code);
        if (status_code == 0)
        {
            if (json.HasMember("message"))
            {
                const rapidjson::Value& msg_val = json["message"];

                if (msg_val.HasMember("challenge"))
                {
                    const rapidjson::Value& challengeVal = msg_val["challenge"];

                    if (!challengeVal.IsNull())
                    {
                        // Log::getInstance()->printf(Log::Debug, " %s Got challenge from DAE", __func__);
                        return challengeVal.GetString();
                    }
                }
            }
        }
        else
        {
            // It failed so tell the log why
            processStatusCode("Challenge", json, message);
        }
    }

    return "";
}

std::string DeviceAuthority::challenge(const std::string& type, const std::string& bodytext, bool& registered, std::string& message, void *p_http_client, int &status_code)
{
    message = "";
    status_code = 0;

    std::string result = "";
    std::string body = bodytext;
    std::string json_response = "";
    std::string apiurl = m_APIURL+ CHALLENGE_PATH;

    if (!p_http_client)
    {
        Log::getInstance()->printf(Log::Error, " %s:%d HTTP Client object not initialized!", __func__, __LINE__);

        return result;
    }

    rapidjson::Document json;
    DAHttpClient *p_http_client_obj = (DAHttpClient *)p_http_client;

    //if (!APIKey_.empty() || !APISecret_.empty())
    //{
    //    json.setSSLUserPass(APIKey_.c_str(), APISecret_.c_str());
    //}
    DAErrorCode rc = p_http_client_obj->sendRequest(DAHttp::ReqType::ePOST, apiurl, json_response, body);
    // Log::getInstance()->printf(Log::Debug, " %s:%d sendResponseJson returns %d, jsonResponseLength: %s", __func__, __LINE__, rc, json_response.c_str());

    if (!json_response.empty())
    {
        json.Parse<0>(json_response.c_str());

        if (json.HasParseError())
        {
            Log::getInstance()->printf(Log::Error, " %s Bad responseData: %s", __func__, json_response.c_str());
            rc = ERR_BAD_DATA;
        }
    }

    if (rc != ERR_OK)
    {
        message = processError(apiurl, json, rc);

        if (!json.IsNull() && json.HasMember("statusCode"))
        {
            status_code = json["statusCode"].GetInt();
        }
    }
    else if (!json.IsNull())
    {
        // Check the status code and
        if (json.HasMember("httpCode"))
        {
            stringstream sstr;
            const rapidjson::Value& http_code_val = json["httpCode"];
            int data = http_code_val.GetInt();

            sstr << data;
            //message = string("Challenge returned httpCode: ") + sstr.str() + ".";
            //logger.printf(Log::Debug, " In %s message is %s \n", __func__, message.c_str());
        }
        registered = true; // Assume device is already registered.
        if (json.HasMember("message"))
        {
            const rapidjson::Value& msg_val = json["message"];

            if (msg_val.HasMember("nextAction"))
            {
                const rapidjson::Value& next_action_val = msg_val["nextAction"];
                if (!next_action_val.IsNull())
                {
                    const std::string data = next_action_val.GetString();
                    if (!data.empty() && (data == "register"))
                    {
                        registered = false;
                        Log::getInstance()->printf(Log::Warning, "Device is not registered");
                    }
                }
            }
        }

        result = getChallengeStringFromJson(json, message);
    }
    //Log::instance()->printf(Log::Debug, " %s:%d result: %s", __func__, __LINE__, result.c_str());

    return result;
}

std::string DeviceAuthority::registrationChallenge(std::string &message, void *p_client_ptr)
{
    message = "";

    Log::getInstance()->printf(Log::Debug, " %s:%d", __func__, __LINE__);

    const std::string bodytext = "{\"challengeType\": \"" + std::string(CHTYPEFULL_TEXT) + "\", \"userAgent\": \"" + m_user_agent + "\"}";

    DAHttpClient *p_http_client_obj = (DAHttpClient *)p_client_ptr;

    std::string json_response = "";
    std::string apiurl = m_APIURL + CHALLENGE_PATH;
    DAErrorCode rc = p_http_client_obj->sendRequest(DAHttp::ReqType::ePOST, apiurl, json_response, bodytext);

    rapidjson::Document json;
    if ((rc == ERR_OK) && !json_response.empty())
    {
        json.Parse<0>(json_response.c_str());
        if (json.HasParseError())
        {
            Log::getInstance()->printf(Log::Error, " %s Bad responseData: %s", __func__, json_response.c_str());
            rc = ERR_BAD_DATA;
        }
    }

    std::string challenge = "";
    if (rc != 0)
    {
        message = processError(apiurl, json, rc);
    }
    else if (!json.IsNull())
    {
        challenge = getChallengeStringFromJson(json, message);
    }

    return challenge;
}

std::string DeviceAuthority::authorisationChallenge(std::string &message, bool &registered, void *p_client_ptr, int &status_code, std::string policyID)
{
    Log::getInstance()->printf(Log::Debug, " %s:%d", __func__, __LINE__);

    if (mp_event_manager) 
    {
        mp_event_manager->notifyAuthorizationInProgress();
    }
    
    std::string deviceKey = "";
    std::string result = "";

    if (m_deviceTID.empty())
    {
        deviceKey = getDeviceKey("", message);
    }
    //Log::getInstance()->printf(Log::Debug, " %s:%d deviceKey size:%d ", __func__, __LINE__, deviceKey.size());
    if (!deviceKey.empty() || !m_deviceTID.empty())
    {
        std::string bodytext = "{";
        bodytext.append("\"userAgent\":\"");
        bodytext.append(m_user_agent);
        bodytext.append("\"");
        bodytext.append(",\"challengeType\":\"");
        bodytext.append(CHTYPEAUTH_TEXT);
        bodytext.append("\"");
#if 0
        bodytext.append(",\"ddkgVersion\":\"");
        bodytext.append(m_version);
        bodytext.append("\"");
#endif
        if (!m_user.empty())
        {
            // Add userId to json string
            bodytext.append(",\"userId\":\"");
            bodytext.append(m_user);
            bodytext.append("\"");
        }
        if (!policyID.empty())
        {
            // Add policyId to json string
            bodytext.append(",\"encryptPolicyId\":\"");
            bodytext.append(policyID);
            bodytext.append("\"");
        }
        //if (deviceKey.empty())
        //{
        //    bodytext += "\"tid\":\"" + m_deviceTID + "\"}";
        //}
        //else if (m_deviceTID.empty())
        bodytext.append(",\"deviceKey\":\"");
        bodytext.append(deviceKey);
        bodytext.append("\"");
        bodytext.append("}");
        Log::getInstance()->printf(Log::Debug, " %s:%d send challenge", __func__, __LINE__);
        result = challenge(CHTYPEAUTH_TEXT, bodytext, registered, message, p_client_ptr, status_code);
    }
    //Log::getInstance()->printf(Log::Debug, "Exit %s %d registered :%d ", __func__, __LINE__, registered);

    return result;
}

/*
 * Gets the device key from the DDKG (with or without challenge)
 *
 * @param challengeID  optional input value containing DDKG challenge when non empty.
 * @param message output param containing error Information.
 * @param keyId  output param containing keyId from the DDKG response.
 * @param key  output param containing key from the DDKG response.
 * @param iv output param containing iv from the DDKG response.
 */
string DeviceAuthority::getDeviceKey(const std::string& challengeID, std::string& message, char *keyid, char *key, char *iv)
{
    std::string deviceKey("");
    int result = kDDKStatusError;
    char *deviceKeyJSON = NULL;
    /*
    metaDataJSON
    # node: Valid values are edge and central
    # crypto_provider: Valid values are SunPKCS11-NSS, nCipherKM, LunaProvider (default SunPKCS11-NSS)
    # mimetype: Valid values are text/xml, application/json
    {
        "node": "edge",
        "crypto_provider": "SunPKCS11-NSS",
        "mimetype": "text/xml",
        "device_role": "DA Agent",
        "device_meta": [
            {
                "name": "deviceId",
                "value": "deviceIdValue"
            }
        ],
        "ch": "",
        "keyAndExpiry": {
		    "key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAopT6xCVGP4KPCOXXwUD8\n3aM1lWREhMaNP783mZ2ob3EN9P2cSACKSTtGid++qDgb3l1mbX3sru4eWWOXTw/w\nkJSdhTZoON0UVABTvgX/31JS1QXYO0cog0UYn5QGOwgxTi5WsbqDPGoOumFw5gC8\n2wjEoiF2BMMb6IgHZ7224q0cE/x6BAY7K56PxzsjtpLbtJJaFk7wxhvRe3v6EE1E\no8SVPCeSXEXKZa/clFNs9lMggqD8b6V7ilO91ooVsstxAsc/lF1qt403n0mluD9y\nb67EFHZXL1anR4V8GvAH4yQZlzgDowO+2G6J8SngREAv+LBDloCKiDE/bvkPpMEH\nmwIDAQAB\n-----END PUBLIC KEY-----\n",
		    "expiry": "2021-05-15T20:18:29.807+00:00"
	    },
	    "signature": {
		    "algo": "RSA",
		    "data": "zOwdjUEKkzE41ISdQ98CyRj64fxeToatMiLGa61g6AAhk9H64zL0ZEKAfG/U7BSp0qxavZP9Hkbu8JoUhyhkUqxwYEuW/O6i2NiDa6nqDyN6QSmcplGv/CwPwozQW/KP9bQJ9QW2rkcTHDTOtnjaUvnt67jV+EaWmzYE2ngHWWn2tOBGq+tnElIqA3lNCModsuZBrA8BoKpPRw96om4sPbsmNsrdxrHPWxgh1qxTCpAI+bafdb7ytgBWwZLNybbBu0/QJ9sWeTzisr+osWtiW6iv3MvnUzt0Xrf4X1pDfzrvdbUYFEv0bf0JMis6zyXfJ/XgmkSizkOWWzddtoWN7Q==",
		    "encoding": "Base64",
		    "sig_algo": "SHA1withRSA"
	    }
    }
    */
    std::string metadataJSON = "{";

    if (m_is_edge_node)
    {
        std::string node = config.lookup(CFG_NODE);

        metadataJSON = metadataJSON + "\"" + JSON_NODE + "\":\"" + node + "\"";
    }
    if (!challengeID.empty())
    {
        //Log::getInstance()->printf(Log::Debug, " %s:%d", __func__, __LINE__);

        std::string deviceRole = config.lookup(CFG_DEVICE_ROLE);

        if (deviceRole.empty())
        {
            deviceRole = DEVICE_ROLE;
        }

        const std::string udi = config.lookup(CFG_UDI);
		if (m_is_edge_node)
		{
			metadataJSON = metadataJSON + ",";
		}
        metadataJSON = metadataJSON + "\"" + JSON_DEVICE_ROLE + "\":\"" + deviceRole + "\"";
        if (udi.length() > 0)
        {
            metadataJSON = metadataJSON + ",\"" + JSON_DEVICE_META + "\":[{\"" + JSON_DEVICE_META_NAME + "\":\"deviceId\",\"" + JSON_DEVICE_META_VALUE + "\":\"" + udi + "\"}]";
        }
        metadataJSON = metadataJSON + ",\"" + JSON_CH + "\":\"" + challengeID + "\"";
        /*
        if ((udi.length() > 0) && pfnaudaddk_getdevicekeywithchallenge_withdevicemeta)
        {
            std::string deviceMeta = "{\"device_role\":\"" + deviceRole + "\",\"device_meta\":[{\"name\":\"deviceId\",\"value\":\"" + udi + "\"}]}";

            result = pfnaudaddk_getdevicekeywithchallenge_withdevicemeta(challengeID.c_str(), deviceMeta.c_str(), &deviceKeyJSON);
        }
        else if (pfnaudaddk_getdevicekeywithchallenge_withdevicerole)
        {
            result = pfnaudaddk_getdevicekeywithchallenge_withdevicerole(challengeID.c_str(), deviceRole.c_str(), &deviceKeyJSON);
        }
        */
    }
    else
    {
        const std::string cryptoProvider = config.lookup(CFG_KEYSTORE_PROVIDER);

		if (m_is_edge_node)
		{
			metadataJSON = metadataJSON + ",";
		}
        metadataJSON = metadataJSON + "\"" + JSON_CRYPTO_PROVIDER + "\":\"" + cryptoProvider + "\"";
        //Log::getInstance()->printf(Log::Debug, " %s:%d", __func__, __LINE__);
        /*
        if (pfnaudaddk_getdevicekeyoaep)
        {
            result = pfnaudaddk_getdevicekeyoaep(cryptoProvider.c_str(), &deviceKeyJSON, NULL);
        }
        */
    }
    if (m_is_edge_node)
    {
        rapidjson::Document json;
        std::string json_response;
        std::string keyEdge = "/key/edge";
        DAErrorCode rc = ERR_OK;
        DAHttpClient p_http_client_obj(m_user_agent);
        std::string edgeKeyApiUrl = config.lookup(CFG_DAAPIURL) + keyEdge;

        rc = p_http_client_obj.sendRequest(DAHttp::ReqType::eGET, edgeKeyApiUrl, json_response, "");

        Log::getInstance()->printf(Log::Debug, "json_response => %s", json_response.c_str());
        if ((rc == ERR_OK) && !json_response.empty())
        {
            json.Parse(json_response.c_str());
            if (json.HasParseError())
            {
                Log::getInstance()->printf(Log::Error, " %s:%d: Bad responseData=%s", __func__, __LINE__, json_response.c_str());
                rc = ERR_BAD_DATA;
            }
        }
        if (rc == ERR_OK)
        {
            if (json.IsObject() && json.HasMember("message"))
            {
                const Value& a = json["message"];

                if (a.HasMember("keyAndExpiry"))
                {
                    // Get keyAndExpiry
                    const Value& b = a["keyAndExpiry"];

                    metadataJSON = metadataJSON + ",\"" + JSON_KEY_AND_EXPIRY + "\":{";
                    if (b.HasMember("key"))
                    {
                        const rapidjson::Value& keyVal = b["key"];
                        std::string temp_string = keyVal.GetString();
                        std::string eol = "\n";
                        size_t pos = temp_string.find(eol);
                        std::string neweol = "\\n";

                        while (pos != std::string::npos)
                        {
                            temp_string.replace(pos, eol.size(), neweol);
                            pos = temp_string.find(eol, pos + neweol.size());
                        }
                        metadataJSON = metadataJSON + "\"" + JSON_KEY + "\":\"" + temp_string + "\"";
                    }
                    if (b.HasMember("expiry"))
                    {
                        const rapidjson::Value& expiryVal = b["expiry"];
                        uint64_t expiry_int = expiryVal.GetUint64();

                        metadataJSON = metadataJSON + ",\"" + JSON_EXPIRY + "\":" + std::to_string(expiry_int);
                    }
                    metadataJSON = metadataJSON + "}";
                }
                if (a.HasMember("signature"))
                {
                    // Get signature
                    const Value& c = a["signature"];

                    metadataJSON = metadataJSON + ",\"" + JSON_SIGNATURE + "\":{";
                    if (c.HasMember("algo"))
                    {
                        const rapidjson::Value& algo = c["algo"];
                        std::string temp_algo = algo.GetString();

                        metadataJSON = metadataJSON + "\"" + JSON_SIGNATURE_ALGO + "\":\"" + temp_algo + "\"";
                    }
                    if (c.HasMember("data"))
                    {
                        const rapidjson::Value& data = c["data"];
                        std::string temp_data = data.GetString();

                        metadataJSON = metadataJSON + ",\"" + JSON_SIGNATURE_DATA + "\":\"" + temp_data + "\"";
                    }
                    if (c.HasMember("encoding"))
                    {
                        const rapidjson::Value& encoding = c["encoding"];
                        std::string temp_encoding = encoding.GetString();

                        metadataJSON = metadataJSON + ",\"" + JSON_SIGNATURE_ENCODING + "\":\"" + temp_encoding + "\"";
                    }
                    if (c.HasMember("sig_algo"))
                    {
                        const rapidjson::Value& sig_algo = c["sig_algo"];
                        std::string temp_sig_algo = sig_algo.GetString();

                        metadataJSON = metadataJSON + ",\"" + JSON_SIGNATURE_SIGN_ALGO + "\":\"" + temp_sig_algo + "\"";
                    }
                    metadataJSON = metadataJSON + "}";
                }
            }
        }
    }
    metadataJSON = metadataJSON + "}";
	// Log::getInstance()->printf(Log::Debug, " %s:%d metadataJSON: %s", __func__, __LINE__, metadataJSON.c_str());
    if (pfnaudaddk_getdevicekey_foredge)
    {
        result = pfnaudaddk_getdevicekey_foredge(metadataJSON.c_str(), &deviceKeyJSON);
    }
    if (result == kDDKStatusSuccess)
    {
        rapidjson::Document json;

        json.Parse(deviceKeyJSON);
        if (json.HasParseError())
        {
            message = "Unable to parse device key response.";
        }
        else
        {
            if (json.HasMember(JSON_DDK_TEXT))
            {
                const rapidjson::Value& ddkVal = json[JSON_DDK_TEXT];

                deviceKey = ddkVal.GetString();

                size_t codeStart = deviceKey.find("<code>");

                if (codeStart != string::npos)
                {
                    codeStart += 6;

                    size_t codeEnd = deviceKey.find("</code>", codeStart);
                    std::string errorCode = deviceKey.substr(codeStart, codeEnd - codeStart);

                    message = "Device key generation has failed with (DDKG code " + errorCode + ") .";
                    deviceKey = "";
                }
                else
                {
                    //Log::getInstance()->printf(Log::Debug, " %s:%d", __func__, __LINE__);
                    // Try this to make device key acceptable: strip out '\n'
                    deviceKey.erase(remove(deviceKey.begin(), deviceKey.end(), '\n'), deviceKey.end());

                    // There are also "\n" (2 characters) in it that need to be removed.
                    std::string newKey = "";
                    unsigned int deviceKeyLength = deviceKey.length();

                    for (unsigned int i = 0; i < deviceKeyLength; ++i)
                    {
                        if ((deviceKey[i] == '\\') && (deviceKey[i + 1] == 'n'))
                        {
                            ++i;
                        }
                        else
                        {
                            newKey += deviceKey[i];
                        }
                    }
                    deviceKey = newKey;
                    //Log::getInstance()->printf(Log::Debug, "In %s LINE %d Generated device key successfully %s \n", __func__, __LINE__, deviceKey.c_str());
                    //message = "Generated device key successfully.";
                }
            }
            if (json.HasMember(JSON_IOT_TEXT))
            {
                const rapidjson::Value& iotVal = json[JSON_IOT_TEXT];
                /*
                rapidjson::StringBuffer buffer;
                rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
                json.Accept(writer);
                std::string jsonStr = buffer.GetString();
                Log::getInstance()->printf(Log::Debug, "\n %s:%d input: %s", __func__, __LINE__ , jsonStr.c_str());
                */

                if (keyid && key && iv)
                {
                    if (iotVal.HasMember(JSON_KEY_ID_TEXT))
                    {
                        const rapidjson::Value& keyIdVal = iotVal[JSON_KEY_ID_TEXT];
                        std::string keyIdStr = keyIdVal.GetString();

                        if (keyid)
                        {
#if __STDC_WANT_SECURE_LIB__
                            size_t cbKeyId = keyIdStr.length();

                            strcpy_s(keyid, cbKeyId + 1, keyIdStr.c_str());
#else
                            strcpy(keyid, (char *)keyIdStr.c_str());
#endif // #if __STDC_WANT_SECURE_LIB__
                        }
                    }
                    if (iotVal.HasMember(JSON_KEY_TEXT))
                    {
                        const rapidjson::Value& keyVal = iotVal[JSON_KEY_TEXT];
                        std::string keyStr = keyVal.GetString();

                        if (key)
                        {
#if __STDC_WANT_SECURE_LIB__
                            size_t cbKey = keyStr.length();

                            strcpy_s(key, cbKey + 1, keyStr.c_str());
#else
                            strcpy(key, (char *)keyStr.c_str());
#endif // #if __STDC_WANT_SECURE_LIB__
                        }
                    }
                    if (iotVal.HasMember(JSON_IV_TEXT))
                    {
                        const rapidjson::Value& ivVal = iotVal[JSON_IV_TEXT];
                        std::string  ivStr = ivVal.GetString();

                        if (iv)
                        {
#if __STDC_WANT_SECURE_LIB__
                            size_t cbIv = ivStr.length();

                            strcpy_s(iv, cbIv + 1, ivStr.c_str());
#else
                            strcpy(iv, (char *)ivStr.c_str());
#endif // #if __STDC_WANT_SECURE_LIB__
                        }
                    }
                    else
                    {
                        message = "Device key generation has failed, no key data found.";
                        deviceKey = "";
                    }
                }
            }
        }
        if (pfnaudaddk_freedevicekey)
        {
            result = pfnaudaddk_freedevicekey(&deviceKeyJSON);
        }
    } //if (result == kDDKStatusSuccess)
    else
    {
        ostringstream oss;

        Log::getInstance()->printf(Log::Information, " %s:%d Failed to generate device key: %d", __func__, __LINE__, result);

        oss << "Failed to generate device key, error: " << result << ".";

        message = oss.str();
    }
    //OpenSSL_add_all_algorithms(); // Fix for issue where call to da function clobbers ssl context
    //logger.printf(Log::Debug, " %s:%d deviceKey size: %ld", __func__, __LINE__, deviceKey.size());
    //logger.printf(Log::Debug, " %s:%d message: %s", __func__, __LINE__, message.c_str());

    return deviceKey;
}

string DeviceAuthority::getDeviceTid()
{
    int result = kDDKStatusError;
    char* devicetid = NULL;
    std::string result_tid = "";

    pfnaudaddk_getdevicetid(&devicetid);
    rapidjson::Document json;

    json.Parse(devicetid);
    if (json.HasParseError())
    {
        printf("Unable to parse device key response.");
    }
    else
    {
        if (json.HasMember("tid"))
        {
            const rapidjson::Value& tidVal = json["tid"];
            result_tid = tidVal.GetString();
        }
    }
    pfnaudaddk_freebuffer(&devicetid);

    return result_tid;
}

std::string DeviceAuthority::getBodyJSONForAPICall(
    const std::string &challenge_id,
    std::string &key_id,
    std::string &key,
    std::string &iv,
    const std::string &apphash,
    const std::string &asset_id_str,
    std::string &message)
{
    return DeviceAuthority::getBodyJSONForAPICall(challenge_id, key_id, key, iv, apphash, false, asset_id_str, message);
}

std::string DeviceAuthority::getBodyJSONForAPICall(
    const std::string &challenge_id,
    std::string &key_id,
    std::string &key,
    std::string &iv,
    const std::string &apphash,
    bool sign_apphash,
    const std::string &asset_id_str,
    std::string &message)
{
    //Log::getInstance()->printf(Log::Debug, " %s:%d challengeId size: %ld", __func__, __LINE__, challenge_id.size());
    //Log::getInstance()->printf(Log::Debug, "%s:%d appHash: %s, assetId: %s", __func__, __LINE__, apphash.c_str(), asset_id_str.c_str());

    char the_key_id[1024] = { 0 };
    char the_key[1024] = { 0 };
    char the_iv[1024] = { 0 };

    const std::string devicekey = getDeviceKey(challenge_id, message, the_key_id, the_key, the_iv);
    std::string bodytext = "";

    //Log::getInstance()->printf(Log::Debug, " %s:%d device key size: %d", __func__, __LINE__, devicekey.size());
    if (!devicekey.empty())
    {
        bodytext += "{";

        if (config.lookup(CFG_NODE) == "edge") {

            bodytext += "\"userAgent\":\"" + m_user_agent + "\",";
        }
        if (!m_user.empty())
        {
            // Add userId to json string
            bodytext += "\"userId\":\"" + m_user + "\",";
        }
        if (!key_id.empty())
        {
            // A keyID will be passed in if it needs adding to the JSON
            bodytext += "\"keyId\":\"" + key_id + "\",";
        }
        if (apphash.size())
        {
            bodytext += "\"appHash\":\"" + apphash + "\",";
        }
        if (sign_apphash)
        {
            bodytext += "\"appHashSignature\":\"" + utils::generateHMAC(apphash, the_key, true) + "\",";
        }
        if (asset_id_str.size())
        {
            bodytext += "\"assetId\":\"" + asset_id_str + "\",";
        }
        bodytext += "\"deviceKey\":\"" + devicekey + "\"";
        bodytext += "}";
        key_id = the_key_id;
        key = the_key;
        iv = the_iv;
        // TODO: Uncommented out these lines only for debugging purpose
        //Log::getInstance()->printf(Log::Debug, " %s:%d keyID: %s", __func__, __LINE__, key_id.c_str());
        //Log::getInstance()->printf(Log::Debug, " %s:%d key: %s", __func__, __LINE__, key.c_str());
        //Log::getInstance()->printf(Log::Debug, " %s:%d iv: %s", __func__, __LINE__, iv.c_str());
    }
    //Log::instance()->printf(Log::Debug, " %s:%d bodytext: %s", __func__, __LINE__, bodytext.c_str());

    return bodytext;
}

bool DeviceAuthority::getIDCToken(std::string &token)
{
    mutex_lock();

    std::string keyId;
    std::string authkey;
    std::string authiv;
    std::string errMessage;
    bool authenticated = false;
    bool retVal = false;
    DAErrorCode rc = ERR_OK;
    DAHttpClient p_http_client_obj(m_user_agent);
    std::string daJSON = identifyAndAuthorise(keyId, authkey, authiv, errMessage, &p_http_client_obj);

    if (!daJSON.empty())
    {
        std::string jsonKeyStr;
        rapidjson::Document jsonDKey;

        jsonDKey.Parse(daJSON.c_str());
        if (jsonDKey.HasMember("deviceKey") && !jsonDKey["deviceKey"].IsNull())
        {
            const rapidjson::Value& deviceKeyVal = jsonDKey["deviceKey"];

            jsonKeyStr = deviceKeyVal.GetString();
        }
        else
        {
            errMessage = " deviceKey not found in authenticate response";
            Log::getInstance()->printf(Log::Error, "%s : %s", __func__, errMessage.c_str());

            mutex_unlock();

            return retVal;
        }

        std::string json_response;
        std::string idcPacket;
        std::string appId;
        const std::string udi = config.lookup(CFG_UDI);
        const std::string udiType = config.lookup(CFG_UDITYPE);
        std::string apiurl = m_APIURL+ IDC_PATH;
        std::string request = "\"req\":{ \"op\":\"idc\",\"auth_id\":\"" + m_user + "\",\"app-id\":\"" + appId + "\",\"meta\":{},\"udi\":\"" + udi + "\",\"udi-type\":\"" + udiType + "\",\"type\":\"self\"}";

        idcPacket += "{\"ddkg\":\"" + jsonKeyStr + "\",\"deviceAccountId\":\"" + m_user + "\",\"userAgent\":\"" + m_user_agent+ "\",\"domainPublicIP\":\"\"," + request + "}";

        std::string idcPacketReq = "{\"idcPacket\":" + idcPacket + "}";

        //Log::instance()->printf(Log::Information, "************* idcPacketReq: %s", idcPacketReq);
        rc = p_http_client_obj.sendRequest(DAHttp::ReqType::ePOST, apiurl, json_response, idcPacketReq);
        if ((rc == ERR_OK) && !json_response.empty())
        {
            rapidjson::Document json;

            json.Parse(json_response.c_str());
            if (json.HasParseError())
            {
                errMessage = " Bad response:: " + json_response;
                Log::getInstance()->printf(Log::Error, "%s : %s", __func__, errMessage.c_str());
            }
            else
            {
                const rapidjson::Value& msg_val = json["message"];

                if (msg_val.HasMember("errorMessage") && !msg_val["errorMessage"].IsNull())
                {
                    const rapidjson::Value& errMsgVal = msg_val["errorMessage"];

                    errMessage = errMsgVal.GetString();
                }
                else if (msg_val.HasMember("idcResponse") && !msg_val["idcResponse"].IsNull())
                {
                    const rapidjson::Value& idcRespVal = msg_val["idcResponse"];
                    rapidjson::StringBuffer buffer;
                    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

                    idcRespVal.Accept(writer);

                    std::string jsonStr = buffer.GetString();

                    token = jsonStr;
                    Log::getInstance()->printf(Log::Debug, "%s : FINAL token:%s", __func__, jsonStr.c_str());
                    retVal = true;
                }
            } // if (json.HasParseError())
        } // if (errorCode != SDK_NO_ERROR)
    } // authenticated
    else
    {
        Log::getInstance()->printf(Log::Error, " %s Device failed to authenticate in getIDC()", __func__);
    }
    
    mutex_unlock();

    return retVal;
}

std::string DeviceAuthority::doCipherAES(const std::string &key, const std::string &iv, const std::string &input, CipherMode mode)
{
    std::string output;
    if (pfnaudaddk_docipher_aes_cfb128)
    {
        unsigned char* result = 0;
        int res = pfnaudaddk_docipher_aes_cfb128(key.c_str(), key.size(), iv.c_str(), iv.size(), (const unsigned char*)input.c_str(), input.size(), &result, mode);
        if (res >= 0)
        {
            output.assign(result, result + res);
            pfnaudaddk_freebuffer((char**)&result);
        }
        else
        {
            Log::getInstance()->printf(Log::Error, " %s Failed to doCipherAES error:%d", __func__, res);
        }
    }
    return output;
}

int DeviceAuthority::doCipherAES(const char* key, const int key_sz, const char* iv, const int iv_sz, const char* input, const int input_sz, CipherMode mode, char** output) {

    if (pfnaudaddk_docipher_aes_cfb128)
    {
        unsigned char* result = 0;
        int res = pfnaudaddk_docipher_aes_cfb128(key, key_sz, iv, iv_sz, (const unsigned char*)input, input_sz, &result, mode);
        if (res >= 0)
        {
            //output.assign(result, result + res);
            *output = new char[res + 1];
            memcpy(*output, result, res);
            (*output)[res] = '\0';
            pfnaudaddk_freebuffer((char**)&result);
        }
        else
        {
            Log::getInstance()->printf(Log::Error, " %s Failed to doCipherAES error:%d", __func__, res);
        }
        return res;
    }
    return -1;
}

std::string DeviceAuthority::doDigestSHA256(const std::string &input)
{
    std::string output;
    if ( pfnaudaddk_dodigest_sha256)
    {
        unsigned char* result = 0;
        int res = pfnaudaddk_dodigest_sha256(input.c_str(), input.size(), &result);
        if (res >= 0)
        {
            output.assign(result, result + res);
            pfnaudaddk_freebuffer((char**)&result);
        }
        else
        {
            Log::getInstance()->printf(Log::Error, " %s Failed to doDigestSHA256 error:%d", __func__, res);
        }
    }
    return output;
}

//
// Keyscaler Edge Supports
//

std::string DeviceAuthority::identifyAndAuthoriseForEdge(const std::string& deviceMeta, std::string& keyID, std::string& key, std::string& iv, std::string& message, std::string& metadata, void *p_client_ptr, std::string policyID)
{
    Log *logger = Log::getInstance();

#if defined(ENABLE_VERBOSE_LOG)
    logger->printf(Log::Debug, "*****identifyAndAuthoriseForEdge(lock wait) called");
#endif // #if defined(ENABLE_VERBOSE_LOG)

    mutex_lock();

#if defined(ENABLE_VERBOSE_LOG)
    logger->printf(Log::Debug, "*****identifyAndAuthoriseForEdge(lock acquired) called");
#endif // #if defined(ENABLE_VERBOSE_LOG)

    std::string result;
    bool registered = true; // Assume true for now
    int status_code = 0;
    std::string challenge = authorisationChallenge(message, registered, (void *)p_client_ptr, status_code, policyID);

#if defined(ENABLE_VERBOSE_LOG)
    logger->printf(Log::Debug, "*****authorisationChallenge returned %d", challenge.size());
#endif // #if defined(ENABLE_VERBOSE_LOG)
    if (!challenge.empty())
    {
        // The SAC will inform if registration is needed first
        if (registered)
        {
            result = getBodyJSONForAPICall(challenge, keyID, key, iv, "", "", message);
        }
        else
        {
            // Need to register first
            logger->printf(Log::Information, "Device registration required");
            if (mp_event_manager) 
            {
                mp_event_manager->notifyRegistrationRequired();
            }

            registered = registration(challenge, message, metadata);
            if (registered)
            {
                if (!message.empty())
                {
                    logger->printf(Log::Information, message.c_str());
                }
                result = identifyAndAuthorise(keyID, key, iv, message, p_client_ptr, policyID);
            }
        }
    }
    
    mutex_unlock();

#if defined(ENABLE_VERBOSE_LOG)
    logger->printf(Log::Debug, "*****identifyAndAuthorise(lock released) called size:%d error:%s", result.size(), message.c_str());
#endif // #if defined(ENABLE_VERBOSE_LOG)

    return result;
}

/*
 * Gets the device key from the DDKG (with or without challenge) for Keyscaler Edge
 *
 * @param edgeDeviceMeta  input value containing Keyscaler Edge device meta JSON. See note below.
 * @param challengeID  optional input value containing DDKG challenge when non empty.
 * @param message  output param containing error Information.
 * @param keyId  output param containing keyId from the DDKG response.
 * @param key  output param containing key from the DDKG response.
 * @param iv  output param containing iv from the DDKG response.
 *
 * @note
 * "edge_device_meta": {
 *   "keyAndExpiry": {
 *     "key": null,
 *     "expiry": null
 *   },
 *   "signature": {
 *     "algo": null,
 *     "data": null,
 *     "encoding": null,
 *     "key_type": null,
 *     "sig_algo": null
 *   }
 * }
 */
std::string DeviceAuthority::getDeviceKeyForEdge(const std::string& edgeDeviceMeta, const std::string& challengeID, std::string& message, char *keyid, char *key, char *iv)
{
    if (edgeDeviceMeta.empty())
    {
        return getDeviceKey(challengeID, message, keyid, key, iv);
    }

    // We have device meta data from Credentials Manager (Agent)
    std::string deviceKey("");
    int result = kDDKStatusError;
    char *deviceKeyJSON = NULL;

    if (!challengeID.empty())
    {
        //Log::getInstance()->printf(Log::Debug, " %s:%d", __func__, __LINE__);
        const std::string deviceRole(DEVICE_ROLE);
        const std::string udi = config.lookup(CFG_UDI);
        std::string deviceMeta = "{\"device_role\":\"" + deviceRole + "\"";

        if ((udi.length() > 0) && pfnaudaddk_getdevicekeywithchallenge_withdevicemeta)
        {
            deviceMeta += ",\"device_meta\":[{\"name\":\"deviceId\",\"value\":\"" + udi + "\"}]";
            deviceMeta += "}";
            result = pfnaudaddk_getdevicekeywithchallenge_withdevicemeta(challengeID.c_str(), deviceMeta.c_str(), &deviceKeyJSON);
        }
        else if (pfnaudaddk_getdevicekeywithchallenge_withdevicerole)
        {
            deviceMeta += "}";
            result = pfnaudaddk_getdevicekeywithchallenge_withdevicerole(challengeID.c_str(), deviceRole.c_str(), &deviceKeyJSON);
        }
    }
    else
    {
        const std::string cryptoProvider = config.lookup(CFG_KEYSTORE_PROVIDER);
        std::string deviceMeta = "{\"provider\":\"" + cryptoProvider + "\"";

        deviceMeta += "," + edgeDeviceMeta;
        deviceMeta += "}";
        //Log::getInstance()->printf(Log::Debug, " %s:%d", __func__, __LINE__);
        if (pfnaudaddk_getdevicekeyoaep)
        {
            result = pfnaudaddk_getdevicekeyoaep(cryptoProvider.c_str(), &deviceKeyJSON, NULL);
        }
    }
    if (result == kDDKStatusSuccess)
    {
        rapidjson::Document json;

        json.Parse(deviceKeyJSON);
        if (json.HasParseError())
        {
            message = "Unable to parse device key response.";
        }
        else
        {
            if (json.HasMember(JSON_DDK_TEXT))
            {
                const rapidjson::Value& ddkVal = json[JSON_DDK_TEXT];
                deviceKey = ddkVal.GetString();

                size_t codeStart = deviceKey.find("<code>");

                if (codeStart != string::npos)
                {
                    codeStart += 6;

                    size_t codeEnd = deviceKey.find("</code>", codeStart);
                    std::string errorCode = deviceKey.substr(codeStart, codeEnd - codeStart);

                    message = "Device key generation has failed with code " + errorCode + ".";
                    deviceKey = "";
                }
                else
                {
                    //printf("\n In %s LINE %d \n", __func__, __LINE__);
                    // Try this to make device key acceptable: strip out '\n'
                    deviceKey.erase(remove(deviceKey.begin(), deviceKey.end(), '\n'), deviceKey.end());

                    // There are also "\n" (2 characters) in it that need to be removed.
                    std::string newKey = "";
                    unsigned int deviceKeyLength = deviceKey.length();

                    for (unsigned int i = 0; i < deviceKeyLength; ++i)
                    {
                        if ((deviceKey[i] == '\\') && (deviceKey[i + 1] == 'n'))
                        {
                            ++i;
                        }
                        else
                        {
                            newKey += deviceKey[i];
                        }
                    }
                    deviceKey = newKey;
                    //Log::getInstance()->printf(Log::Debug, "In %s LINE %d Generated device key successfully %s \n", __func__, __LINE__, deviceKey.c_str());
                    //message = "Generated device key successfully.";
                }
            }
            if (json.HasMember(JSON_IOT_TEXT))
            {
                const rapidjson::Value& iotVal = json[JSON_IOT_TEXT];
                /*
                rapidjson::StringBuffer buffer;
                rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
                json.Accept(writer);
                std::string jsonStr = buffer.GetString();
                Log::getInstance()->printf(Log::Debug, "\n %s:%d input: %s", __func__, __LINE__ , jsonStr.c_str());
                */

                if (keyid && key && iv)
                {
                    if (iotVal.HasMember(JSON_KEY_ID_TEXT))
                    {
                        const rapidjson::Value& keyIdVal = iotVal[JSON_KEY_ID_TEXT];
                        std::string keyIdStr = keyIdVal.GetString();

                        if (keyid)
                        {
#if __STDC_WANT_SECURE_LIB__
                            size_t cbKeyId = keyIdStr.length();

                            strcpy_s(keyid, cbKeyId + 1, keyIdStr.c_str());
#else
                            strcpy(keyid, (char *)keyIdStr.c_str());
#endif // #if __STDC_WANT_SECURE_LIB__
                        }
                    }
                    if (iotVal.HasMember(JSON_KEY_TEXT))
                    {
                        const rapidjson::Value& keyVal = iotVal[JSON_KEY_TEXT];
                        std::string keyStr = keyVal.GetString();

                        if (key)
                        {
#if __STDC_WANT_SECURE_LIB__
                            size_t cbKey = keyStr.length();

                            strcpy_s(key, cbKey + 1, keyStr.c_str());
#else
                            strcpy(key, (char *)keyStr.c_str());
#endif // #if __STDC_WANT_SECURE_LIB__
                        }
                    }
                    if (iotVal.HasMember(JSON_IV_TEXT))
                    {
                        const rapidjson::Value& ivVal = iotVal[JSON_IV_TEXT];
                        std::string  ivStr = ivVal.GetString();

                        if (iv)
                        {
#if __STDC_WANT_SECURE_LIB__
                            size_t cbIv = ivStr.length();

                            strcpy_s(iv, cbIv + 1, ivStr.c_str());
#else
                            strcpy(iv, (char *)ivStr.c_str());
#endif // #if __STDC_WANT_SECURE_LIB__
                        }
                    }
                    else
                    {
                        message = "Device key generation has failed, no key data found.";
                        deviceKey = "";
                    }
                }
            }
        }
        if (pfnaudaddk_freedevicekey)
        {
            result = pfnaudaddk_freedevicekey(&deviceKeyJSON);
        }
    } //if (result == kDDKStatusSuccess)
    else
    {
        ostringstream oss;

        Log::getInstance()->printf(Log::Information, " %s:%d Failed to generate device key: %d", __func__, __LINE__, result);

        oss << "Failed to generate device key, error: " << result << ".";
        message = oss.str();
    }
    //OpenSSL_add_all_algorithms(); // Fix for issue where call to da function clobbers ssl context
    //logger.printf(Log::Debug, " %s:%d deviceKey size: %ld", __func__, __LINE__, deviceKey.size());
    //logger.printf(Log::Debug, " %s:%d message: %s", __func__, __LINE__, message.c_str());

    return deviceKey;
}

std::string DeviceAuthority::authorisationChallengeForEdge(const std::string& deviceMeta, std::string& message, bool& registered, void *p_client_ptr, std::string policyID)
{
    Log::getInstance()->printf(Log::Debug, " %s:%d", __func__, __LINE__);

    if (mp_event_manager) 
    {
        mp_event_manager->notifyAuthorizationInProgress();
    }
    
    std::string deviceKey;
    std::string result = "";

    if (m_deviceTID.empty())
    {
        if (deviceMeta.empty())
        {
            deviceKey = getDeviceKey("", message);
        }
        else
        {
            deviceKey = getDeviceKeyForEdge(deviceMeta, "", message);
        }
    }
#if defined(ENABLE_VERBOSE_LOG)
    Log::getInstance()->printf(Log::Debug, " %s:%d deviceKey size:%d ", __func__, __LINE__, deviceKey.size());
#endif // #if defined(ENABLE_VERBOSE_LOG)
    if (!deviceKey.empty() || !m_deviceTID.empty())
    {
        std::string bodytext = "{\"userAgent\":\"" + m_user_agent + "\","
                                "\"challengeType\":\"" + CHTYPEAUTH_TEXT + "\","
                                "\"ddkgVersion\":\"" + m_version + "\",";
        if (!m_user.empty())
        {
            // Add userId to json string
            bodytext += "\"userId\":\"" + m_user + "\",";
        }
        if (!policyID.empty())
        {
            // Add policyId to json string
            bodytext += "\"encryptPolicyId\":\"";
            bodytext += policyID;
            bodytext += "\",";
        }
        //if (deviceKey.empty())
        //{
        //    bodytext += "\"tid\":\"" + m_deviceTID + "\"}";
        //}
        //else if (m_deviceTID.empty())
        bodytext += "\"deviceKey\":\"" + deviceKey + "\"";
        bodytext += "}";
        Log::getInstance()->printf(Log::Debug, " %s:%d send challenge", __func__, __LINE__);

        int status_code = 0;
        result = challenge(CHTYPEAUTH_TEXT, bodytext, registered, message, p_client_ptr, status_code);
    }
#if defined(ENABLE_VERBOSE_LOG)
    Log::getInstance()->printf(Log::Debug, "Exit %s %d registered :%d ", __func__, __LINE__, registered);
#endif // #if defined(ENABLE_VERBOSE_LOG)

    return result;
}
