
/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Tester implementation of the DeviceAuthority DDKG interface
 */
#ifndef TEST_DEVICEAUTHORITY_HPP
#define TEST_DEVICEAUTHORITY_HPP

#if defined(WIN32)
#include <Windows.h>
#endif // #if defined(WIN32)
#if defined(USETHREADING)
#include <pthread.h>
#endif // #if defined(USETHREADING)

#ifdef _WIN32
#include <codecvt>
#else // # ifdef _WIN32
#include <dlfcn.h>
#endif // # ifdef _WIN32
#include "deviceauthority_base.hpp"

#if !defined(WIN32)
typedef void* HMODULE;
#endif // #ifndef _WIN32

typedef union
{
    NAUDADDK_DOCIPHER_AES_CFB128_PROC pfnaudaddk_docipher_aes_cfb128;
    NAUDADDK_DODIGEST_SHA256_PROC pfnaudaddk_dodigest_sha256;
    NAUDADDK_FREEBUFFER_PROC pfnaudaddk_freebuffer;
    NAUDADDK_GLOBALINIT_PROC pfnaudaddk_globalinit;
    NAUDADDK_GLOBALCLEANUP_PROC pfnaudaddk_globalcleanup;
    void *obj;
} uNAUDADDKFuncPtrAlias;

class TestDeviceAuthority : public DeviceAuthorityBase
{
public:
    TestDeviceAuthority()
        : mp_event_manager(nullptr), pfnaudaddk_docipher_aes_cfb128(nullptr), pfnaudaddk_dodigest_sha256(nullptr), pfnaudaddk_freebuffer(nullptr), pfnaudaddk_globalinit(nullptr), pfnaudaddk_globalcleanup(nullptr)
    {
        Log *p_logger = Log::getInstance();
		
        // Dynamically load DDKG shared library
#ifdef _WIN32
        // Convert string to wide-string
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv;
        std::wstring sDdkgLib = conv.from_bytes("npUDADDK.dll");
        m_hdll = LoadLibrary(sDdkgLib.c_str());
#else // ifdef _WIN32
        m_hdll = dlopen("libnaudaddk_shared.so", RTLD_LAZY);
#endif // ifdef _WIN32
		
        if (m_hdll)
        {
#ifdef _WIN32
			pfnaudaddk_dodigest_sha256 = (NAUDADDK_DODIGEST_SHA256_PROC)GetProcAddress(m_hdll, "naudaddk_dodigest_sha256");
			pfnaudaddk_docipher_aes_cfb128 = (NAUDADDK_DOCIPHER_AES_CFB128_PROC)GetProcAddress(m_hdll, "naudaddk_docipher_aes_cfb128");
			pfnaudaddk_freebuffer = (NAUDADDK_FREEBUFFER_PROC)GetProcAddress(m_hdll, "naudaddk_freebuffer");
			pfnaudaddk_globalinit = (NAUDADDK_GLOBALINIT_PROC)GetProcAddress(m_hdll, "naudaddk_globalinit");
			pfnaudaddk_globalcleanup = (NAUDADDK_GLOBALCLEANUP_PROC)GetProcAddress(m_hdll, "naudaddk_globalcleanup");
#else // ifdef _WIN32
            uNAUDADDKFuncPtrAlias alias;
            alias.obj = dlsym(m_hdll, "naudaddk_dodigest_sha256");
            pfnaudaddk_dodigest_sha256 = alias.pfnaudaddk_dodigest_sha256;
            alias.obj = dlsym(m_hdll, "naudaddk_docipher_aes_cfb128");
            pfnaudaddk_docipher_aes_cfb128 = alias.pfnaudaddk_docipher_aes_cfb128;
            alias.obj = dlsym(m_hdll, "naudaddk_freebuffer");
            pfnaudaddk_freebuffer = alias.pfnaudaddk_freebuffer;
            alias.obj = dlsym(m_hdll, "naudaddk_globalinit");
            pfnaudaddk_globalinit = alias.pfnaudaddk_globalinit;
            alias.obj = dlsym(m_hdll, "naudaddk_globalcleanup");
            pfnaudaddk_globalcleanup = alias.pfnaudaddk_globalcleanup;
#endif // ifdef _WIN32
        }

        // Sanity check to make sure we have all required APIs
        if (pfnaudaddk_docipher_aes_cfb128 == nullptr)
        {
            static const char *error = "Unable to find symbol naudaddk_docipher_aes_cfb128!";

            std::cerr << error << std::endl;
            if (p_logger)
            {
                p_logger->printf(Log::Alert, " %s %s", __func__, error);
            }
        }
        if (pfnaudaddk_dodigest_sha256 == nullptr)
        {
            static const char *error = "Unable to find symbol naudaddk_dodigest_sha256!";

            std::cerr << error << std::endl;
            if (p_logger)
            {
                p_logger->printf(Log::Alert, " %s %s", __func__, error);
            }
        }
        if (pfnaudaddk_globalinit == nullptr)
        {
            static const char *error = "Unable to find symbol naudaddk_globalinit!";

            std::cerr << error << std::endl;
            if (p_logger)
            {
                p_logger->printf(Log::Alert, " %s %s", __func__, error);
            }
        }
        if (pfnaudaddk_globalcleanup == nullptr)
        {
            static const char *error = "Unable to find symbol naudaddk_globalcleanup!";

            std::cerr << error << std::endl;
            if (p_logger)
            {
                p_logger->printf(Log::Alert, " %s %s", __func__, error);
            }
        }

        if (pfnaudaddk_globalinit)
        {
            pfnaudaddk_globalinit();
        }
    }

    virtual ~TestDeviceAuthority()
    {
        if (pfnaudaddk_globalcleanup)
        {
            pfnaudaddk_globalcleanup();
        }
		
#ifndef _WIN32
        if (m_hdll != nullptr)
        {
            dlclose(m_hdll);
            m_hdll = nullptr;
        }
#endif // #ifndef _WIN32
    }

    void setEventManager(EventManagerBase *p_event_manager) override
    {
        mp_event_manager = p_event_manager;
    }

    std::string identifyAndAuthorise(std::string &keyID, std::string &key, std::string &iv, std::string &message, void *clientPtr, std::string policyID = "")
    {
        std::string metadata;
        return identifyAndAuthorise(keyID, key, iv, message, metadata, clientPtr, policyID);
    }

    std::string identifyAndAuthorise(std::string &keyID, std::string &key, std::string &iv, std::string &message, std::string &metadata, void *clientPtr, std::string policyID = "")
    {
        std::string bodyText = "";

        bodyText += "{";

        if (!m_userId.empty())
        {
            // Add userId to json string
            bodyText += "\"userId\":\"" + m_userId + "\",";
        }
        if (!keyID.empty())
        {
            // A keyID will be passed in if it needs adding to the JSON
            bodyText += "\"keyId\":\"" + keyID + "\",";
        }

        const std::string deviceKey = "test_device_key";
        bodyText += "\"deviceKey\":\"" + deviceKey + "\"";
        bodyText += "}";

        keyID = "newKeyId";
        key = "E8B6C00C9ADC5E75BB656ECD429CB1643A25B111FCD22C6622D53E0722439993";
        iv = "E486BB61EB213ED88CC3CFB938CD58D7";

        return bodyText;
    }

    std::string authoriseTheApp(std::string &keyid, std::string &key, std::string &iv, std::string &message, const std::string &apphash, const std::string &asset_id_str, void *p_client_ptr)
    {
        return "";
    }

    std::string authoriseTheApp(std::string &keyid, std::string &key, std::string &iv, std::string &message, const std::string &apphash, bool sign_apphash, const std::string &asset_id_str, void *p_client_ptr)
    {
        return "";
    }

    std::string doCipherAES(const std::string &key, const std::string &iv, const std::string &input, CipherMode mode)
    {
        std::string output;
        if (pfnaudaddk_docipher_aes_cfb128)
        {
            unsigned char *result = 0;
            int res = pfnaudaddk_docipher_aes_cfb128(key.c_str(), key.size(), iv.c_str(), iv.size(), (const unsigned char *)input.c_str(), input.size(), &result, mode);
            if (res >= 0)
            {
                output.assign(result, result + res);
                pfnaudaddk_freebuffer((char **)&result);
            }
            else
            {
                Log::getInstance()->printf(Log::Error, " %s Failed to doCipherAES error:%d", __func__, res);
            }
        }
        return output;
    }

    int doCipherAES(const char *key, const int key_sz, const char *iv, const int iv_sz, const char *input, const int input_sz, CipherMode mode, char **output)
    {
        if (pfnaudaddk_docipher_aes_cfb128)
        {
            unsigned char *result = 0;
            int res = pfnaudaddk_docipher_aes_cfb128(key, key_sz, iv, iv_sz, (const unsigned char *)input, input_sz, &result, mode);
            if (res >= 0)
            {
                *output = new char[res + 1];
                memcpy(*output, result, res);
                (*output)[res] = '\0';
                pfnaudaddk_freebuffer((char **)&result);
            }
            else
            {
                Log::getInstance()->printf(Log::Error, " %s Failed to doCipherAES error:%d", __func__, res);
            }
            return res;
        }
        return -1;
    }

    std::string doDigestSHA256(const std::string &input)
    {
        std::string output;
        if (pfnaudaddk_dodigest_sha256)
        {
            unsigned char *result = 0;
            int res = pfnaudaddk_dodigest_sha256(input.c_str(), input.size(), &result);
            if (res >= 0)
            {
                output.assign(result, result + res);
                pfnaudaddk_freebuffer((char **)&result);
            }
            else
            {
                Log::getInstance()->printf(Log::Error, " %s Failed to doDigestSHA256 error:%d", __func__, res);
            }
        }
        return output;
    }

    std::string getDeviceKey(const std::string &challengeID, std::string &message, char *keyid = 0, char *key = 0, char *iv = 0)
    {
        return "devicekey";
    }

    std::string getDeviceTid()
    {
        return "";
    }

    bool getIDCToken(std::string &token)
    {
        return true;
    }

    bool destroyInstance()
    {
        return true;
    }

    void setAPIURL(const std::string &APIURL)
    {
        m_apiURL = APIURL;
    }

    void setUserId(const std::string &user)
    {
        m_userId = user;
    }

    const std::string &getUserId() const override
    {
        return m_userId;
    }

    bool setUDI(const std::string &udi) const override
    {
        return true;
    }

    const std::string getUDI() const override
    {
        return "my-device-udi";
    }

    const std::string &userAgentString() const
    {
        return m_userAgent;
    }

    const std::string &platformString() const
    {
        return m_platform;
    }

    std::string identifyAndAuthoriseForEdge(const std::string &deviceMeta, std::string &keyID, std::string &key, std::string &iv, std::string &message, std::string &metadata, void *clientPtr, std::string policyID = "")
    {
        return "";
    }

	bool setExtDdkgUDIPropertyName(const std::string &udi_property) const override
	{
		return true;
	}

	bool setDdkgRootFilepath(const std::string &ddkg_root_fs) const override
	{
		return true;
	}

private:
    EventManagerBase *mp_event_manager;
    
    NAUDADDK_DOCIPHER_AES_CFB128_PROC pfnaudaddk_docipher_aes_cfb128;
    NAUDADDK_DODIGEST_SHA256_PROC pfnaudaddk_dodigest_sha256;
    NAUDADDK_FREEBUFFER_PROC pfnaudaddk_freebuffer;
    NAUDADDK_GLOBALINIT_PROC pfnaudaddk_globalinit;
    NAUDADDK_GLOBALCLEANUP_PROC pfnaudaddk_globalcleanup;
    HMODULE m_hdll;

    std::string m_userId;
    std::string m_apiURL;
    std::string m_userAgent;
    std::string m_platform;
};

#endif // #ifndef TEST_DEVICEAUTHORITY_HPP
