/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * A wrapper for the Device Authority security calls
 */
#ifndef DEVICE_AUTHORITY_HPP
#define DEVICE_AUTHORITY_HPP

#if defined(WIN32)
#include <Windows.h>
#endif // #if defined(WIN32)
#include <string>
#include "DeviceKeyDef.h"
#include <vector>
#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"     // rapidjson's DOM-style API
#include "rapidjson/prettywriter.h" // for stringify JSON
#include "rapidjson/stringbuffer.h" // for stringify JSON
#include "deviceauthority_base.hpp"
#include "event_manager_base.hpp"
#include "log.hpp"

#if defined(WIN32)
#define NPUDADDK_DLL TEXT("npUDADDK.dll")
#else
typedef void* HMODULE;
#endif // #ifndef _WIN32

class Log;

class DeviceAuthority : public DeviceAuthorityBase
{
public:
    // Error code raised by the DAE when the synthetic material ID is not found in the database
    static const int CHALLENGE_NO_DEVICE_WITH_ID_KEY = 1120;
    static const char* CHTYPEAUTH_TEXT;
    static const char* CHTYPEFULL_TEXT;

    static void setInstance(DeviceAuthorityBase *pDeviceAuthority);
    static DeviceAuthorityBase *getInstance();
    static DeviceAuthorityBase *getInstanceForApp(const std::string& DAUser, const std::string& DAAPIURL, const std::string& deviceName, const std::string& cryptoProvider);
    static DeviceAuthorityBase *getInstanceForEdge(const std::string& DAUser, const std::string& DAAPIURL, const std::string& deviceName, const std::string& cryptoProvider, const std::string& edgePublicKeyJSON);
    // Identify, then authorise with DA and return the json body needed to make the policy gateway call (will register if needed)
    std::string identifyAndAuthorise(std::string& keyID, std::string& key, std::string& iv, std::string& message, void *clientPtr, std::string policyID = "");
    std::string identifyAndAuthorise(std::string& keyID, std::string& key, std::string& iv, std::string& message, std::string& metadata, void *clientPtr, std::string policyID = "");

    void setEventManager(EventManagerBase *p_event_manager) override;

    /**
    * @brief Authorizes the application wanting to decrypt the certs using application hash.
    * @param key_id input value containing KeyId in the encrypted JSON structure
    * @param key output value from the authorization challenge.
    * @param iv output value from the authorization challenge.
    * @param message output value containing error string
    * @param apphash a hash value generated on the application binary
    * @param asset_id_str input value containing assetId in the encrypted JSON structure
    * @param client_obj input value containing pointer to curl client object.
    */
    std::string authoriseTheApp(std::string& keyID, std::string& key, std::string& iv, std::string& message, const std::string& appHash, const std::string& assetIdStr, void *clientPtr);

    /**
    * @brief Authorizes the application wanting to decrypt the certs using application hash.
    * @param key_id input value containing KeyId in the encrypted JSON structure
    * @param key output value from the authorization challenge.
    * @param iv output value from the authorization challenge.
    * @param message output value containing error string
    * @param apphash a hash value generated on the application binary
    * @param sign_apphash if true will generate a hmac signature on the apphash
    * @param asset_id_str input value containing assetId in the encrypted JSON structure
    * @param client_obj input value containing pointer to curl client object.
    */
    std::string authoriseTheApp(std::string& key_id, std::string& key, std::string& iv, std::string& message, const std::string& apphash, bool sign_apphash, const std::string& asset_id_str, void *client_ptr);

    std::string doCipherAES(const std::string &key, const std::string &iv, const std::string &input, CipherMode mode);
    int doCipherAES(const char * key, const int key_sz, const char* iv, const int iv_sz, const char* input, const int input_sz, CipherMode mode, char ** output);
    std::string doDigestSHA256(const std::string &input);
    std::string getDeviceKey(const std::string& challengeID, std::string& message, char* keyid = 0, char* key = 0, char* iv = 0);
    std::string getDeviceTid();
    bool getIDCToken(std::string &token);
    bool destroyInstance();
    void setAPIURL(const std::string& APIURL);
    void setUserId(const std::string& user);
    // Write UDI to the DDKG
    bool setUDI(const std::string &udi) const override;
    // Read UDI from the DDKG
    const std::string getUDI() const override;
    // Write Ext DDKG UDI property name to DDKG
    bool setExtDdkgUDIPropertyName(const std::string &udi_property) const;
    // Write DDKG root filesystem path to DDKG
    bool setDdkgRootFilepath(const std::string &ddkg_root_fs) const;

    const std::string &getUserId() const override
    {
        return m_user;
    }

    // Keyscaler Edge Support
    const std::string& userAgentString() const;
    const std::string& platformString() const;
    std::string identifyAndAuthoriseForEdge(const std::string& deviceMeta, std::string& keyID, std::string& key, std::string& iv, std::string& message, std::string& metadata, void *clientPtr, std::string policyID = "");

private:
    // To disable copying of Singleton class
    DeviceAuthority(const DeviceAuthority&);
    DeviceAuthority(const std::string& user, const std::string& APIURL, const std::string& deviceName, const std::string& cryptoProvider);
#if defined(WIN32)
    DeviceAuthority(const std::string& user, const std::string& APIURL, const std::string& deviceName, const std::string& cryptoProvider, const std::string& ddkgLib, const std::string& libDir); // Used only for unit testing
#endif // #if defined(WIN32)
    virtual ~DeviceAuthority();

    DeviceAuthority& operator=(const DeviceAuthority&);

    // Do registration. This only needs to be done once (ever) unless the device has been removed from DA.
    bool registration(const std::string& challengeID, std::string& message);
    bool registration(const std::string& challengeID, std::string& message, std::string& metadata);
    // Request an registration challenge from DA
    std::string registrationChallenge(std::string &message, void *clientPtr);
    // Request an authorisation challenge from DA (via reliant party)
    std::string authorisationChallenge(std::string& message, bool& registered, void *clientPtr, int &status_code, std::string policyID = "");
    // Generate the json body needed for the policy gateway call
    std::string getBodyJSONForAPICall(const std::string &challenge_id, std::string &key_id, std::string &key, std::string &iv, const std::string &apphash, const std::string& asset_id_str, std::string &message);
    std::string getBodyJSONForAPICall(const std::string &challenge_id, std::string &key_id, std::string &key, std::string &iv, const std::string &apphash, bool sign_apphash, const std::string& asset_id_str, std::string &message);
    std::string challenge(const std::string& type, const std::string& bodytext, bool& registered, std::string& message, void *clientPtr, int &status_code);
    //std::string getDeviceKey(const std::string& challengeID, std::string& message, char *keyid = 0, char *key = 0, char *iv = 0);
    // Load up the dynamic ddk library
    bool loadLibrary();

    // Keyscaler Edge Support
    std::string getDeviceKeyForEdge(const std::string& edgeDeviceMeta, const std::string& challengeID, std::string& message, char *keyid = 0, char *key = 0, char *iv = 0);
    std::string authorisationChallengeForEdge(const std::string& deviceMeta, std::string& message, bool& registered, void *clientPtr, std::string policyID = "");

private:
    static DeviceAuthorityBase *mp_da_instance;    // Singleton
    
#if defined(USETHREADING)
    static pthread_mutex_t mutexDA_;
#endif // #if defined(USETHREADING)
    /// @brief Pointer to the event manager instance
    EventManagerBase *mp_event_manager;

    bool m_registered;
    std::string m_user;
    std::string m_APIURL;
    std::string m_user_agent;
    std::string m_platform;
    std::string m_device_name;
    std::string m_version;
    std::string m_crypto_provider;
#if defined(WIN32)
    std::string libDir_;
    std::string ddkgLib_;
#endif // #if defined(WIN32)

    NAUDADDK_GETDEVICEKEYWITHCHALLENGE_WITHDEVICEROLE_PROC pfnaudaddk_getdevicekeywithchallenge_withdevicerole;
    NAUDADDK_GETDEVICEKEYWITHCHALLENGE_WITHDEVICEMETA_PROC pfnaudaddk_getdevicekeywithchallenge_withdevicemeta;
    NAUDADDK_DOCIPHER_AES_CFB128_PROC pfnaudaddk_docipher_aes_cfb128;
    NAUDADDK_DODIGEST_SHA256_PROC pfnaudaddk_dodigest_sha256;
    NAUDADDK_GETDEVICEKEY_PROC pfnaudaddk_getdevicekey;
    NAUDADDK_GETDEVICEKEYOAEP_PROC pfnaudaddk_getdevicekeyoaep;
    NAUDADDK_GETDEVICETID_PROC pfnaudaddk_getdevicetid;
    NAUDADDK_GETDEVICEKEY_FOREDGE_PROC pfnaudaddk_getdevicekey_foredge;
    NAUDADDK_FREEDEVICEKEY_PROC pfnaudaddk_freedevicekey;
    NAUDADDK_GETDEVICEKEYVERSION_PROC pfnaudaddk_getdevicekeyversion;
    NAUDADDK_GETUSERAGENTSTRING_PROC pfnaudaddk_getuseragentstring;
    NAUDADDK_GETPLATFORMSTRING_PROC pfnaudaddk_getplatformstring;
    NAUDADDK_FREEBUFFER_PROC pfnaudaddk_freebuffer;
    NAUDADDK_GLOBALINIT_PROC pfnaudaddk_globalinit;
    NAUDADDK_GLOBALCLEANUP_PROC pfnaudaddk_globalcleanup;
    NAUDADDK_SETUDI_PROC pfnaudaddk_setudi;
    NAUDADDK_GETUDI_PROC pfnaudaddk_getudi;
    NAUDADDK_EXTDDKG_SETUDIPROPERTYNAME pfnaudaddk_extddkg_setudipropertyname;
    NAUDADDK_SETROOTFS_PROC pfnaudaddk_setrootfs;
    std::string m_deviceTID;
    HMODULE m_hdll;
    bool m_is_edge_node;

    static void mutex_lock();
    static void mutex_unlock();
};

#endif // #ifndef DEVICE_AUTHORITY_HPP
