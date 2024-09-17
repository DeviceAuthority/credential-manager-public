/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * A base class for the Device Authority security calls
 */
#ifndef IDEVICE_AUTHORITY_HPP
#define IDEVICE_AUTHORITY_HPP

#include <string>
#include "event_manager_base.hpp"

enum CipherMode
{
    CipherModeDecrypt = 0,
    CipherModeEncrypt = 1
};

class DeviceAuthorityBase
{
public:
    virtual ~DeviceAuthorityBase() {};

    virtual void setEventManager(EventManagerBase *p_event_manager) = 0;
    virtual std::string identifyAndAuthorise(std::string& keyID, std::string& key, std::string& iv, std::string& message, void *clientPtr, std::string policyID = "") = 0;
    virtual std::string identifyAndAuthorise(std::string& keyID, std::string& key, std::string& iv, std::string& message, std::string& metadata, void *clientPtr, std::string policyID = "") = 0;
    virtual std::string authoriseTheApp(std::string& key_id, std::string& key, std::string& iv, std::string& message, const std::string& apphash, const std::string& asset_id_str, void *p_client_ptr) = 0;
    virtual std::string authoriseTheApp(std::string& key_id, std::string& key, std::string& iv, std::string& message, const std::string& apphash, bool sign_apphash, const std::string& asset_id_str, void *p_client_ptr) = 0;
    virtual std::string doCipherAES(const std::string &key, const std::string &iv, const std::string &input, CipherMode mode) = 0;
    virtual int doCipherAES(const char * key, const int key_sz, const char* iv, const int iv_sz, const char* input, const int input_sz, CipherMode mode, char ** output) = 0;
    virtual std::string doDigestSHA256(const std::string &input) = 0;
    virtual std::string getDeviceKey(const std::string& challengeID, std::string& message, char* keyid = 0, char* key = 0, char* iv = 0) = 0;
    virtual std::string getDeviceTid() = 0;
    virtual bool getIDCToken(std::string &token) = 0;
    virtual bool destroyInstance() = 0;
    virtual void setAPIURL(const std::string& APIURL) = 0;
    virtual void setUserId(const std::string& user) = 0;
    virtual bool setUDI(const std::string &udi) const = 0;
    virtual const std::string getUDI() const = 0;
    virtual bool setExtDdkgUDIPropertyName(const std::string &udi_property) const = 0;
    virtual bool setDdkgRootFilepath(const std::string &ddkg_root_fs) const = 0;
    virtual const std::string &getUserId() const = 0;

    // Keyscaler Edge Support
    virtual const std::string &userAgentString() const = 0;
    virtual const std::string &platformString() const = 0;
    virtual std::string identifyAndAuthoriseForEdge(const std::string& deviceMeta, std::string& keyID, std::string& key, std::string& iv, std::string& message, std::string& metadata, void *clientPtr, std::string policyID = "") = 0;
};

#endif // #ifndef IDEVICE_AUTHORITY_HPP
