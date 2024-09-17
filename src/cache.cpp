/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An implementation of a cache that goes stale based on access and time.
 *
 */

#include "cache.hpp"
#include "dacryptor.hpp"
#include "configuration.hpp"
#include "log.hpp"
#include "base64.h"
#include "byte.h"
#include <sstream>
#include <cstring>
#include <cstdlib>
#include "deviceauthority.hpp"
#include "dahttpclient.hpp"
#include "constants.hpp"


Cache::cacheType Cache::cache_;
#if defined(USETHREADING)
pthread_mutex_t Cache::mutex_ = PTHREAD_MUTEX_INITIALIZER;
#endif // #if defined(USETHREADING)

Cache::Cache( unsigned int refreshTime) : refreshTime_(refreshTime)
{
}

Cache::~Cache()
{
}

void Cache::clear(void)
{
#if defined(USETHREADING)
  pthread_mutex_lock(&mutex_);
#endif // #if defined(USETHREADING)
  cache_.clear();
#if defined(USETHREADING)
  pthread_mutex_unlock(&mutex_);
#endif // #if defined(USETHREADING)
}

bool Cache::lookup(const Lookup& cacheKey, CachedData& cacheValue, std::string& message, const std::string policyid)
{
#if defined(USETHREADING)
    pthread_mutex_lock(&mutex_);
#endif // #if defined(USETHREADING)

    Log *logger = Log::getInstance();
    CachedData foundItem;

    // Look for it in the cache.
    cacheType::iterator c = cache_.find(cacheKey);
    //logger->printf(Log::Debug, "%s  %d cache size:%d cacheKey.keyID,cacheKey:%s,policyid:%s", __func__, __LINE__ , cache_.size(), cacheKey.keyID_.c_str(), cacheKey.policyID_.c_str());
    if (c == cache_.end())
    {
        // Doesn't exist in the cache.
        message = "lookup Cache miss for " + cacheKey.keyID() + ".";
        if (cacheKey.keyID().empty())
        {
            message = "lookup Generating new key.";
        }
        logger->printf(Log::Information,"Cache miss for the key..fetching new key");

        // Fetch it and insert it.
        FetchResponse result = fetch(cacheKey, cacheValue, message, policyid);

        //logger->printf(Log::Debug, " lookup Fetch %s %d", __func__, __LINE__);
        if (result == Found)
        {
            //logger->printf(Log::Debug, " %s Fetch   keyID:%s", __func__, cacheValue.keyID_.c_str());
            foundItem.setValues(cacheValue);
            cacheKey.reset();
        }
        cache_.insert(cacheType::value_type(cacheKey, foundItem));
        if ((result == NotAllowed) || (result == Error))
        {
            message = "lookup Not Authorised";
#if defined(USETHREADING)
            pthread_mutex_unlock(&mutex_);
#endif // #if defined(USETHREADING)

            return false;
        }
        c = cache_.find(cacheKey);
    }
    else if (c->first.isTimeStale(refreshTime_))
    {
        message = "lookup Cache hit but stale for " + cacheKey.keyID() + ".";
        logger->printf(Log::Information, "Crypto Key is stale..fetching new key");

        // Fetch it and insert the new one
        FetchResponse result = fetch(cacheKey, cacheValue, message, policyid);

        if (result == Found)
        {
            foundItem.setValues(cacheValue);
            cacheKey.reset();
        }
        else if ((result == NotAllowed) || (result == Error))
        {
            message = "lookup Not Authorised";
#if defined(USETHREADING)
            pthread_mutex_unlock(&mutex_);
#endif // #if defined(USETHREADING)

            return false;
        }
        if ((result != Error) && (result != NotAllowed))
        {
            // Exists in the cache but has gone stale. However only delete it if are
            // able to contact the API, if not better to keep using this out of date
            // one for now.
            message = "lookup Cache refreshed for " + cacheKey.keyID() + ".";
            logger->printf( Log::Information, "Cache refreshed with new key" );

            // Delete the old one.
            if (c != cache_.end())
            {
                cache_.erase( c );
            }
            cache_.insert(cacheType::value_type(cacheKey, foundItem));
        }
        c = cache_.find(cacheKey);
    }
    // Check it has been found in the cache
    if (c != cache_.end())
    {
        logger->printf(Log::Information,"Using key from the cache");
        foundItem = c->second;
    }
    // Done like this becuase it may have been found but not
    // in the cache (e.g. if the cache was full)
    if (!foundItem.unknown())
    {
        cacheValue.keyID_ = foundItem.keyID_;
        cacheValue.key_ = foundItem.key_;
        cacheValue.iv_ = foundItem.iv_;
    }
#if defined(USETHREADING)
    pthread_mutex_unlock(&mutex_);
#endif // #if defined(USETHREADING)

    return !foundItem.unknown();
}

Cache::FetchResponse Cache::fetch( const Lookup& cacheKey, CachedData& cacheValue, std::string& message, const std::string  policyid )
{
    static const unsigned short maxParamLength = 100;

    Log::getInstance()->printf(Log::Debug, "Enter %s ", __func__ );
    if (cacheKey.keyID().length() > maxParamLength)
    {
        return Error;
    }

    std::string newkeyid;
    std::string newkey;
    std::string newiv;
    FetchResponse rc = NotAllowed;
    Log *logger = Log::getInstance();
    static const std::string DAUser = config.lookup(CFG_DAUSERID);
    static const std::string DAAPIURL = config.lookup(CFG_DAAPIURL);
    static const std::string deviceName = config.lookup(CFG_DEVICENAME);
    DeviceAuthorityBase *daInstance = DeviceAuthority::getInstance();

    if (!daInstance)
    {
        message = "Failed to obtain DeviceAuthority instance";
        logger->printf(Log::Error, message.c_str());

        return rc;
    }
    if (cacheKey.keyID().empty())
    {
        DAHttpClient httpClientObj(daInstance->userAgentString());
        std::string daJSON = daInstance->identifyAndAuthorise(newkeyid, newkey, newiv, message, &httpClientObj, policyid);

        if (!daJSON.empty())
        {
            //logger->printf( Log::Debug, "%s %d",__func__,__LINE__ );
            rc = Found;
            //logger->printf( Log::Debug, "KeyID is: %s", newkeyid.c_str() );
            //logger->printf( Log::Debug, "Key is: %s", newkey.c_str() );
            //logger->printf( Log::Debug, "IV is: %s", newiv.c_str() );
            unsigned char decodedData[1024] = {};
            unsigned int decodedLength = base64Decode( newkey.c_str(), decodedData, 1024 );

            if (decodedLength)
            {
                newkey = std::string((const char *)decodedData, decodedLength);
            }
            else
            {
                logger->printf(Log::Critical, "Unable to decode key (E).");
                rc = Error;
            }
            decodedLength = base64Decode(newiv.c_str(), decodedData, 1024);
            if (decodedLength)
            {
                newiv = std::string((const char *)decodedData, decodedLength);
            }
            else
            {
                logger->printf(Log::Critical, "Unable to decode IV (E).");
                rc = Error;
            }
            cacheValue.keyID_ = newkeyid;
            cacheValue.key_ = newkey;
            cacheValue.iv_ = newiv;

            std::string apiurl = DAAPIURL + "/auth";
            DAErrorCode rcHttpClient= ERR_OK;
            rapidjson::Document json;
            std::string jsonResponse;

            rcHttpClient = httpClientObj.sendRequest(DAHttp::ReqType::ePOST, apiurl, jsonResponse, daJSON);
            if (rcHttpClient != ERR_OK)
            {
                return Error;
            }
            if (jsonResponse.length() > 0)
            {
                json.Parse(jsonResponse.c_str());
                if (json.HasParseError())
                {
                    logger->printf(Log::Warning, " %s Bad responseData %s \n", __func__, jsonResponse.c_str());

                    return Error;
                }
            }
            /*
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

            json.Accept(writer);

            std::string jsonStr = buffer.GetString();

            Log::getInstance()->printf(Log::Debug, "\n %s:%d policies: %s", __func__, __LINE__ , jsonStr.c_str());
            */
            if (!json.IsNull())
            {
                if (json.HasMember("message"))
                {
                    const rapidjson::Value& msgVal = json["message"];

                    if (msgVal.HasMember( "authenticated"))
                    {
                        const rapidjson::Value& authVal = msgVal["authenticated"];
                        bool auth = authVal.GetBool();

                        if (!auth)
                        {
                            logger->printf(Log::Error, "Authentication failed.");
                            rc = Error;
                        }
                    }
                    else
                    {
                        logger->printf(Log::Error, "No authentication reponse value from API (was expected).");
                        rc = Error;
                    }
                }
                else
                {
                    // There isn't a match
                    logger->printf(Log::Error, "No authentication response from API (was expected).");
                    rc = NotFound;
                }
            }
        }
        else
        {
            rc = NotAllowed;
            logger->printf(Log::Error, message.c_str());
        }
    }
    else
    {
        std::string newkeyid = cacheKey.keyID(); // Pass in the keyID we are looking for (so can be added to daJSON)
        DAHttpClient httpClientObj(daInstance->userAgentString());
        std::string daJSON = daInstance->identifyAndAuthorise( newkeyid, newkey, newiv, message,&httpClientObj );

        if (!daJSON.empty())
        {
            std::string apiurl = DAAPIURL + "/key";
            DAErrorCode rcHttpClient= ERR_OK;
            rapidjson::Document json;
            std::string jsonResponse;

            rcHttpClient = httpClientObj.sendRequest(DAHttp::ReqType::ePOST, apiurl, jsonResponse, daJSON);
            if (rcHttpClient != ERR_OK)
            {
                return Error;
            }
            if (jsonResponse.length() > 0)
            {
                json.Parse<0>(jsonResponse.c_str());
                if (json.HasParseError())
                {
                    logger->printf(Log::Warning, " %s Bad responseData %s \n", __func__, jsonResponse.c_str());

                    return Error;
                }
            }
            if (!json.IsNull())
            {
                //logger->printf(Log::Debug, "KeyID is: %s", newkeyid.c_str());
                //logger->printf(Log::Debug, "Key is: %s", newkey.c_str());
                //logger->printf(Log::Debug, "IV is: %s", newiv.c_str());
                unsigned char decodedData[1024] = "";
                unsigned int decodedLength = base64Decode(newkey.c_str(), decodedData, 1024);

                if (decodedLength)
                {
                    newkey = std::string((const char *)decodedData, decodedLength);
                }
                else
                {
                    logger->printf(Log::Critical, "Unable to decode key (E).");
                    rc = Error;
                }
                decodedLength = base64Decode(newiv.c_str(), decodedData, 1024);
                if (decodedLength)
                {
                    newiv = std::string((const char *)decodedData, decodedLength);
                }
                else
                {
                    logger->printf(Log::Critical, "Unable to decode IV (E).");
                    rc = Error;
                }
                if (rc != Error)
                {
                    // The key and iv returned from the API will be encrypted to the key generated as part
                    // of the authentication above.  Decrypted the key/iv so that it can be used.
                    dacryptor cryptor;

                    cryptor.setCryptionKey(newkey); // Use the key generated above
                    cryptor.setInitVector(newiv); // Use the iv generated above
                    // Get key from json
                    if (json.HasMember("message"))
                    {
                        const rapidjson::Value& msgVal = json["message"];

                        if (msgVal.HasMember("key"))
                        {
                            const rapidjson::Value& keyVal = msgVal["key"];
                            std::string encodedKey = keyVal.GetString();

                            rc = Found;
                            cryptor.setInputData(encodedKey);
                            if (cryptor.decrypt())
                            {
                                const da::byte *output;
                                unsigned int length;

                                cryptor.getCryptedData(output, length);
                                // Need to strip off padding that will have been left over from decrypt
                                // I SHOULDNT NEED TO DO THIS REALLY.  Something is not right between the
                                // encryption code (on the DAE side) and the decryption code in IPWorks.

                                length -= output[length - 1];

                                cacheValue.key_ = std::string((const char *)output, length);
                            }
                            else
                            {
                                logger->printf(Log::Critical, "Unable to decode key (D).");
                                rc = Error;
                            }
                        }
                        else
                        {
                            // There isn't a match
                            logger->printf(Log::Critical, "No key returned from API (was expected) for keyID '%s'.", cacheKey.keyID().c_str());
                            rc = Error;
                        }
                        if (msgVal.HasMember("iv"))
                        {
                            const rapidjson::Value& ivVal = msgVal["iv"];
                            // The data will have a " at the start and end of it which needs to be removed
                            std::string encodedIV = ivVal.GetString();

                            rc = Found;
                            cryptor.setInputData(encodedIV);
                            if (cryptor.decrypt())
                            {
                                const da::byte *output;
                                unsigned int length;

                                cryptor.getCryptedData(output, length);
                                // Need to strip off padding that will have been left over from decrypt
                                // I SHOULDNT NEED TO DO THIS REALLY.  Something is not right between the
                                // encryption code (on the DAE side) and the decryption code in IPWorks.

                                length -= output[length - 1];

                                cacheValue.iv_ = std::string((const char*) output, length);
                            }
                            else
                            {
                                logger->printf(Log::Critical, "Unable to decode IV (D).");
                                rc = Error;
                            }
                        }
                        else
                        {
                            // There isn't a match
                            logger->printf(Log::Critical, "No IV returned from API (was expected) for keyID '%s'.", cacheKey.keyID().c_str());
                            rc = Error;
                        }
                    }
                }
            }
        }
        else
        {
            rc = NotAllowed;
            logger->printf(Log::Error, message.c_str());
        }
    }

    return rc;
}
