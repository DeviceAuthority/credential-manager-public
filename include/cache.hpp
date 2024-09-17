#ifndef CACHE_HPP
#define CACHE_HPP

/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An implementation of a cache that goes stale based on access and time.
 *
 */

#include <map>
#include <string>
#include <cassert>
#include <ctime>
#include <pthread.h>
#include "log.hpp"

class Lookup
{
public:
    Lookup(const std::string& keyID, const std::string& policyID) : keyID_(keyID), policyID_(policyID), timestamp_(0), forceStale_(false)
    {
        reset();
    }

    // Force to be stale so that next call will refetch
    void makeStale(void) const
    {
        forceStale_ = true;
    }

    // See if item is older then refreshTime seconds.
    bool isTimeStale(unsigned int refreshTime) const
    {
        // 0 is special number means that it never goes stale
        if ((refreshTime == 0) && !forceStale_)
        {
            return false;
        }
        if (forceStale_)
        {
            return true; // Optimisation as call to time() can be expensive.
        }

        time_t currentTime = time(NULL);

        //Log::getInstance()->printf(Log::Debug, "%s currentTime:%ld", __func__, currentTime);
        //Log::getInstance()->printf(Log::Debug, "%s timestamp_:%ld", __func__, timestamp_);
        Log::getInstance()->printf( Log::Debug, "Lookup:%s diff:%f refreshTime:%ld", __func__, difftime(currentTime, timestamp_), refreshTime);

        return (difftime(currentTime, timestamp_) > refreshTime);
    }

    // Set to current time.
    void resetTimestamp(void) const
    {
        timestamp_ = time(NULL);
    }

    void reset(void) const
    {
        forceStale_ = false;
        resetTimestamp();
    }

    bool operator<(const Lookup& rhs) const
    {
        return (keyID_ < rhs.keyID_) || ((keyID_ == rhs.keyID_) && (policyID_ < rhs.policyID_));
    }

    const std::string& keyID(void) const
    {
        return keyID_;
    }

private:
    std::string keyID_;
    std::string policyID_;
    mutable time_t timestamp_;
    mutable bool forceStale_;
};

class CachedData
{
public:
    CachedData(void) : keyID_(""), key_(""), iv_("")
    {
    }

    CachedData(const std::string& key, const std::string& iv) : keyID_(""), key_(key), iv_(iv)
    {
    }

    void setValues(const CachedData& data)
    {
        keyID_ = data.keyID_;
        key_ = data.key_;
        iv_ = data.iv_;
    }

    bool unknown(void) const
    {
        return key_.empty();
    }

    std::string keyID_;
    std::string key_;
    std::string iv_;
};

class Cache
{
public:

    // -1 (large positive number) means it is switched off.
    // 0 means cache is always stale (kinda pointless having it then but still...)
    // refreshTime is in seconds.
    Cache(unsigned int refreshTime = (unsigned int)-1);
    ~Cache();

    // Look up the cryption key based on the url, direction and operation type.
    bool lookup(const Lookup& cacheKey, CachedData& cacheValue, std::string& message, const std::string  policyid = "");

    // Clear the contents of the cache
    static void clear(void);

private:
    enum FetchResponse
    {
        Error,
        Found,
        NotFound,
        NotAllowed
    };

    // Go and get the data (will do this if the cache needs updating).
    FetchResponse fetch(const Lookup& cacheKey, CachedData& cacheValue, std::string& message,const std::string  policyid = "");

    typedef std::map<Lookup, CachedData> cacheType;
    static cacheType cache_;
    static pthread_mutex_t mutex_;
    unsigned int refreshTime_;
};

#endif // #ifndef CACHE_HPP
