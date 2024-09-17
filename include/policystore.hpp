/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An implementation of a policy list that goes stale based on time.
 *
 */
#ifndef POLICYSTORE_HPP
#define POLICYSTORE_HPP

#include "policy.hpp"
#include "log.hpp"
#include "optype.h"
#include <vector>
#include <map>
#include <ctime>
#include <pthread.h>
#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "rapidjson/document.h"     // rapidjson's DOM-style API
#include "rapidjson/prettywriter.h" // for stringify JSON
#include "rapidjson/stringbuffer.h" // for stringify JSON

typedef std::map<std::string, Policy> POLICYMAP;    // (policyId,Policy)
typedef std::map<std::string, std::string> STRINGMAP;
typedef std::vector<Policy> POLICYLIST;

class PolicyStore
{
public:
    static PolicyStore *getPolicyStoreInstance(const std::string & protocol, bool loadPolicies);
    static bool destroyInstance();

    // See if item is older then refreshTime seconds.
    bool isStale(void) const
    {
        // 0 is special number means that it never goes stale
        if ((refreshTime_ == 0) && !forceStale_)
        {
            return false;
        }
        if (forceStale_)
        {
            // Optimisation as call to time() can be expensive
            return true;
        }
        time_t currentTime = time(NULL);

        Log::getInstance()->printf(Log::Debug, " PolicyStore %s diff: %f, refreshTime: %ld", __func__ , difftime(currentTime, timestamp_), refreshTime_);

        return (difftime(currentTime, timestamp_) > refreshTime_);
    }

    // Clear the contents of the store
    void clear(void);

    // Force to be stale so that next call will refetch data from SAC.
    static void makeStale(void)
    {
        forceStale_ = true;
    }

    // Set to current time.
    void resetTimestamp(void) const
    {
        timestamp_ = time(NULL);
    }

    // Reset the cache triggers
    void reset(void) const
    {
        Log::getInstance()->printf(Log::Debug, " PolicyStore reset called");
        forceStale_ = false;
        resetTimestamp();
    }

    void updatePolicyRefreshTime(int updateIntervalFromKRP)
    {
        refreshTime_ = updateIntervalFromKRP;
    }

    const std::vector<Policy *> findPoliciesWithKeyRotationPolicy(const std::string& domain,std::string& error);
    //const Policy* findPolicyWithKeyRotationPolicy(const std::string& domain, std::string& error);

    const Policy* findPolicyWithKeyRotationPolicy(const std::string& domain, DirectionType flow, MethodType method, const std::string& url, std::string& error);
    const Policy* findAPolicyMatch(const std::string& domain, std::string& error);
    const Policy* findAPolicyMatch(const std::string& domain, DirectionType flow, MethodType method, const std::string& url, std::string& error);
    // Search through the policies for a match (based on the domain, the direction and the destination url).
    bool findAPolicyMatch(const std::string& domain, DirectionType flow, MethodType method, const std::string& url, OpType& operation, std::string& name, std::string& payloadType, std::string& cryptionPath, std::string& policyID, std::string& error);

    bool getPropertiesFromPolicy(std::string domain, STRINGMAP *mapProps, OpType& operation, std::string& name, std::string& policyID, std::string& error, bool &policyUpdateFailed);

    bool processCryptoPolicies(std::string cryptoPolicies, std::string&  error);
    bool processJSONPolicies(const rapidjson::Value& jsonPolicies, std::string&  error);
    bool processPolicy(const rapidjson::Value& jsonPolicy, std::string&  error);
    // Print out the list of policies to the supplied stream
    void dumpToStream(std::ostream& os) const;

private:
    // -1 (large positive number) means it is switched off
    // 0 means is always stale (kinda pointless having it then but still...)
    // refreshTime is in seconds.
    PolicyStore(const std::string& protocol, unsigned int refreshTime = (unsigned int) -1, bool loadPolicies = false);
    ~PolicyStore();

    // Helper function to remove " from front and back of string
    std::string stripQuotes(const std::string& data) const;
    // Make a call to the SAC API to get all the policies for this device/protocol then cache them up
    bool getPoliciesFromSAC(std::string& error);

private:
    std::string protocol_;
    unsigned int refreshTime_;
    unsigned int refreshRetryTime_;
    static time_t timestamp_;
    static bool forceStale_;
    static POLICYMAP policies_;
    static PolicyStore *gPolicyStoreInstance;   // Singleton
    static pthread_mutex_t mutex_;
};

#endif // #ifndef POLICYSTORE_HPP
