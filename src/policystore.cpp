/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An implementation of a policy list that goes stale based on time.
 *
 */
#include "policystore.hpp"
#include "deviceauthority.hpp"
#include "dahttpclient.hpp"
#include "configuration.hpp"
#include "log.hpp"
#include "constants.hpp"
#include <sstream>
#include <cassert>
#include <cstdlib>
#include <vector>


POLICYMAP PolicyStore::policies_;
#if defined(USETHREADING)
#if !defined(PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP)
pthread_mutex_t PolicyStore::mutex_ = PTHREAD_MUTEX_INITIALIZER;
#else
pthread_mutex_t PolicyStore::mutex_ = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
#endif // #if !defined(PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP)
#endif // #if defined(USETHREADING)
time_t PolicyStore::timestamp_ = 0;
bool PolicyStore::forceStale_ = true;
PolicyStore *PolicyStore::gPolicyStoreInstance = NULL;

PolicyStore *PolicyStore::getPolicyStoreInstance(const std::string& protocol, bool loadPolicies)
{
#if defined(USETHREADING)
    pthread_mutex_lock(&mutex_);
#endif // #if defined(USETHREADING)
    if (gPolicyStoreInstance == NULL)
    {
        Log::getInstance()->printf(Log::Debug, " %s *** getPolicyStoreInstance SHOULD BE SEEN ONLY ONCE IN LOGS ***", __func__);

        // How long (seconds) before a cached policy is refreshed (-1 means no timeout)
        static const unsigned int pcto = config.lookupAsLong(CFG_POLICYCACHETIMEOUT);

        gPolicyStoreInstance = new PolicyStore(protocol, pcto, loadPolicies);
    }
#if defined(USETHREADING)
    pthread_mutex_unlock(&mutex_);
#endif // #if defined(USETHREADING)

    return gPolicyStoreInstance;
}

bool PolicyStore::destroyInstance()
{
    Log::getInstance()->printf(Log::Debug, "*** PolicyStore destroyInstance called ***");
#if defined(USETHREADING)
    pthread_mutex_lock(&mutex_);
#endif // #if defined(USETHREADING)
    // Calls PolicyStore destructor
    delete gPolicyStoreInstance;
    gPolicyStoreInstance = NULL;
#if defined(USETHREADING)
    pthread_mutex_unlock(&mutex_);
#endif // #if defined(USETHREADING)

    return true;
}

PolicyStore::PolicyStore(const std::string& protocol, unsigned int refreshTime, bool loadPolicies): protocol_(protocol),refreshTime_(refreshTime),refreshRetryTime_(refreshTime)
{
    if ((protocol_ != PROTO_MQTT) && (protocol_ != PROTO_HTTP) && (protocol_ != PROTO_ALWAYSON))
    {
        policies_.clear();
    }
    if (loadPolicies)
    {
        std::string error = "";
        // Make sure error string contains only errors and not information..use logger for logging information
        bool ret = getPoliciesFromSAC(error);

        if (!error.empty())
        {
            Log::getInstance()->printf(Log::Warning, " %s: policies size: %d, error: %s", __func__, policies_.size(), error.c_str());
        }
    }
}

PolicyStore::~PolicyStore()
{
    clear();
}

void PolicyStore::clear(void)
{
#if defined(USETHREADING)
    pthread_mutex_lock(&mutex_);
#endif // #if defined(USETHREADING)
    policies_.clear();
#if defined(USETHREADING)
    pthread_mutex_unlock(&mutex_);
#endif // #if defined(USETHREADING)
}

/* Used by AlwaysOn agent */
const std::vector<Policy *> PolicyStore::findPoliciesWithKeyRotationPolicy(const std::string& domain, std::string& error)
{
#if defined(USETHREADING)
    pthread_mutex_lock(&mutex_);
#endif // #if defined(USETHREADING)

    std::vector<Policy *> vect;
    Policy *p = NULL;
    Log *logger = Log::getInstance();

    // Check each time that the policy data has not gone stale
    if (isStale())
    {
        logger->printf(Log::Information, " %s: Policies are stale, updating...", __func__);
        // Refresh the data from the SAC
        if (!getPoliciesFromSAC(error))
        {
            logger->printf(Log::Error, " %s: getPoliciesFromSAC failed, next policy refresh attempt after: %d", __func__, refreshTime_);
            if (error.size())
            {
                logger->printf(Log::Error, " %s: getPoliciesFromSAC failed with error: %s", __func__, error.c_str());
            }
        }
    }
    logger->printf(Log::Debug, " %s: Searching for AlwaysOn Policy match, policies size: %d", __func__, policies_.size());
    // Now search through the policies (will be in priority order) for a match
    for (POLICYMAP::const_iterator i = policies_.begin(); i != policies_.end(); ++i)
    {
        if (i->second.isAlwaysOnMatch(domain) && i->second.operation_ == ENCRYPT)
        {
            p = new Policy(i->second);
            logger->printf(Log::Information, " %s Found a policy to Encrypt alwaysOn data name: %s", __func__, p->name_.c_str());
            vect.push_back(p);
        }
    }
#if defined(USETHREADING)
    pthread_mutex_unlock(&mutex_);
#endif // #if defined(USETHREADING)

    return vect;
}

/* Used by MQTT agent */
const Policy *PolicyStore::findPolicyWithKeyRotationPolicy(const std::string& domain, DirectionType flow, MethodType method, const std::string& url, std::string& error)
{
#if defined(USETHREADING)
    pthread_mutex_lock(&mutex_);
#endif // #if defined(USETHREADING)

    Policy *p = NULL;
    Log *logger = Log::getInstance();
    bool policyUpdateFailed = false;

    // Check each time that the policy data has not gone stale
    if (isStale())
    {
        logger->printf(Log::Information, " %s: Policies are stale, updating..", __func__);
        // Refresh the data from the SAC
        if (!getPoliciesFromSAC(error))
        {
            logger->printf(Log::Error, " %s: getPoliciesFromSAC failed, next policy refresh attempt after: %d", __func__, refreshTime_);
            if (error.size())
            {
                logger->printf(Log::Error, " %s: getPoliciesFromSAC failed with error: %s", __func__, error.c_str());
            }
            policyUpdateFailed = true;
        }
    }
    logger->printf(Log::Debug, " %s: Searching for MQTT policy match, policies size: %d", __func__, policies_.size());
    // Now search through the policies (will be in priority order) for a match
    for (POLICYMAP::const_iterator i = policies_.begin(); i != policies_.end(); ++i)
    {
        if (i->second.isAMatch(domain, flow, url, method))
        {
            if (i->second.operation_ == ENCRYPT)
            {
                p = new Policy(i->second);
                logger->printf(Log::Information, " %s: Found Encrypt policy with name: %s, payloadType: %s ", __func__, p->name_.c_str(), p->payloadType_.c_str());
                if (!policyUpdateFailed)
                {
                    refreshTime_ = p->krPolicy.updateInterval_;
                    refreshRetryTime_ = p->krPolicy.retryInterval_;
                    logger->printf(Log::Debug, " %s:%d: Policy refreshTime: %d, refreshRetryTime: %d", __func__, __LINE__, i->second.krPolicy.updateInterval_, i->second.krPolicy.retryInterval_);
                }
            }
            else
            {
                p = new Policy(i->second);
                logger->printf(Log::Information, " %s: Found Decrypt policy with name: %s", __func__, p->name_.c_str());
            }
            break;
        }
    }
#if defined(USETHREADING)
    pthread_mutex_unlock(&mutex_);
#endif // #if defined(USETHREADING)

    return (const Policy *)p;
}

const Policy* PolicyStore::findAPolicyMatch(const std::string& domain, std::string& error)
{
#if defined(USETHREADING)
    pthread_mutex_lock(&mutex_);
#endif // #if defined(USETHREADING)

    Policy *p = NULL;
    Log *logger = Log::getInstance();

    // Check each time that the policy data has not gone stale
    if (isStale())
    {
        logger->printf(Log::Information, " %s: Policies are stale, updating...", __func__);
        // Refresh the data from the SAC
        if (!getPoliciesFromSAC(error))
        {
            logger->printf(Log::Error, " %s: getPoliciesFromSAC failed, next policy refresh attempt after: %d", __func__, refreshTime_);
            if (error.size())
            {
                logger->printf(Log::Error, " %s: getPoliciesFromSAC failed with error: %s", __func__, error.c_str());
            }
        }
    }
    logger->printf(Log::Debug, " %s: Searching for a policy match, policies size: %d", __func__, policies_.size());
    // Now search through the policies (will be in priority order) for a match
    for (POLICYMAP::const_iterator i = policies_.begin(); i != policies_.end(); ++i)
    {
        if (i->second.isAlwaysOnMatch(domain))
        {
            p = new Policy(i->second);
            break;
        }
    }
#if defined(USETHREADING)
    pthread_mutex_unlock(&mutex_);
#endif // #if defined(USETHREADING)

    return (const Policy *)p;
}

const Policy *PolicyStore::findAPolicyMatch(const std::string& domain, DirectionType flow, MethodType method,
        const std::string& url, std::string& error)
{
#if defined(USETHREADING)
    pthread_mutex_lock(&mutex_);
#endif // #if defined(USETHREADING)

    Policy *p = NULL;
    Log *logger = Log::getInstance();

    // Check each time that the policy data has not gone stale
    if (isStale())
    {
        logger->printf(Log::Information, " %s: Policies are stale, updating...", __func__);
        // Refresh the data from the SAC
        if (!getPoliciesFromSAC(error))
        {
            logger->printf(Log::Error, " %s: getPoliciesFromSAC failed, next policy refresh attempt after: %d", __func__, refreshTime_);
            if (error.size())
            {
                logger->printf(Log::Error, " %s: getPoliciesFromSAC failed with error: %s", __func__, error.c_str());
            }
        }
    }
    logger->printf(Log::Debug, " %s: Searching for a policy match, policies size: %d", __func__, policies_.size());
    // Now search through the policies (will be in priority order) for a match
    for (POLICYMAP::const_iterator i = policies_.begin(); i != policies_.end(); ++i)
    {
        if (i->second.isAMatch(domain, flow, url, method))
        {
            p = new Policy(i->second);
            if (i->second.operation_ == ENCRYPT)
            {
                logger->printf(Log::Information, " %s: Found a policy to Encrypt data", __func__);
            }
            else if (i->second.operation_ == DECRYPT)
            {
                logger->printf(Log::Information, " %s: Found a policy to Decrypt data", __func__);
            }
            break;
        }
    }
#if defined(USETHREADING)
    pthread_mutex_unlock(&mutex_);
#endif // #if defined(USETHREADING)

    return (const Policy *)p;
}

// Need to see (for the currently intercepted data) if there are any policies that need to be applied to it.
// This is done by searching through the policies for a match (based on the domain, the direction, the
// destination url and the method if relevant).  The first match will be used and as the policies are in priority
// order, it will be the highest priority match.
bool PolicyStore::findAPolicyMatch(const std::string& domain, DirectionType flow, MethodType method, const std::string& url, OpType& operation,
    std::string& name, std::string& payloadType, std::string& cryptionPath, std::string& policyID, std::string& error)
{
#if defined(USETHREADING)
    pthread_mutex_lock(&mutex_);
#endif // #if defined(USETHREADING)

    bool result = true;
    Log *logger = Log::getInstance();

    // Check each time that the policy data has not gone stale
    if (isStale())
    {
        logger->printf(Log::Information, " %s: Policies are stale, updating...", __func__);
        // Refresh the data from the SAC
        result = getPoliciesFromSAC(error);
    }
    //
    logger->printf(Log::Debug, " %s: Searching for a policy match, policies size: %d", __func__, policies_.size());
    // Now search through the policies (will be in priority order) for a match
    for (POLICYMAP::const_iterator i = policies_.begin(); i != policies_.end(); ++i)
    {
        if (i->second.isAMatch(domain, flow, url, method))
        {
            name = i->second.name_;
            policyID = i->second.id_;
            payloadType = i->second.payloadType_;
            cryptionPath = i->second.cryptionPath_;
            operation = i->second.operation_;
            if (operation == ENCRYPT)
            {
                logger->printf(Log::Information, " %s: Found a policy to Encrypt alwaysOn data", __func__);
            }
            else if (operation == DECRYPT)
            {
                logger->printf(Log::Information, " %s: Found a policy to Decrypt alwaysOn data", __func__);
            }
            break;
        }
    }
#if defined(USETHREADING)
    pthread_mutex_unlock(&mutex_);
#endif // #if defined(USETHREADING)

    return result;
}

bool PolicyStore::getPropertiesFromPolicy(std::string domain, std::map<std::string, std::string> *mapProps, OpType& operation, std::string& name,
    std::string& policyID, std::string& error, bool &policyUpdateFailed)
{
#if defined(USETHREADING)
    pthread_mutex_lock(&mutex_);
#endif // #if defined(USETHREADING)

    Log *logger = Log::getInstance();

    policyUpdateFailed = false;
    // Check each time that the policy data has not gone stale
    if (isStale())
    {
        logger->printf(Log::Information, " %s: Policies are stale, updating...", __func__);

        // Refresh the data from the SAC
        if (!getPoliciesFromSAC(error))
        {
            logger->printf(Log::Error, " %s: getPoliciesFromSAC failed, next policy refresh attempt after: %d", __func__, refreshTime_);
            if (error.size())
            {
                logger->printf(Log::Error, " %s: getPoliciesFromSAC failed with error: %s", __func__, error.c_str());
            }
            policyUpdateFailed = true;
        }
    }
    logger->printf(Log::Debug, " %s: Searching for a policy match, policies_ size: %d", __func__, policies_.size());
    // Now search through the policies (will be in priority order) for a match
    for (POLICYMAP::const_iterator i = policies_.begin(); i != policies_.end(); ++i)
    {
        if (i->second.isAlwaysOnMatch(domain))
        {
            name = i->second.name_;
            policyID = i->second.id_;
            operation = i->second.operation_;

            std::string cryptionPath = i->second.cryptionPath_;

            logger->printf(Log::Information, " %s: Thing Property Names: %s", __func__, cryptionPath.c_str());
            // Extract the first path from the ';' delimited list of paths
            if ((cryptionPath.size() > 0) && (operation == ENCRYPT))
            {
                std::string token;
                std::istringstream iss(cryptionPath);

                while (std::getline(iss, token, ';'))
                {
                    //logger.printf(Log::Debug, " %s: Token: %s", __func__, token.c_str());
                    //mapProps->insert(std::make_pair<std::string, std::string>(token, policyID));
                    (*mapProps)[token] = policyID;
                }
                logger->printf(Log::Debug, " %s: Found a policy to Encrypt", __func__);
            }
        }
    }
#if defined(USETHREADING)
    pthread_mutex_unlock(&mutex_);
#endif // #if defined(USETHREADING)

    return true;
}

std::string PolicyStore::stripQuotes(const std::string& data) const
{
    return data.substr(1, data.length() - 2);
}

bool PolicyStore::processJSONPolicies(const rapidjson::Value& jsonPolicies, std::string& error)
{
#if defined(USETHREADING)
    pthread_mutex_lock(&mutex_);
#endif // #if defined(USETHREADING)

    Log *logger = Log::getInstance();

    //logger->printf(Log::Debug, " Enter %s", __func__);
    policies_.clear();
    for (rapidjson::Value::ConstValueIterator itr = jsonPolicies.Begin(); itr != jsonPolicies.End(); ++itr)
    {
        const rapidjson::Value& jsonPolicy = (*itr);

        if (!processPolicy(jsonPolicy, error))
        {
            logger->printf(Log::Error, " %s: Process policy failed with error: %s", __func__, error.c_str());
        }
    }
    logger->printf(Log::Debug, " %s: Policies size: %d ", __func__, policies_.size());
    if (policies_.empty())
    {
        logger->printf(Log::Warning, " %s: No valid crypto policies returned from API", __func__);
    }
    // Got all policies. Reset cache timers now
    reset();

    std::ostringstream oss;

    dumpToStream(oss);
#if defined(USETHREADING)
    pthread_mutex_unlock(&mutex_);
#endif // #if defined(USETHREADING)

    return true;
}
//policyCryptoOperation

bool PolicyStore::processPolicy(const rapidjson::Value& jsonPolicy, std::string&  error)
{
    std::string operationStr;
    //char arrayString[200];
    bool retVal = false;
    OpType operation = NOTHING;
    Log *logger = Log::getInstance();
    // JSON writer
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

    jsonPolicy.Accept(writer);

    std::string jsonStr = buffer.GetString();

    logger->printf(Log::Debug, " %s:%d: input: %s", __func__, __LINE__, jsonStr.c_str());
    logger->printf(Log::Information, " Entering %s", __func__);
    if (jsonPolicy.HasMember(JSON_POLICYCRYPTOOPERATION) && !jsonPolicy[JSON_POLICYCRYPTOOPERATION].IsNull())
    {
        operationStr = jsonPolicy[JSON_POLICYCRYPTOOPERATION].GetString();
        if (operationStr == CRYPTO_OP_ENCRYPT)
        {
            operation = ENCRYPT;
        }
        else
        {
            operation = DECRYPT;
        }
    }
    if (operationStr.empty())
    {
        logger->printf(Log::Critical, " %s: No crypto operation returned from API (was expected)", __func__);
        error.assign("No crypto operation returned from API (was expected).");

        return false;
    }
    logger->printf(Log::Information, " %s: operationStr is: %s", __func__, operationStr.c_str());

    std::string id;
    std::string name;
    std::string domain;

    if (jsonPolicy.HasMember(JSON_ID) && !jsonPolicy[JSON_ID].IsNull())
    {
        id = jsonPolicy[JSON_ID].GetString();
    }
    if (id.empty())
    {
        logger->printf(Log::Critical, " %s: No id returned from API (was expected)", __func__);
        error.assign("No id returned from API (was expected).");

        return false;
    }
    if (jsonPolicy.HasMember(JSON_NAME) && !jsonPolicy[JSON_NAME].IsNull())
    {
        name = jsonPolicy[JSON_NAME].GetString();
    }
    else
    {
        logger->printf(Log::Critical, " %s: No name returned from API (was expected)", __func__);
        error.assign("No name returned from API (was expected).");

        return false;
    }
    if (jsonPolicy.HasMember(JSON_DOMAIN) && !jsonPolicy[JSON_DOMAIN].IsNull())
    {
        domain = jsonPolicy[JSON_DOMAIN].GetString();
    }
    else
    {
        logger->printf(Log::Critical, " %s: No domain returned from API (was expected)", __func__);
        error.assign("No domain returned from API (was expected).");

        return false;
    }

    std::string urlPattern,cryptionPath,payloadType = "PLAIN";
    DirectionType direction = BOTH;
    MethodType method = NA;

    if (protocol_ != PROTO_ALWAYSON)
    {
        // Protocol is not "alwayson"
        logger->printf(Log::Warning, " %s: In processPolicy don't come here for alwaysOn", __func__);
        if (jsonPolicy.HasMember(JSON_URLPATTERN))
        {
            const rapidjson::Value& urlPatternJsonVal = jsonPolicy[JSON_URLPATTERN];

            if (!urlPatternJsonVal.IsNull())
            {
                urlPattern = urlPatternJsonVal.GetString();
            }
        }
        if (urlPattern.empty())
        {
            logger->printf(Log::Critical, " %s: No URL pattern returned from API (was expected)", __func__);
            error.assign("No URL pattern returned from API (was expected).");

            return retVal;
        }
        if (jsonPolicy.HasMember(JSON_POLICYDATADIRECTION))
        {
            const rapidjson::Value& dataDirVal = jsonPolicy[JSON_POLICYDATADIRECTION];

            if (!dataDirVal.IsNull())
            {
                std::string directionStr = dataDirVal.GetString();

                if (directionStr == DATADIR_C2S)
                {
                    direction = C2S;
                }
                else if(directionStr == DATADIR_S2C)
                {
                    direction = S2C;
                }
                else
                {
                    // == "BOTH"
                    direction = BOTH;
                }
            }
        }
        else
        {
            logger->printf(Log::Critical, " %s: No direction returned from API (was expected)", __func__);
            error.assign("No direction returned from API (was expected).");

            return false;
        }
        if (jsonPolicy.HasMember(JSON_POLICYMETHODTYPE))
        {
            const rapidjson::Value& methodTypeVal = jsonPolicy[JSON_POLICYMETHODTYPE];

            if (!methodTypeVal.IsNull())
            {
                std::string gwMethod = methodTypeVal.GetString();

                if (gwMethod == METHOD_POST)
                {
                    method = POST;
                }
                else if (gwMethod == METHOD_GET)
                {
                    method = GET;
                }
                else
                {
                    method = NA;
                }
            }
        }
        else
        {
            logger->printf(Log::Critical, " %s: No method returned from API (was expected)", __func__);
            error.assign("No method returned from API (was expected).");

            return false;
        }
        if (jsonPolicy.HasMember(JSON_POLICYPAYLOADTYPE))
        {
            const rapidjson::Value& payloadTypeVal = jsonPolicy[JSON_POLICYPAYLOADTYPE];

            if (!payloadTypeVal.IsNull())
            {
                payloadType = payloadTypeVal.GetString();
            }
        }
        if (payloadType.empty())
        {
            logger->printf(Log::Critical, " %s: No payload type returned from API (was expected)", __func__);
            error.assign("No payload type returned from API (was expected).");

            return false;
        }
        if (jsonPolicy.HasMember(JSON_CRYPTIONPATH))
        {
            const rapidjson::Value& cryptionPathVal = jsonPolicy[JSON_CRYPTIONPATH];

            if (!cryptionPathVal.IsNull())
            {
                cryptionPath = cryptionPathVal.GetString();
            }
        }
        if (cryptionPath.empty())
        {
            logger->printf(Log::Critical, " %s: No cryption path  returned from API (was expected)", __func__);
            error.assign("No cryption path returned from API (was expected).");

            return false;
        }
    } // end of (!alwayson)
    // Get property names for alwaysOn
    if ((protocol_ == PROTO_ALWAYSON))
    {
        if (jsonPolicy.HasMember(JSON_CRYPTIONPATH))
        {
            const rapidjson::Value& cryptionPathVal = jsonPolicy[JSON_CRYPTIONPATH];

            if (!cryptionPathVal.IsNull())
            {
                cryptionPath = cryptionPathVal.GetString();
            }
        }
        if (cryptionPath.empty())
        {
            logger->printf(Log::Critical, " %s: No property names names were returned from API (was expected)", __func__);
            error.assign("No property names names were returned from API (was expected).");

            return false;
        }
    }
    if (operation == ENCRYPT)
    {
        if (jsonPolicy.HasMember(JSON_CRYPTOKEYROTATIONPOLICY) && !jsonPolicy[JSON_CRYPTOKEYROTATIONPOLICY].IsNull())
        {
            std::string ckrT;
            int64_t ckrSchd = 0;
            int64_t ckrUpd = 0;
            int64_t ckrRtry = 0;
            const rapidjson::Value& keyRotationPolicyVal = jsonPolicy[JSON_CRYPTOKEYROTATIONPOLICY];

            if (keyRotationPolicyVal.HasMember(JSON_ROTATIONPOLICY_T))
            {
                const rapidjson::Value& val = keyRotationPolicyVal[JSON_ROTATIONPOLICY_T];

                ckrT = val.GetString();
            }
            if (keyRotationPolicyVal.HasMember(JSON_ROTATIONPOLICY_SCHEDULE))
            {
                const rapidjson::Value& val = keyRotationPolicyVal[JSON_ROTATIONPOLICY_SCHEDULE];

                ckrSchd = val.GetInt64();
            }
            if (keyRotationPolicyVal.HasMember(JSON_ROTATIONPOLICY_UPDATE))
            {
                const rapidjson::Value& val = keyRotationPolicyVal[JSON_ROTATIONPOLICY_UPDATE];

                ckrUpd = val.GetInt64();
            }
            if (keyRotationPolicyVal.HasMember(JSON_ROTATIONPOLICY_RETRY))
            {
                const rapidjson::Value& val = keyRotationPolicyVal[JSON_ROTATIONPOLICY_RETRY];

                ckrRtry = val.GetInt64();
            }
            policies_.insert(std::make_pair(id, Policy(name, id, operation, domain, direction, urlPattern, payloadType, cryptionPath, method, ckrSchd, ckrUpd, ckrRtry)));
        }
    }
    else
    {
        policies_.insert(std::make_pair(id, Policy(name, id, operation, domain, direction, urlPattern, payloadType, cryptionPath, method)));
    }
    logger->printf(Log::Debug, " %s: policies size: %d", __func__, policies_.size());

    return true;
}

bool PolicyStore::processCryptoPolicies(std::string cryptoPolicies, std::string& error)
{
    rapidjson::Document json;
    Log* logger = Log::getInstance();

    json.Parse<0>(cryptoPolicies.c_str());
    if (json.HasParseError())
    {
        logger->printf(Log::Error, " %s: Bad JSON string %s", __func__, cryptoPolicies.c_str());

        return false;
    }
    logger->printf(Log::Debug, " %s: JSON string %s", __func__, cryptoPolicies.c_str());
    policies_.clear();
    if (json.HasMember(JSON_STATUS_CODE))
    {
        const rapidjson::Value& statusCodeVal = json[JSON_STATUS_CODE];
        int statusCode = statusCodeVal.GetInt();

        if (statusCode != 0)
        {
            if (json.HasMember(JSON_MESSAGE))
            {
                const rapidjson::Value& msgVal = json[JSON_MESSAGE];

                if (!msgVal.IsNull())
                {
                    std::string errorMsg = msgVal.GetString();

                    logger->printf(Log::Error, " %s: %s", __func__, errorMsg.c_str());
                    error.assign(errorMsg);
                }

                return false;
            }
        }
    }

    bool rc = false;

    if (json.HasMember(JSON_MESSAGE))
    {
        const rapidjson::Value& msgVal = json[JSON_MESSAGE];

        if (msgVal.HasMember(JSON_POLICIES))
        {
            const rapidjson::Value& policiesVal = msgVal[JSON_POLICIES];
            unsigned int elementCount = policiesVal.Size();

            // For every policy
            for (unsigned int c = 0; c < elementCount; ++c)
            {
                //char arrayString[200];
                std::string operationStr;
                std::string id;
                std::string name;
                std::string domain;
                OpType operation = NOTHING;
                const rapidjson::Value& policyVal = policiesVal[c];

                if (policyVal.IsNull())
                {
                    logger->printf(Log::Critical, " %s: JSON policy value is NULL, continuing", __func__);
                    continue;
                }
                // Gateway Crypto Operation
                if (policyVal.HasMember(JSON_GATEWAYCRYPTOOPERATION))
                {
                    const rapidjson::Value& gtwyCryptoOprVal = policyVal[JSON_GATEWAYCRYPTOOPERATION];

                    if (!gtwyCryptoOprVal.IsNull())
                    {
                        operationStr = gtwyCryptoOprVal.GetString();
                        if (operationStr == CRYPTO_OP_ENCRYPT)
                        {
                            operation = ENCRYPT;
                        }
                        else
                        {
                            operation = DECRYPT;
                        }
                    }
                }
                if (operationStr.empty())
                {
                    logger->printf(Log::Critical, " %s: No crypto operation returned from API (was expected)", __func__);
                    error.assign("No crypto operation returned from API (was expected).");
                    break;
                }
                // Policy Id
                if (policyVal.HasMember(JSON_ID))
                {
                    const rapidjson::Value& idVal = policyVal[JSON_ID];

                    if (!idVal.IsNull())
                    {
                        id =  idVal.GetString();
                    }
                }
                if (id.empty())
                {
                    logger->printf(Log::Critical, " %s: No id returned from API (was expected)", __func__);
                    error.assign("No id returned from API (was expected).");
                    break;
                }
                // Policy Name
                if (policyVal.HasMember(JSON_NAME))
                {
                    const rapidjson::Value& nameVal = policyVal[JSON_NAME];

                    if (!nameVal.IsNull())
                    {
                        name = nameVal.GetString();
                    }
                }
                if (name.empty())
                {
                    logger->printf(Log::Critical, " %s: No name returned from API (was expected)", __func__);
                    error.assign("No name returned from API (was expected).");
                    break;
                }
                // Policy Domain
                if (policyVal.HasMember(JSON_DOMAIN))
                {
                    const rapidjson::Value& domainVal = policyVal[JSON_DOMAIN];

                    if (!domainVal.IsNull())
                    {
                        domain = domainVal.GetString();
                    }
                }
                if (domain.empty())
                {
                    logger->printf(Log::Critical, " %s: No domain returned from API (was expected)", __func__);
                    error.assign("No domain returned from API (was expected).");
                    break;
                }

                std::string urlPattern;
                std::string cryptionPath;
                std::string payloadType = "PLAIN";
                DirectionType direction = BOTH;
                MethodType method = NA;

                if (protocol_ != PROTO_ALWAYSON)
                {
                    // AlwaysOn Protocol
                    // URL Pattern
                    if (policyVal.HasMember(JSON_URLPATTERN))
                    {
                        const rapidjson::Value& urlPatternVal = policyVal[JSON_URLPATTERN];

                        if (!urlPatternVal.IsNull())
                        {
                            urlPattern = urlPatternVal.GetString();
                        }
                    }
                    if (urlPattern.empty())
                    {
                        logger->printf(Log::Critical, " %s: No URL pattern returned from API (was expected)", __func__);
                        error.assign("No URL pattern returned from API (was expected).");
                        break;
                    }
                    // Gateway Data Direction
                    if (policyVal.HasMember(JSON_GATEWAYDATADIRECTION))
                    {
                        const rapidjson::Value& gtwyDataDirVal = policyVal[JSON_GATEWAYDATADIRECTION];

                        if (!gtwyDataDirVal.IsNull())
                        {
                            std::string directionStr = gtwyDataDirVal.GetString();

                            if (directionStr == DATADIR_C2S)
                            {
                                direction = C2S;
                            }
                            else if (directionStr == DATADIR_S2C)
                            {
                                direction = S2C;
                            }
                            else
                            {
                                // == "BOTH"
                                direction = BOTH;
                            }
                        }
                    }
                    else
                    {
                        logger->printf(Log::Critical, " %s: No direction returned from API (was expected)", __func__);
                        error.assign("No direction returned from API (was expected).");
                        break;
                    }

                    bool hasMethod = false;

                    // Gateway Method Type
                    if (policyVal.HasMember(JSON_GATEWAYMETHODTYPE))
                    {
                        const rapidjson::Value& gtwyMethodTypeVal = policyVal[JSON_GATEWAYMETHODTYPE];

                        if (!gtwyMethodTypeVal.IsNull())
                        {
                            std::string gwMethod = gtwyMethodTypeVal.GetString();

                            if (gwMethod == METHOD_POST)
                            {
                                method = POST;
                            }
                            else if (gwMethod == METHOD_GET)
                            {
                                method = GET;
                            }
                            else
                            {
                                method = NA;
                            }
                            hasMethod = true;
                        }
                    }
                    if (!hasMethod)
                    {
                        logger->printf(Log::Critical, " %s: No method returned from API (was expected)", __func__);
                        error.assign("No method returned from API (was expected).");
                        break;
                    }
                    // Payload Type
                    if (policyVal.HasMember(JSON_PAYLOADTYPE))
                    {
                        const rapidjson::Value& payloadTypeVal = policyVal[JSON_PAYLOADTYPE];

                        if (!payloadTypeVal.IsNull())
                        {
                            payloadType = payloadTypeVal.GetString();
                        }
                    }
                    if (payloadType.empty())
                    {
                        logger->printf(Log::Critical, " %s: No payload type returned from API (was expected)", __func__);
                        error.assign("No  payload type returned from API (was expected).");
                        break;
                    }
                    // Cryption Path
                    if (policyVal.HasMember(JSON_CRYPTIONPATH))
                    {
                        const rapidjson::Value& cryptionPathVal = policyVal[JSON_CRYPTIONPATH];

                        if (!cryptionPathVal.IsNull())
                        {
                            cryptionPath = cryptionPathVal.GetString();
                        }
                    }
                    if (cryptionPath.empty())
                    {
                        logger->printf(Log::Critical, " %s: No cryption path returned from API (was expected)", __func__);
                        error.assign("No cryption path returned from API (was expected).");
                        break;
                    }
                }
                // Get property names for alwaysOn
                if ((protocol_ == PROTO_ALWAYSON) && policyVal.HasMember(JSON_PROPERTYNAMES))
                {
                    const rapidjson::Value& propNamesVal = policyVal[JSON_PROPERTYNAMES];

                    if (!propNamesVal.IsNull())
                    {
                        cryptionPath = propNamesVal.GetString();
                    }
                    if (cryptionPath.empty())
                    {
                        logger->printf(Log::Critical, " %s: No property names names were returned from API (was expected)", __func__);
                        error.assign("No property names names were returned from API (was expected).");
                        break;
                    }
                }
                if (operation == ENCRYPT)
                {
                    // Encryption operation requires Crypto Key Rotation Policy
                    // Crypto Key Rotation Policy
                    if (policyVal.HasMember(JSON_CRYPTOKEYROTATIONPOLICY))
                    {
                        const rapidjson::Value& keyRotationPolicyVal = policyVal[JSON_CRYPTOKEYROTATIONPOLICY];

                        if (!keyRotationPolicyVal.IsNull())
                        {
                            std::string ckrT;
                            int64_t ckrSchd = 0;
                            int64_t ckrUpd = 0;
                            int64_t ckrRtry = 0;

                            if (keyRotationPolicyVal.HasMember(JSON_ROTATIONPOLICY_T))
                            {
                                const rapidjson::Value& val = keyRotationPolicyVal[JSON_ROTATIONPOLICY_T];

                                ckrT = val.GetString();
                            }
                            if (keyRotationPolicyVal.HasMember(JSON_ROTATIONPOLICY_SCHEDULE))
                            {
                                const rapidjson::Value& val = keyRotationPolicyVal[JSON_ROTATIONPOLICY_SCHEDULE];

                                ckrSchd = val.GetInt64();
                            }
                            if (keyRotationPolicyVal.HasMember(JSON_ROTATIONPOLICY_UPDATE))
                            {
                                const rapidjson::Value& val = keyRotationPolicyVal[JSON_ROTATIONPOLICY_UPDATE];

                                ckrUpd = val.GetInt64();
                            }
                            if (keyRotationPolicyVal.HasMember(JSON_ROTATIONPOLICY_RETRY))
                            {
                                const rapidjson::Value& val = keyRotationPolicyVal[JSON_ROTATIONPOLICY_RETRY];

                                ckrRtry = val.GetInt64();
                            }
                            policies_.insert(std::make_pair(id, Policy(name, id, operation, domain, direction, urlPattern, payloadType, cryptionPath, method, ckrSchd, ckrUpd, ckrRtry)));
                        }
                        else
                        {
                            logger->printf(Log::Error, " %s: Key Rotation Policy not found", __func__);
                            policies_.insert(std::make_pair(id, Policy(name, id, operation, domain, direction, urlPattern, payloadType, cryptionPath, method)));
                        }
                    }
                    else
                    {
                        logger->printf(Log::Error, " %s: Key Rotation Policy not found", __func__);
                        policies_.insert(std::make_pair(id, Policy(name, id, operation, domain, direction, urlPattern, payloadType, cryptionPath, method)));
                    }
                }
                else
                {
                    // Decryption operation
                    policies_.insert(std::make_pair(id, Policy(name, id, operation, domain, direction, urlPattern, payloadType, cryptionPath, method)));
                }
                rc = true;
            } //end of for loop
            logger->printf(Log::Debug, " %s: policies size: %d", __func__, policies_.size());
            if (policies_.empty())
            {
                logger->printf(Log::Warning, " %s: No valid crypto policies returned from API", __func__);
            }
        }
        else
        {
            if (msgVal.HasMember(JSON_ERRORMESSAGE))
            {
                const rapidjson::Value& errMsgVal = msgVal[JSON_ERRORMESSAGE];

                if (!errMsgVal.IsNull())
                {
                    std::string errorMsg = errMsgVal.GetString();

                    error.assign(errorMsg);
                }
            }
        }
    }
    // Finally reset the timestamp
    logger->printf(Log::Debug, " %s: Reset the timestamp", __func__);
    reset();

    return rc;
}

/*
  Make a call to the SAC API to get all the policies for this device/protocol then cache them up.
  If curl request to get policy update fails then update refresh time with value in "If Update Check Fails, Retry Every " from KRP
*/
bool PolicyStore::getPoliciesFromSAC(std::string& error)
{
    bool rc = false;
    Log *logger = Log::getInstance();

    logger->printf(Log::Debug, " %s: protocol: %s", __func__, protocol_.c_str());
    // Sanity check
    if ((protocol_ != PROTO_MQTT) && (protocol_ != PROTO_HTTP) && (protocol_ != PROTO_ALWAYSON))
    {
        error = "Unknown protocol (" + protocol_ + ")";

        return rc;
    }

    static const std::string DAUser = config.lookup(CFG_DAUSERID);
    static const std::string DAAPIURL = config.lookup(CFG_DAAPIURL);
    static const std::string deviceName = config.lookup(CFG_DEVICENAME);
    std::string keyid;
    std::string key;
    std::string iv;
    DeviceAuthorityBase *daInstance = DeviceAuthority::getInstance();

    if (!daInstance)
    {
      error = "DeviceAuthority object was not initialized";

      return false;
    }

    DAHttpClient httpClientObj(daInstance->userAgentString());
    std::string daJSON = daInstance->identifyAndAuthorise(keyid, key, iv, error, &httpClientObj);

    if (daJSON.empty())
    {
        logger->printf(Log::Error, " %s: Failed to authenticate and obtain policies from SAC, updating policy refresh time with retry value from KRP", __func__);
        logger->printf(Log::Debug, " %s: Updating policy refreshTime to %d", __func__, refreshRetryTime_);
        refreshTime_ = refreshRetryTime_;

        return false;
    }
    //logger->printf(Log::Debug, "KeyID is: %s", keyid.c_str());
    //logger->printf(Log::Debug, "Key is: %s", key.c_str());
    //logger->printf(Log::Debug, "IV is: %s", iv.c_str());
    //logger->printf(Log::Debug, "Body is: %s", daJSON.c_str());
    rapidjson::Document json;
    std::string jsonResponse;
    std::string apiurl = DAAPIURL + "/policies/" + protocol_;
    DAErrorCode rcHttpClient = ERR_OK;

    //logger->printf(Log::Debug, " %s:%d: API URL: %s", __func__, __LINE__, apiurl.c_str());
    rcHttpClient = httpClientObj.sendRequest(DAHttp::ReqType::ePOST, apiurl, jsonResponse, daJSON);
    if ((rcHttpClient != ERR_OK) || jsonResponse.empty())
    {
        logger->printf(Log::Error, " %s: Failed to obtain policies from SAC..updating policy refresh time with retry value from KRP", __func__);
        logger->printf(Log::Debug, " %s: Updating policy refreshTime to %d", __func__, refreshRetryTime_);
        refreshTime_ = refreshRetryTime_;

        return false;
    }
    logger->printf(Log::Debug, " %s: Obtained policies from SAC", __func__);

    return processCryptoPolicies(jsonResponse, error);
}

void PolicyStore::dumpToStream(std::ostream& os) const
{
    os << "Policies:" << std::endl;
    for (POLICYMAP::const_iterator i = policies_.begin(); i != policies_.end(); ++i)
    {
        os << i->second << std::endl;
    }
}
