/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An implementation of a policy.
 *
 */
#include "log.hpp"
#include "policy.hpp"
#include "regexmatch.h"


/*
 * KeyRotationPolicy
 */

KeyRotationPolicy::KeyRotationPolicy() :
        scheduleInterval_(0), updateInterval_(0), retryInterval_(0)
{
  
}

KeyRotationPolicy::KeyRotationPolicy(const long scheduleInterval,
        const long updateInterval, const long retryInterval) :
        scheduleInterval_(scheduleInterval), updateInterval_(updateInterval), retryInterval_(retryInterval)
{
  
}

KeyRotationPolicy::KeyRotationPolicy(const KeyRotationPolicy& policy)
{
   scheduleInterval_ = policy.scheduleInterval_;
   updateInterval_ = policy.updateInterval_;
   retryInterval_ = policy.retryInterval_;
}

KeyRotationPolicy::~KeyRotationPolicy()
{
  
}

KeyRotationPolicy& KeyRotationPolicy::operator=(KeyRotationPolicy policy)
{
  scheduleInterval_ = policy.scheduleInterval_;
  updateInterval_ = policy.updateInterval_;
  retryInterval_ = policy.retryInterval_;
  return *this;
}

std::ostream& operator<<( std::ostream& os, const KeyRotationPolicy& policy )
{
  os << "Key Rotation Policy: schd: " << policy.scheduleInterval_ << ", upd: " << policy.updateInterval_ << ", rtry: " << policy.retryInterval_;
  return os;
}

/*
 * Policy
 */

Policy::Policy(const std::string& name, const std::string& id, OpType operation,
        const std::string& domain, DirectionType flow, const std::string& pattern,
        const std::string& payloadType, const std::string& cryptionPath, MethodType method,
        int64_t schd, int64_t upd, int64_t rtry)
        : name_(name), id_(id), operation_(operation), domain_(domain), pattern_(pattern),
        flow_(flow), method_(method), payloadType_(payloadType), cryptionPath_(cryptionPath)
{
  krPolicy.scheduleInterval_ = schd;
  krPolicy.updateInterval_ = upd;
  krPolicy.retryInterval_ = rtry;
}

Policy::Policy(const Policy& policy)
    : name_(policy.name_), id_(policy.id_), operation_(policy.operation_), domain_(policy.domain_),
        pattern_(policy.pattern_), flow_(policy.flow_), method_(policy.method_), payloadType_(policy.payloadType_),
        cryptionPath_(policy.cryptionPath_)
{
  krPolicy = policy.krPolicy;
}

Policy::~Policy()
{
}

// Does this policy match the supplied parameters?
bool Policy::isAMatch(const std::string& domain, DirectionType flow, const std::string& url, MethodType method) const
{
  char error[100] = "";
  Log *logger = Log::getInstance();
  logger->printf( Log::Debug, "1 domain:%s method:%d flow:%d pattern:%s", domain_.c_str(),method_,flow_,pattern_.c_str());
  logger->printf( Log::Debug,"2 domain:%s method:%d flow:%d     url:%s", domain.c_str(),method,flow,url.c_str());
  logger->printf( Log::Debug, "Is match?? %d url:%d pattern:%d",matches( url.c_str(), pattern_.c_str(), error, 100 ),url.size(),pattern_.size());
  if ((domain_ == domain) && (method_ == method) && ((flow_ == flow) || (flow_ == BOTH)) && matches(url.c_str(), pattern_.c_str(), error, 100))
  {
    return true;
  }
  return false;
}

bool Policy::isAlwaysOnMatch(const std::string& domain) const
{
   Log::getInstance()->printf(Log::Debug, "%s domain_:%s domain:%s  ", __func__, domain_.c_str(),domain.c_str());
   return (domain_ == domain) ? true : false;
}

std::ostream& operator<<(std::ostream& os, const Policy& policy)
{
    os << "Policy: " << policy.name_ << " to ";
    if (policy.operation_ != NOTHING)
    {
        if (policy.payloadType_ == "PLAIN")
            os << "fully ";
        else if (policy.payloadType_ == "JSON")
            os << "selectively ";
        if (policy.operation_ == ENCRYPT)
            os << "ENCRYPT";
        else // (policy.operation_ == DECRYPT)
            os << "DECRYPT";
    }
    else
        os << "do NOTHING with";
    os << " messages flowing ";
    if (policy.flow_ == C2S)
        os << "from device to server";
    else if (policy.flow_ == S2C)
        os << "from server to device";
    else
        os << "in both directions";
    if (policy.method_ == POST)
        os << " via a POST";
    else if (policy.method_ == GET)
        os << " via a GET";
    if (policy.method_ == NA)
        os << " on topic: ";
    else
        os << " on URL: ";
    os << policy.pattern_;
    return os;
}

