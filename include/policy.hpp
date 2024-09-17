#ifndef POLICY_HPP
#define POLICY_HPP

/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * An implementation of a policy.
 *
 */

#include <stdint.h>
#include <string>
#include "optype.h"
#include <ostream>

//namespace cryptosoft
//{
    struct KeyRotationPolicy
    {
        KeyRotationPolicy();
        KeyRotationPolicy(const long scheduleInterval, const long updateInterval, const long retryInterval);
        KeyRotationPolicy(const KeyRotationPolicy& policy);
        ~KeyRotationPolicy();

        KeyRotationPolicy& operator=(KeyRotationPolicy policy);
        friend std::ostream& operator<<(std::ostream& os, const KeyRotationPolicy& policy);

        std::string t;
        uint64_t scheduleInterval_;
        uint64_t updateInterval_;
        uint64_t retryInterval_;
    };

    struct Policy
    {
        Policy(const std::string& name, const std::string& id, OpType operation, const std::string& domain, DirectionType flow, const std::string& pattern, const std::string& payloadType, const std::string& cryptionPath, MethodType method = NA, int64_t schd = 0, int64_t upd = 0, int64_t rtry = 0);
        Policy(const Policy& policy);
        ~Policy();

        // Does this policy match the supplied parameters?
        bool isAMatch(const std::string& domain, DirectionType flow, const std::string& url, MethodType method) const;

        //Less params to match for alwaysOm
        bool isAlwaysOnMatch(const std::string& domain) const;
        
        friend std::ostream& operator<<(std::ostream& os, const Policy& policy);

        std::string name_;
        std::string id_;
        OpType operation_;
        std::string domain_;
        std::string pattern_;
        DirectionType flow_;
        MethodType method_;
        std::string payloadType_;
        std::string cryptionPath_;
        KeyRotationPolicy krPolicy;
    };
//};

#endif
