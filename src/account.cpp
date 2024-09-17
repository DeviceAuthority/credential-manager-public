/*
 * Copyright (c) 2016 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Management class for accounts
 */
#include <sstream>
#include "account.hpp"
#include "base64.h"
#include "log.hpp"
#include "utils.hpp"

const std::string account::success = "SUCCESS";
const std::string account::failure = "FAILED";

account::account(const std::string &name, const std::string &salt, const std::string &hash, const std::string &result, const std::string &reason)
    : m_name(name), m_salt(salt), m_validation_hash(hash), m_result(result), m_reason(reason)
{
}

account::~account()
{
}

const std::string account::sha256AndEncode(const std::string& input) const
{
    std::string hash_str;
    utils::sha256AndEncode(input, /*isFile*/false, /*base64 out*/true, hash_str );
    return hash_str;
}

bool account::validateHash(const std::string& password) const
{
    Log::getInstance()->printf(Log::Debug, " %s m_validation_hash: %s, size: %d", __func__, m_validation_hash.c_str(), m_validation_hash.size());

    std::string str_to_hash = password + m_name;
    std::string generated_hash = sha256AndEncode(str_to_hash);

    Log::getInstance()->printf(Log::Debug, " %s generatedHash: %s, size: %d", __func__, generated_hash.c_str(), generated_hash.size());

    return (m_validation_hash == generated_hash);
}

const std::string account::generatePassword(const std::string& key) const
{
    //Log::getInstance()->printf(Log::Information, " %s Generating password for: %s, with salt: %s", m_name.c_str(), m_salt.c_str());
    std::string key_str = key;
    std::string str_to_hash = key_str.append(m_salt);
    std::string hashed_pwd = sha256AndEncode(str_to_hash);

    Log::getInstance()->printf(Log::Debug, " %s Generated base64Encode hashedPwd: %s, for account: %s", __func__, hashed_pwd.c_str(), getName().c_str());

    return hashed_pwd;
}

/*
void accountInfo::display()
{
    Log::getInstance()->printf(Log::Information, " %s Account :%s", __func__, m_name.c_str());
    Log::getInstance()->printf(Log::Information, " %s Salt :%s", __func__, m_salt.c_str());
    Log::getInstance()->printf(Log::Information, " %s Hash :%s", __func__, m_validation_hash.c_str());
    Log::getInstance()->printf(Log::Information, " %s Result :%s", __func__, m_result.c_str());
    Log::getInstance()->printf(Log::Information, " %s Reason :%s", __func__, m_reason.c_str());
}
*/
