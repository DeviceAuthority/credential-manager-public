
#if defined(WIN32)
#include <Windows.h>
#include <iostream>
#include <tchar.h>
#include "wincrypt.h"
#include <stdio.h>
#else
#include <pwd.h>
#endif // #if defined(WIN32)
#include <sstream>
#include "account.hpp"
#include "apm_asset_processor.hpp"
#include "event_manager.hpp"
#include "message_factory.hpp"
#include "script_utils.hpp"
#include "utils.hpp"

ApmAssetProcessor::ApmAssetProcessor(const std::string &asset_id, AssetMessenger *p_asset_messenger)
    : AssetProcessor(asset_id, p_asset_messenger)
{
    // do nothing
}

void ApmAssetProcessor::handleAsset(
    const rapidjson::Value &json,
    const std::string &key,
    const std::string &iv,
    const std::string &keyId,
    unsigned int &sleep_value_from_ks)
{
    m_success = processPasswordManagementRequest(json, key, iv, m_error_message, sleep_value_from_ks);
    const std::string json_receipt = MessageFactory::buildPasswordChangeStatusMessage(m_asset_id, m_success, m_error_message);
    mp_asset_messenger->acknowledgeAPMReceipt(json_receipt, m_error_message);

    m_complete = true;
}

void ApmAssetProcessor::onUpdate()
{
}

bool ApmAssetProcessor::processPasswordManagementRequest(const rapidjson::Value &json, const std::string &key, const std::string &iv, std::string &message, unsigned int &sleep_value_from_ks)
{
    Log *p_logger = Log::getInstance();

    // autoRotate
    if (json.HasMember("autoRotate"))
    {
        const rapidjson::Value &auto_rotate_val = json["autoRotate"];
        bool autoRotate = auto_rotate_val.GetBool();

        if (autoRotate && json.HasMember("pollingRate"))
        {
            const rapidjson::Value &polling_rate_val = json["pollingRate"];
            sleep_value_from_ks = polling_rate_val.GetInt();
            p_logger->printf(Log::Debug, " %s pollingRate: %d", __func__, sleep_value_from_ks);
        }
    }

    std::vector<account *> account_info;

    // apmPasswords
    if (json.HasMember("apmPasswords"))
    {
        // Get the number of accounts
        const rapidjson::Value &accounts_val = json["apmPasswords"];
        unsigned int accounts = accounts_val.Size();

        p_logger->printf(Log::Information, " %s Processing APM policy for %d account(s)", __func__, accounts);
        for (unsigned int c = 0; c < accounts; c++)
        {
            std::string name;
            std::string salt;
            std::string hash;
            std::string reason;
            std::string result = account::success;

            const rapidjson::Value &account_val = accounts_val[c];
            if (!account_val.IsNull())
            {
                // Account Name
                if (account_val.HasMember("account"))
                {
                    const rapidjson::Value &account_name_val = account_val["account"];
                    if (!account_name_val.IsNull())
                    {
                        const std::string account_name_str = account_name_val.GetString();
                        p_logger->printf(Log::Information, " %s Account name: %s, len: %d", __func__, account_name_str.c_str(), account_name_str.length());
                        name.append(account_name_str);
                    }
                }
                if (name.empty())
                {
                    result = account::failure;

                    std::ostringstream oss;
                    oss << "Name is missing in account record #" << c;
                    reason = oss.str();
                    p_logger->printf(Log::Error, " %s FATAL! Name info missing..skipping account record #%d", __func__, c);
                }
                else
                {
                    // Salt
                    if (account_val.HasMember("salt"))
                    {
                        const rapidjson::Value &salt_val = account_val["salt"];
                        if (!salt_val.IsNull())
                        {
                            const std::string salt_str = salt_val.GetString();
                            salt.append(salt_str);
                        }
                    }
                    if (salt.empty())
                    {
                        result = account::failure;

                        std::ostringstream oss;
                        oss << "Salt info is missing in account record #" << c;
                        reason = oss.str();
                        p_logger->printf(Log::Error, " %s FATAL! Salt info missing..skipping account record #%d", __func__, c);
                    }
                    else
                    {
                        // Hash
                        if (account_val.HasMember("hash"))
                        {
                            const rapidjson::Value &hash_val = account_val["hash"];
                            if (!hash_val.IsNull())
                            {
                                const std::string hash_str = hash_val.GetString();
                                hash.append(hash_str);
                            }
                        }
                        if (hash.empty())
                        {
                            result = account::failure;

                            std::ostringstream oss;
                            oss << "Hash info is missing in account record #" << c;
                            reason = oss.str();
                            p_logger->printf(Log::Error, " %s FATAL! Hash info missing..skipping account record #%d", __func__, c);
                        }
                    }
                }
            }
            else
            {
                result = account::failure;

                std::ostringstream oss;
                oss << "Account is missing in record #" << c;
                reason = oss.str();
                p_logger->printf(Log::Error, " %s FATAL! Account missing..skipping record #%d", __func__, c);
            }

            account_info.push_back(new account(name, salt, hash, result, reason));
        }

        if (account_info.size())
        {
            return updatePasswords(account_info, key, message);
        }

        // Empty apmPasswords array
        message = MessageFactory::buildApmPasswordsMessage(account_info);
        p_logger->printf(Log::Error, " %s No apmPasswords information received. Nothing to process (apmPasswords array is empty).", __func__);

        return false;
    }
    // Missing apmPasswords array
    message = MessageFactory::buildApmPasswordsMessage(account_info);
    p_logger->printf(Log::Error, " %s No apmPasswords information received. Nothing to process (apmPasswords is not present in json).", __func__);

    return false;
}

bool ApmAssetProcessor::updatePasswords(std::vector<account *> &accounts, const std::string &key, std::string &message)
{
    Log *p_logger = Log::getInstance();

    unsigned int index = 0;
    for (std::vector<account *>::const_iterator itr = accounts.cbegin(); itr != accounts.cend(); itr++)
    {
        index++;

        account *p_account = *(itr);
        if (p_account->getResult() == account::success)
        {
            const std::string account_name = p_account->getName();

            EventManager::getInstance()->notifyAPMReceived(account_name);
#if defined(WIN32)
            std::ostringstream oss;
            p_logger->printf(Log::Error, " %s Changing password NOT SUPPORTED on Windows platform for account: %s", __func__, account_name.c_str());
            oss << "Changing password NOT SUPPORTED on Windows platform for record #" << index;
            updateFailure(p_account, oss.str());
            continue;
#else
            struct passwd *pw = getpwnam(account_name.c_str());
            if (pw == nullptr)
            {
                std::ostringstream oss;
                oss << "Account specified in record #" << index << " does not exist";
                updateFailure(p_account, oss.str());
                continue;
            }
            else
            {
                FILE *pf1 = nullptr;
                std::string command = "";
                command.append("passwd ");
                command.append(account_name);
                p_logger->printf(Log::Debug, " %s Command: %s", __func__, command.c_str());
                pf1 = popen(command.c_str(), "w");
                if (pf1 == nullptr)
                {
                    std::ostringstream oss;
                    p_logger->printf(Log::Error, " %s Changing password failed for account: %s, errno: %d", __func__, account_name.c_str(), errno);
                    oss << "Changing password failed for record #" << index;
                    updateFailure(p_account, oss.str());
                    continue;
                }

                const std::string password = p_account->generatePassword(key);
                bool is_valid_password = p_account->validateHash(password);

                if (is_valid_password)
                {
                    fprintf(pf1, "%s\n", password.c_str());
                    fprintf(pf1, "%s\n", password.c_str());

                    int result = pclose(pf1);

                    if (result)
                    {
                        p_logger->printf(Log::Error, " %s Changing password failed for account: %s, errno: %d", __func__, account_name.c_str(), errno);

                        std::ostringstream oss;
                        oss << "Changing password failed for record #" << index;
                        updateFailure(p_account, oss.str());
                    }
                    else
                    {
                        p_account->setResult(account::success);
                        p_logger->printf(Log::Information, " %s Password changed success for record #%d", __func__, index);
                        EventManager::getInstance()->notifyAPMSuccess(account_name);
                    }
                }
                else
                {
                    p_logger->printf(Log::Error, " %s Password validation failed for account: %s", __func__, account_name.c_str());

                    std::ostringstream oss;
                    oss << "Password validation failed for record #" << index;
                    updateFailure(p_account, oss.str());
                }
            }
#endif // #if defined(WIN32)
        }
    }

    message = MessageFactory::buildApmPasswordsMessage(accounts);

    // Cleanup
    for (std::vector<account *>::iterator itr = accounts.begin(); itr != accounts.end(); itr++)
    {
        account *p_account_obj = *(itr);
        delete p_account_obj;
    }
    accounts.clear();

    return true;
}

void ApmAssetProcessor::updateFailure(account *p_account, const std::string &result)
{
    Log::getInstance()->printf(Log::Error, result.c_str());
    p_account->setResult(account::failure, result);
    EventManager::getInstance()->notifyAPMFailure(result);
}
