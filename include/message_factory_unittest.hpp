/**
 * \file
 *
 * \brief Unit test message factory
 *
 * \author Copyright (c) 2022 by Device Authority Ltd. ALL RIGHTS RESERVED.
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to Device Authority Ltd. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from Device Authority Ltd.
 *
 *
 * \date Oct 10, 2022
 *
 */

#ifndef MESSAGE_FACTORY_UNITTEST_HPP
#define MESSAGE_FACTORY_UNITTEST_HPP

#include "gtest/gtest.h"
#include "message_factory.hpp"

TEST(MessageFactory, GenerateAckMessageSuccess)
{
    const auto expected_json = "{\"assetDeliveryStatus\":{\"assetId\":\"57a4f09d-8db2-4d1e-833c-9c12749bc199\",\"status\":true,\"failureReason\":\"\"}}";
    const std::string result = MessageFactory::buildAcknowledgeMessage("57a4f09d-8db2-4d1e-833c-9c12749bc199", true, "");
    ASSERT_STREQ(expected_json, result.c_str());
}

TEST(MessageFactory, GenerateAckMessageFailure)
{
    const auto expected_json = "{\"assetDeliveryStatus\":{\"assetId\":\"bcdef\",\"status\":false,\"failureReason\":\"failure due to test\"}}";
    const std::string result = MessageFactory::buildAcknowledgeMessage("bcdef", false, "failure due to test");
    ASSERT_STREQ(expected_json, result.c_str());
}

TEST(MessageFactory, GenerateAckMessageNoAssetId)
{
    const auto expected_json = "{\"assetDeliveryStatus\":{}}";
    const std::string result = MessageFactory::buildAcknowledgeMessage("", true, "");
    ASSERT_STREQ(expected_json, result.c_str());
}

TEST(MessageFactory, GenerateDFactorAuthenticationMessageEmptyDeviceKey)
{
    const auto expected_json = "";
    const std::string result = MessageFactory::buildDFactorAuthenticationMessage("", false, "", "", "", "", "");
    ASSERT_STREQ(expected_json, result.c_str());
}

TEST(MessageFactory, GenerateDFactorAuthenticationMessageDeviceKey)
{
    const auto expected_json = "{\"deviceKey\":\"abcdefg-devicekey\"}";
    const std::string result = MessageFactory::buildDFactorAuthenticationMessage(
        "abcdefg-devicekey",
        false,
        "",
        "",
        "",
        "",
        "");
    ASSERT_STREQ(expected_json, result.c_str());
}

TEST(MessageFactory, GenerateDFactorAuthenticationMessageEdge)
{
    const auto expected_json = "{\"userAgent\":\"user_agent\",\"userId\":\"user_id\",\"keyId\":\"key_id\",\"appHash\":\"app_hash\",\"assetId\":\"asset_id\",\"deviceKey\":\"abcdefg_devicekey\"}";
    const std::string result = MessageFactory::buildDFactorAuthenticationMessage(
        "abcdefg_devicekey",
        true,
        "user_agent",
        "user_id",
        "key_id",
        "app_hash",
        "asset_id");
    ASSERT_STREQ(expected_json, result.c_str());
}

TEST(MessageFactory, GenerateDFactorAuthenticationMessageNotEdge)
{
    const auto expected_json = "{\"userId\":\"user_id\",\"keyId\":\"key_id\",\"appHash\":\"app_hash\",\"assetId\":\"asset_id\",\"deviceKey\":\"abcdefg_devicekey\"}";
    const std::string result = MessageFactory::buildDFactorAuthenticationMessage(
        "abcdefg_devicekey",
        false,
        "user_agent",
        "user_id",
        "key_id",
        "app_hash",
        "asset_id");
    ASSERT_STREQ(expected_json, result.c_str());
}

TEST(MessageFactory, GenerateAuthenticationMessage)
{
    const auto expected_json = "{\"dFactorAuthentication\":{\"deviceKey\":\"abcdefg-devicekey\"},\"assetDeliveryStatus\":{\"assetId\":\"abcde\",\"status\":true,\"failureReason\":\"\"}}";

    const std::string dfactor_auth_msg = MessageFactory::buildDFactorAuthenticationMessage("abcdefg-devicekey", false, "", "", "", "", "");
    const std::string ack_msg = MessageFactory::buildAcknowledgeMessage("abcde", true, "");
    const std::string auth_msg = MessageFactory::buildAuthenticationMessage(dfactor_auth_msg, ack_msg);
    ASSERT_STREQ(expected_json, auth_msg.c_str());
}

TEST(MessageFactory, GenerateAuthenticationMessageWithApmAck)
{
    const auto expected_json = "{\"dFactorAuthentication\":{\"deviceKey\":\"abcdefg-devicekey\"},\"passwordChangeStatus\":{\"assetId\":\"abcde\",\"status\":true,\"apmStatus\":{\"apmPasswords\":[]}}}";

    const std::string dfactor_auth_msg = MessageFactory::buildDFactorAuthenticationMessage("abcdefg-devicekey", false, "", "", "", "", "");
    std::vector<account*> accounts{};
    const std::string accounts_status_msg = MessageFactory::buildApmPasswordsMessage(accounts);
    const std::string ack_msg = MessageFactory::buildPasswordChangeStatusMessage("abcde", true, accounts_status_msg);
    const std::string auth_msg = MessageFactory::buildAuthenticationMessage(dfactor_auth_msg, ack_msg);
    ASSERT_STREQ(expected_json, auth_msg.c_str());
}

TEST(MessageFactory, GenerateScriptResultMessage)
{
    const auto expected_json = "{\"device_logs\":{\"type\":\"asset-device-data-codesigning\",\"compression\":\"none\",\"data\":\"eyJkZXZpY2VfaW5mbyI6IiIsImRldmljZV9sb2dzIjpbeyJsaW5lIjoxLCJkZXNjcmlwdGlvbiI6InNjcmlwdCJ9LHsibGluZSI6MiwiZGVzY3JpcHRpb24iOiJvdXRwdXQifSx7ImxpbmUiOjMsImRlc2NyaXB0aW9uIjoiZXhpdCJ9XX0=\"}}";
    const std::string result = MessageFactory::buildScriptResultMessage("asset-device-data-codesigning", false, "script\noutput\nexit");
    ASSERT_STREQ(expected_json, result.c_str());
}

TEST(MessageFactory, GenerateScriptLogOutputJson)
{
    const auto expected_json = "[{\"line\":1,\"description\":\"script\"},{\"line\":2,\"description\":\"output\"},{\"line\":3,\"description\":\"exit\"}]";
    const std::string result = MessageFactory::buildScriptOutputJson("script\noutput\nexit");
    ASSERT_STREQ(expected_json, result.c_str());
}

TEST(MessageFactory, GenerateScriptOutputMessage)
{
    const auto expected_json = "{\"id\":\"script_name\",\"data\":\"script output data\"}";
    const std::string result = MessageFactory::buildScriptOutputMessage("script_name", "script output data");
    ASSERT_STREQ(expected_json, result.c_str());
}

TEST(MessageFactory, GeneratePasswordChangeStatusMessage)
{
    const auto expected_json = "{\"passwordChangeStatus\":{\"assetId\":\"asset_id\",\"status\":true,\"apmStatus\":\"Password changed\"}}";
    const std::string result = MessageFactory::buildPasswordChangeStatusMessage("asset_id", true, "Password changed");
    ASSERT_STREQ(expected_json, result.c_str());
}

TEST(MessageFactory, GenerateApmPasswordsMessageEmpty)
{
    const auto expected_json = "{\"apmPasswords\":[]}";
    std::vector<account*> accounts{};
    const std::string result = MessageFactory::buildApmPasswordsMessage(accounts);
    ASSERT_STREQ(expected_json, result.c_str());
}

TEST(MessageFactory, GenerateApmPasswordsMessageNonEmpty)
{
    const auto expected_json = "{\"apmPasswords\":[{\"account\":\"acc1\",\"result\":\"result1\",\"reason\":\"reason1\"},{\"account\":\"acc2\",\"result\":\"result2\",\"reason\":\"reason2\"}]}";
    std::vector<account*> accounts{};
    accounts.push_back(new account("acc1", "salt1", "hash1", "result1", "reason1"));
    accounts.push_back(new account("acc2", "salt2", "hash2", "result2", "reason2"));
    const std::string result = MessageFactory::buildApmPasswordsMessage(accounts);
    for (auto p_account : accounts)
    {
        delete p_account;
    }
    ASSERT_STREQ(expected_json, result.c_str());
}

#endif // #ifndef MESSAGE_FACTORY_UNITTEST_HPP
