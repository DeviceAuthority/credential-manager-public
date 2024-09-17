/**
 * \file apm_asset_processor_unittest.cpp
 *
 * \brief Unit test asset processor
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

#ifndef APM_ASSET_PROCESSOR_UNITTEST_HPP
#define APM_ASSET_PROCESSOR_UNITTEST_HPP

#include <vector>
#include "gtest/gtest.h"
#include "rapidjson/document.h"
#include "rapidjson/rapidjson.h"
#include "apm_asset_processor.hpp"
#include "account.hpp"
#include "deviceauthority.hpp"
#include "event_manager.hpp"
#include "http_asset_messenger.hpp"
#include "log.hpp"
#include "test_deviceauthority.hpp"
#include "test_event_manager.hpp"
#include "test_http_client.hpp"
#include "tester_helper.hpp"
#include "utils.hpp"

class ApmAssetProcessorTest : public testing::Test
{
    public:
    struct account_info
    {
        const std::string m_name;
        const std::string m_salt;
        const std::string m_hash;

        account_info(const std::string &name, const std::string &salt, const std::string &hash) :
            m_name(name), m_salt(salt), m_hash(hash)
        {

        }
    };

    const std::string m_test_url{ "https://abc.ks.net" };
    TestHttpClient* mp_http_client = nullptr;
    std::unique_ptr<AssetMessenger> mp_asset_messenger;
    TestEventManager* mp_test_manager = nullptr;

    void SetUp() override
    {
        // Use test deviceauthority instance to mock the interface between us and DDKG
        DeviceAuthority::setInstance(new TestDeviceAuthority());

        mp_http_client = new TestHttpClient();
        mp_asset_messenger.reset(new HttpAssetMessenger(m_test_url, mp_http_client));

        mp_test_manager = new TestEventManager();
        EventManager::setInstance(mp_test_manager);
    }

    void TearDown() override
    {
        if (mp_http_client)
        {
            delete mp_http_client;
            mp_http_client = nullptr;
        }

        EventManager::setInstance(nullptr);
    }

    std::string makeApmAssetData(const std::vector<account_info *> &accounts, bool auto_rotate = false, unsigned int polling_rate = 0)
    {
        rapidjson::Document root_document;
        root_document.SetObject();
        rapidjson::Document::AllocatorType& allocator = root_document.GetAllocator();

        root_document.AddMember("autoRotate", auto_rotate, allocator);
        root_document.AddMember("pollingRate", polling_rate, allocator);

        rapidjson::Value accounts_val(rapidjson::kArrayType);
		for (const auto p_account : accounts)
        {
            rapidjson::Value account_val(rapidjson::kObjectType);
            account_val.AddMember("account", rapidjson::Value(p_account->m_name.c_str(), allocator).Move(), allocator);
            account_val.AddMember("salt", rapidjson::Value(p_account->m_salt.c_str(), allocator).Move(), allocator);
            account_val.AddMember("hash", rapidjson::Value(p_account->m_hash.c_str(), allocator).Move(), allocator);
            accounts_val.PushBack(account_val.Move(), allocator);
        }

        root_document.AddMember("apmPasswords", accounts_val, allocator);

        rapidjson::StringBuffer strbuf;
        rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
        root_document.Accept(writer);

        return std::string(strbuf.GetString());
    }
};

TEST_F(ApmAssetProcessorTest, ProcessSimpleApmRequestWithAutoRotate_ExpectSuccess)
{
    const bool auto_rotate = true;
    const unsigned int polling_rate = 10;

    std::vector<account_info *> test_accounts;
    test_accounts.push_back(new account_info("account1", "salt1", "hash1"));
    test_accounts.push_back(new account_info("account2", "salt2", "hash2"));

    const std::string asset_data_str = makeApmAssetData(test_accounts, auto_rotate, polling_rate);
    for (auto p_account : test_accounts)
    {
        delete p_account;
    }
    test_accounts.clear();

    rapidjson::Document asset_data_json;
    asset_data_json.Parse(asset_data_str.c_str());

    const std::string asset_id = "57a4f09d-8db2-4d1e-833c-9c12749bc199";

    ApmAssetProcessor asset_processor(asset_id, mp_asset_messenger.get());
    unsigned int sleep_val = 0;
    asset_processor.handleAsset(
        asset_data_json,
        utils::toBase64(TesterHelper::getSymmetricKey()),
        utils::toBase64(TesterHelper::getSymmetricIv()),
        "",
        sleep_val);
    // Script runs once and completes
    ASSERT_EQ(polling_rate, sleep_val);

    // Should now be complete and success reported
    ASSERT_TRUE(asset_processor.isComplete());
    ASSERT_TRUE(asset_processor.isSuccess());

    // Check format and contents of receipt is correct
    ASSERT_STREQ(mp_http_client->getLastRequestUrl().c_str(), std::string(m_test_url + "/apm/acknowledgement").c_str());
    ASSERT_FALSE(mp_http_client->getLastRequestJson().empty());

    rapidjson::Document json;
    json.Parse(mp_http_client->getLastRequestJson().c_str());

    ASSERT_TRUE(json.HasMember("passwordChangeStatus"));
    ASSERT_TRUE(json["passwordChangeStatus"].HasMember("assetId"));
    ASSERT_STREQ(json["passwordChangeStatus"]["assetId"].GetString(), asset_id.c_str());
    ASSERT_TRUE(json["passwordChangeStatus"].HasMember("status"));
    ASSERT_TRUE(json["passwordChangeStatus"]["status"].GetBool());

    // Verify APM notifications were raised - expect 2 as each account is a separate set of notifications
    ASSERT_EQ(2, mp_test_manager->getApmReceivedCount());
    ASSERT_EQ(0, mp_test_manager->getApmSuccessCount());
    ASSERT_EQ(2, mp_test_manager->getApmFailureCount());
}

TEST_F(ApmAssetProcessorTest, ProcessSimpleApmRequestNoAutoRotate_ExpectSuccess)
{
    const bool auto_rotate = false;
    const unsigned int polling_rate = 10;

    std::vector<account_info *> test_accounts;
    test_accounts.push_back(new account_info("name1", "salt1", "hash1"));
    test_accounts.push_back(new account_info("name2", "salt2", "hash2"));

    const std::string asset_data_str = makeApmAssetData(test_accounts, auto_rotate, polling_rate);
    for (auto p_account : test_accounts)
    {
        delete p_account;
    }
    test_accounts.clear();

    rapidjson::Document asset_data_json;
    asset_data_json.Parse(asset_data_str.c_str());

    const std::string asset_id = "57a4f09d-8db2-4d1e-833c-9c12749bc199";

    ApmAssetProcessor asset_processor(asset_id, mp_asset_messenger.get());
    unsigned int sleep_val = 0;
    asset_processor.handleAsset(
        asset_data_json,
        utils::toBase64(TesterHelper::getSymmetricKey()),
        utils::toBase64(TesterHelper::getSymmetricIv()),
        "",
        sleep_val);

    // Script runs once and completes
    const unsigned int expected_polling_rate = 0;
    ASSERT_EQ(expected_polling_rate, sleep_val);

    // Should now be complete and success reported
    ASSERT_TRUE(asset_processor.isComplete());
    ASSERT_TRUE(asset_processor.isSuccess());

    // Verify APM notifications were raised - expect 2 as each account is a separate set of notifications
    ASSERT_EQ(2, mp_test_manager->getApmReceivedCount());
    ASSERT_EQ(0, mp_test_manager->getApmSuccessCount());
    ASSERT_EQ(2, mp_test_manager->getApmFailureCount());
}

#endif // #ifndef APM_ASSET_PROCESSOR_HPP
