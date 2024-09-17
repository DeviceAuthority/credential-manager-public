/**
 * \file
 *
 * \brief Unit test asset manager
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

#ifndef ASSET_MANAGER_UNITTEST_HPP
#define ASSET_MANAGER_UNITTEST_HPP

#include "gtest/gtest.h"
#include "rapidjson/rapidjson.h"
#include "asset_manager.hpp"
#include "configuration.hpp"
#include "deviceauthority.hpp"
#include "event_manager.hpp"
#include "http_asset_messenger.hpp"
#include "rsa_utils.hpp"
#include "script_asset_processor.hpp"
#include "test_deviceauthority.hpp"
#include "test_event_manager.hpp"
#include "test_http_client.hpp"
#include "tester_helper.hpp"
#include "utils.hpp"

class AssetManagerTest : public testing::Test
{
    public:
    TestEventManager *mp_test_manager = nullptr;

    void SetUp() override
    {
        {
            std::ofstream ofs("/tmp/pubkey");
            ofs << TesterHelper::m_publicKeyStr;
            ofs.close();
        }

        {
            std::ofstream ofs("/tmp/test.conf");
            ofs << "CERTIFICATEPATH = /tmp/pubkey";
            ofs.close();
        }

        // Now do the test
        ASSERT_TRUE(config.parse("/tmp/test.conf"));

        // Use test deviceauthority instance to mock the interface between us and DDKG
        DeviceAuthority::setInstance(new TestDeviceAuthority());

        mp_test_manager = new TestEventManager();
        EventManager::setInstance(mp_test_manager);
    }

    void TearDown() override
    {
        EventManager::setInstance(nullptr);
    }
};

TEST_F(AssetManagerTest, ProcessScriptAssetCheckTidyUpOnceComplete)
{
    const std::string asset_id = "57a4f09d-8db2-4d1e-833c-9c12749bc199";
    const std::string dest_url = "test url";
    const std::string recipe = TesterHelper::makeRecipeAsset(asset_id, "echo \"Hello world\"", "");

    rapidjson::Document json;
    json.Parse(recipe.c_str());
    if (json.HasParseError())
    {
        throw std::runtime_error("Bad recipe JSON:" + recipe);
    }

    TestHttpClient http_client;
    std::unique_ptr<AssetMessenger> p_asset_messenger(new HttpAssetMessenger("test url", &http_client));

    std::unique_ptr<AssetProcessor> p_asset_processor(
        new ScriptAssetProcessor(asset_id, p_asset_messenger.get(), TesterHelper::getRSAPublicKey()));

    AssetManager asset_manager;
    unsigned int sleep_val = 0;
    auto result = asset_manager.processAsset(
        std::move(p_asset_processor),
        json,
        TesterHelper::getSymmetricKey(),
        TesterHelper::getSymmetricIv(),
        "key_id",
        sleep_val);

    // Script is running, requires an update to complete
    ASSERT_EQ(Asset::Status::IN_PROGRESS, result);
    ASSERT_TRUE(asset_manager.isAssetProcessing(asset_id));
    ASSERT_TRUE(http_client.getLastRequestJson().empty()); // no acknowledgement yet
    ASSERT_EQ(1, asset_manager.assetsProcessingCount());

#ifdef _WIN32
    Sleep(1);
#else
    sleep(1);
#endif // #ifdef _WIN32

    // Call update to complete
    asset_manager.update();

    // Should now be complete and success reported
    ASSERT_FALSE(asset_manager.isAssetProcessing(asset_id));
    ASSERT_FALSE(http_client.getLastRequestJson().empty()); // acknowledgement sent
    ASSERT_EQ(0, asset_manager.assetsProcessingCount());

    ASSERT_FALSE(asset_manager.isWaitingForCertificate());

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getSatReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getSatSuccessCount());
    ASSERT_EQ(0, mp_test_manager->getSatFailureCount());
}

#endif // #ifndef ASSET_MANAGER_UNITTEST_HPP
