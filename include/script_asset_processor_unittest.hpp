/**
 * \file script_asset_processor_unittest.cpp
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

#ifndef SCRIPT_ASSET_PROCESSOR_UNITTEST_HPP
#define SCRIPT_ASSET_PROCESSOR_UNITTEST_HPP

#include <stdlib.h>
#include <string>
#include "gtest/gtest.h"
#include "base64.h"
#include "configuration.hpp"
#include "dacryptor.hpp"
#include "deviceauthority.hpp"
#include "event_manager.hpp"
#include "http_asset_messenger.hpp"
#include "log.hpp"
#include "sat_asset_processor.hpp"
#include "script_asset_processor.hpp"
#include "test_deviceauthority.hpp"
#include "test_event_manager.hpp"
#include "test_http_client.hpp"
#include "tester_helper.hpp"
#include "json_utils.hpp"
#include "utils.hpp"

class ScriptAssetProcessorTest : public testing::Test
{
    public:
    const std::string m_test_url{"https://abc.ks.net"};
    std::unique_ptr<TestHttpClient> mp_http_client = nullptr;
    std::unique_ptr<AssetMessenger> mp_asset_messenger = nullptr;
    RSAPtr mp_public_key;
    TestEventManager *mp_test_manager = nullptr;

    void SetUp() override
    {
        // Use test deviceauthority instance to mock the interface between us and DDKG
        DeviceAuthority::setInstance(new TestDeviceAuthority());

        mp_public_key = TesterHelper::getRSAPublicKey();
        mp_http_client.reset(new TestHttpClient());
        mp_asset_messenger.reset(new HttpAssetMessenger(m_test_url, mp_http_client.get()));

        config.parse("credentialmanager.conf");

        mp_test_manager = new TestEventManager();
        EventManager::setInstance(mp_test_manager);
    }

    void TearDown() override
    {
        EventManager::setInstance(nullptr);
    }
};

TEST_F(ScriptAssetProcessorTest, ProcessSimpleScript_ExpectSuccess)
{
    const std::string asset_id = "57a4f09d-8db2-4d1e-833c-9c12749bc199";
    const std::string recipe = TesterHelper::makeRecipeAsset(asset_id, "echo Hello world", "");

    rapidjson::Document recipeJson;
    recipeJson.Parse(recipe.c_str());

    if (recipeJson.HasParseError())
    {
        throw std::runtime_error("Bad recipe JSON:" + recipe);
    }

    ScriptAssetProcessor asset_processor(asset_id, mp_asset_messenger.get(), mp_public_key);
    unsigned int sleepVal = 0;
    asset_processor.handleAsset(recipeJson, TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv(), "", sleepVal);
    // Script is running, requires an update to complete
    ASSERT_FALSE(asset_processor.isComplete());

    // Call update to complete
    while (!asset_processor.isComplete())
    {
#ifdef _WIN32
        Sleep(1);
#else
        sleep(1);
#endif // #ifdef _WIN32
        asset_processor.update();
    }

    // Should now be complete and success reported
    ASSERT_TRUE(asset_processor.isComplete());
    ASSERT_TRUE(asset_processor.isSuccess());
    ASSERT_STREQ(mp_http_client->getLastRequestUrl().c_str(), std::string(m_test_url + "/assets/deliverystatus").c_str());
    ASSERT_FALSE(mp_http_client->getLastRequestJson().empty());

    // Check format and contents of receipt is correct
    rapidjson::Document json;
    json.Parse(mp_http_client->getLastRequestJson().c_str());
    ASSERT_TRUE(json.HasMember("assetDeliveryStatus"));
    ASSERT_TRUE(json["assetDeliveryStatus"].HasMember("status"));
    ASSERT_TRUE(json["assetDeliveryStatus"]["status"].GetBool());
    ASSERT_TRUE(json.HasMember("device_logs"));
    ASSERT_TRUE(json["device_logs"].HasMember("type"));
    ASSERT_STREQ(json["device_logs"]["type"].GetString(), "asset-device-data-logs");

    // Check the device logs are included in the response
    const std::string deviceLogs = utils::fromBase64(json["device_logs"]["data"].GetString());
    json.Parse(deviceLogs.c_str());
    ASSERT_EQ(json["device_logs"][0]["line"].GetInt(), 1);
    ASSERT_STREQ(json["device_logs"][0]["description"].GetString(), "Hello world");

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getSatReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getSatSuccessCount());
    ASSERT_EQ(0, mp_test_manager->getSatFailureCount());
}

TEST_F(ScriptAssetProcessorTest, ProcessCodeSigningAsset_ExpectSuccess)
{
    const std::string asset_id = "57a4f09d-8db2-4d1e-833c-9c12749bc199";
    const std::string recipe = TesterHelper::makeRecipeAsset(asset_id, "echo World hello", "code_signing_path", true);

    rapidjson::Document recipeJson;
    recipeJson.Parse(recipe.c_str());

    if (recipeJson.HasParseError())
    {
        throw std::runtime_error("Bad recipe JSON:" + recipe);
    }

    ScriptAssetProcessor assetProcessor(asset_id, mp_asset_messenger.get(), mp_public_key);
    unsigned int sleepVal = 0;
    assetProcessor.handleAsset(recipeJson, TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv(), "", sleepVal);
    // Script is running, requires an update to complete
    ASSERT_FALSE(assetProcessor.isComplete());

    // Call update to complete
    while (!assetProcessor.isComplete())
    {
#ifdef _WIN32
        Sleep(1);
#else
        sleep(1);
#endif // #ifdef _WIN32
        assetProcessor.update();
    }

    // Should now be complete and success reported
    ASSERT_TRUE(assetProcessor.isComplete());
    ASSERT_TRUE(assetProcessor.isSuccess());
    ASSERT_STREQ(mp_http_client->getLastRequestUrl().c_str(), std::string(m_test_url + "/assets/deliverystatus").c_str());
    ASSERT_FALSE(mp_http_client->getLastRequestJson().empty());

    // Check format and contents of receipt is correct
    rapidjson::Document json;
    json.Parse(mp_http_client->getLastRequestJson().c_str());
    ASSERT_TRUE(json["assetDeliveryStatus"]["status"].GetBool());

    ASSERT_TRUE(json.HasMember("device_logs"));
    ASSERT_TRUE(json["device_logs"].HasMember("type"));
    ASSERT_STREQ(json["device_logs"]["type"].GetString(), "asset-device-data-codesigning");

    // Check the device logs are included in the response
    const std::string deviceLogs = utils::fromBase64(json["device_logs"]["data"].GetString());
    json.Parse(deviceLogs.c_str());
    ASSERT_EQ(json["device_logs"][0]["line"].GetInt(), 1);
    ASSERT_STREQ(json["device_logs"][0]["description"].GetString(), "World hello");

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getSatReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getSatSuccessCount());
    ASSERT_EQ(0, mp_test_manager->getSatFailureCount());
}

TEST_F(ScriptAssetProcessorTest, LongRunningScript_ExpectSuccess)
{
    const std::string asset_id = "57a4f09d-8db2-4d1e-833c-9c12749bc199";
#ifdef _WIN32
    const std::string recipe = TesterHelper::makeRecipeAsset(asset_id, "timeout /t 5 > nul & echo Finished", "");
#else
    const std::string recipe = TesterHelper::makeRecipeAsset(asset_id, "sleep 5; echo \"Finished\"", "");
#endif

    rapidjson::Document recipeJson;
    recipeJson.Parse(recipe.c_str());

    if (recipeJson.HasParseError())
    {
        throw std::runtime_error("Bad recipe JSON:" + recipe);
    }

    ScriptAssetProcessor assetProcessor(asset_id, mp_asset_messenger.get(), mp_public_key);
    unsigned int sleepVal = 0;
    assetProcessor.handleAsset(recipeJson, TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv(), "", sleepVal);
    // Script is running, will require at least 5 seconds to complete
    ASSERT_FALSE(assetProcessor.isComplete());

    // Check update does not report complete as script runs for 5 seconds
    for (int i = 0; i < 4; i++)
    {
#ifdef _WIN32
		Sleep(1);
#else
		sleep(1);
#endif // #ifdef _WIN32
        assetProcessor.update();
        ASSERT_FALSE(assetProcessor.isComplete());
    }

    // Give extra time to complete
    while (!assetProcessor.isComplete())
    {
#ifdef _WIN32
        Sleep(1);
#else
        sleep(1);
#endif // #ifdef _WIN32
        assetProcessor.update();
    }

    // Should now be complete and success reported
    ASSERT_TRUE(assetProcessor.isComplete());
    ASSERT_TRUE(assetProcessor.isSuccess());
    ASSERT_STREQ(mp_http_client->getLastRequestUrl().c_str(), std::string(m_test_url + "/assets/deliverystatus").c_str());
    ASSERT_FALSE(mp_http_client->getLastRequestJson().empty());

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getSatReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getSatSuccessCount());
    ASSERT_EQ(0, mp_test_manager->getSatFailureCount());
}

TEST_F(ScriptAssetProcessorTest, MultipleScriptsRunningAtSameTime_ExpectSuccess)
{
    const std::string asset_id = "57a4f09d-8db2-4d1e-833c-9c12749bc199";
#ifdef _WIN32
    const std::string slowRecipe = TesterHelper::makeRecipeAsset(asset_id, "timeout /t 3 > nul & echo \"Finished\"", "");
    const std::string fastRecipe = TesterHelper::makeRecipeAsset(asset_id, "echo Hello World", "");
#else
    const std::string slowRecipe = TesterHelper::makeRecipeAsset(asset_id, "sleep 3; echo \"Finished\"", "");
    const std::string fastRecipe = TesterHelper::makeRecipeAsset(asset_id, "echo \"Hello World\"", "");
#endif

    rapidjson::Document slowRecipeJson;
    slowRecipeJson.Parse(slowRecipe.c_str());
    if (slowRecipeJson.HasParseError())
    {
        throw std::runtime_error("Bad recipe JSON:" + slowRecipe);
    }

    rapidjson::Document fastRecipeJson;
    fastRecipeJson.Parse(fastRecipe.c_str());
    if (fastRecipeJson.HasParseError())
    {
        throw std::runtime_error("Bad recipe JSON:" + fastRecipe);
    }

    unsigned int sleepVal = 0;
    ScriptAssetProcessor slowAssetProcessor(asset_id, mp_asset_messenger.get(), mp_public_key);
    slowAssetProcessor.handleAsset(slowRecipeJson, TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv(), "", sleepVal);
    // Script is running, will require at least 5 seconds to complete
    ASSERT_FALSE(slowAssetProcessor.isComplete());

    ScriptAssetProcessor fastAssetProcessor(asset_id, mp_asset_messenger.get(), mp_public_key);
    fastAssetProcessor.handleAsset(fastRecipeJson, TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv(), "", sleepVal);
    // Script is running, will require at least 5 seconds to complete
    ASSERT_FALSE(fastAssetProcessor.isComplete());

    // Give extra time to complete
    while (!fastAssetProcessor.isComplete())
    {
#ifdef _WIN32
        Sleep(1);
#else
        sleep(1);
#endif // #ifdef _WIN32

        // Simulate calling update on both processors
        slowAssetProcessor.update();
        fastAssetProcessor.update();
    }

    // Expect slow asset processor to not have yet completed
    ASSERT_FALSE(slowAssetProcessor.isComplete());
    // And the fast asset processor to have completed
    ASSERT_TRUE(fastAssetProcessor.isComplete());

    // Allow time for the slow asset processor and check it is complete

    // Call update to complete
    while (!slowAssetProcessor.isComplete())
    {
#ifdef _WIN32
        Sleep(1);
#else
        sleep(1);
#endif // #ifdef _WIN32
        slowAssetProcessor.update();
    }

    ASSERT_TRUE(slowAssetProcessor.isComplete());

    // Verify notifications were raised
    ASSERT_EQ(2, mp_test_manager->getSatReceivedCount());
    ASSERT_EQ(2, mp_test_manager->getSatSuccessCount());
    ASSERT_EQ(0, mp_test_manager->getSatFailureCount());
}

class CodeSigningAssetProcessorTest : public testing::Test
{
    public:
    const std::string m_test_url{"https://abc.ks.net"};
    std::unique_ptr<TestHttpClient> mp_http_client = nullptr;
    std::unique_ptr<AssetMessenger> mp_asset_messenger = nullptr;
    RSAPtr mp_public_key;
    TestEventManager *mp_test_manager = nullptr;

    void SetUp() override
    {
        // Use test deviceauthority instance to mock the interface between us and DDKG
        DeviceAuthority::setInstance(new TestDeviceAuthority());

        mp_public_key = TesterHelper::getRSAPublicKey();
        mp_http_client.reset(new TestHttpClient());
        mp_asset_messenger.reset(new HttpAssetMessenger(m_test_url, mp_http_client.get()));

        config.parse("credentialmanager.conf");

        mp_test_manager = new TestEventManager();
        EventManager::setInstance(mp_test_manager);
    }

    void TearDown() override
    {
        EventManager::setInstance(nullptr);
    }
};

TEST_F(CodeSigningAssetProcessorTest, ProcessSimpleScript_ExpectSuccess)
{
    const std::string asset_id = "57a4f09d-8db2-4d1e-833c-9c12749bc199";
    const std::string recipe = TesterHelper::makeRecipeAsset(asset_id, "echo hello world", "file://stage.deviceauthority.com/device-authority-logo.png", true);

    rapidjson::Document recipeJson;
    recipeJson.Parse(recipe.c_str());
    if (recipeJson.HasParseError())
    {
        throw std::runtime_error("Bad recipe JSON:" + recipe);
    }

    ScriptAssetProcessor asset_processor(asset_id, mp_asset_messenger.get(), mp_public_key);
    unsigned int sleepVal = 0;
    asset_processor.handleAsset(recipeJson, TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv(), "", sleepVal);
    // Script is running, requires an update to complete
    ASSERT_FALSE(asset_processor.isComplete());

    // Call update to complete
    while (!asset_processor.isComplete())
    {
#ifdef _WIN32
        Sleep(1);
#else
        sleep(1);
#endif // #ifdef _WIN32
        asset_processor.update();
}

    // Should now be complete and success reported
    ASSERT_TRUE(asset_processor.isComplete());
    ASSERT_TRUE(asset_processor.isSuccess());
    ASSERT_STREQ(mp_http_client->getLastRequestUrl().c_str(), std::string(m_test_url + "/assets/deliverystatus").c_str());
    ASSERT_FALSE(mp_http_client->getLastRequestJson().empty());

    // Check format and contents of receipt is correct
    rapidjson::Document json;
    json.Parse(mp_http_client->getLastRequestJson().c_str());
    ASSERT_TRUE(json.HasMember("assetDeliveryStatus"));
    ASSERT_TRUE(json["assetDeliveryStatus"].HasMember("status"));
    ASSERT_TRUE(json["assetDeliveryStatus"]["status"].GetBool());
    ASSERT_TRUE(json.HasMember("device_logs"));
    ASSERT_TRUE(json["device_logs"].HasMember("type"));
    ASSERT_STREQ(json["device_logs"]["type"].GetString(), "asset-device-data-codesigning");

    // Check the device logs are included in the response
    const std::string deviceLogs = utils::fromBase64(json["device_logs"]["data"].GetString());
    json.Parse(deviceLogs.c_str());
    ASSERT_GT(json["device_logs"].Size(), 0);
    ASSERT_EQ(json["device_logs"][0]["line"].GetInt(), 1);
    ASSERT_STREQ(json["device_logs"][0]["description"].GetString(), "hello world");

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getSatReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getSatSuccessCount());
    ASSERT_EQ(0, mp_test_manager->getSatFailureCount());
}

#endif // #ifndef SCRIPT_ASSET_PROCESSOR_UNITTEST_HPP
