/**
 * \file sat_asset_processor_unittest.cpp
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

#ifndef SAT_ASSET_PROCESSOR_UNITTEST_HPP
#define SAT_ASSET_PROCESSOR_UNITTEST_HPP

#ifndef DISABLE_MQTT

#include <stdlib.h>
#include <string>
#include "gtest/gtest.h"
#include "base64.h"
#include "dacryptor.hpp"
#include "log.hpp"
#include "mqtt_asset_messenger.hpp"
#include "sat_asset_processor.hpp"
#include "test_mqtt_client.hpp"
#include "tester_helper.hpp"
#include "utils.hpp"

class SatAssetProcessorTest : public testing::Test
{
    public:
    std::unique_ptr<TestMqttClient> mp_mqtt_client = nullptr;
    rapidjson::Document m_asset_data_json;
    std::unique_ptr<AssetMessenger> mp_asset_messenger = nullptr;
    TestEventManager *mp_test_manager = nullptr;

    void SetUp() override
    {
        mp_test_manager = new TestEventManager();
        EventManager::setInstance(mp_test_manager);

        mp_mqtt_client.reset(new TestMqttClient("", "", "", 0));
        mp_asset_messenger.reset(new MqttAssetMessenger(mp_mqtt_client.get()));

        const std::string asset_data_str = makeSatAssetData(TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv());
        m_asset_data_json.Parse(asset_data_str.c_str());

        if (m_asset_data_json.HasParseError())
        {
            throw std::runtime_error("Bad recipe JSON:" + asset_data_str);
        }
    }

    void TearDown() override
    {
        EventManager::setInstance(nullptr);
    }

    std::string makeSatAssetData(const std::string &key, const std::string &iv) const
    {
        const std::string encryptedKeyB64 = TesterHelper::encrypt(key, TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv());
        const std::string encryptedIvB64 = TesterHelper::encrypt(iv, TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv());

        std::stringstream ss;
        ss << "{\n"
        << "  \"key\": \"" << encryptedKeyB64 << "\",\n"
        << "  \"iv\": \"" << encryptedIvB64 << "\"\n"
        << "}";
        return ss.str();
    }
};

TEST_F(SatAssetProcessorTest, ProcessSimpleSatScript_ExpectSuccess)
{
    const std::string asset_id = "57a4f09d-8db2-4d1e-833c-9c12749bc199";
    const std::string script_id = "scriptId12345";
    const std::string script_data = TesterHelper::encrypt("echo \"Hello World\"", TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv());
    const std::string asset_data_str = makeSatAssetData(TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv());

    SatAssetProcessor asset_processor(asset_id, mp_asset_messenger.get(), script_id, script_data, "specifictopic");
    unsigned int sleep_val = 0;
    asset_processor.handleAsset(
        m_asset_data_json,
        utils::toBase64(TesterHelper::getSymmetricKey()),
        utils::toBase64(TesterHelper::getSymmetricIv()),
        "",
        sleep_val);
    // Script is running, requires an update to complete
    ASSERT_FALSE(asset_processor.isComplete());
	
#ifdef _WIN32
    Sleep(1);
#else
    sleep(1);
#endif // #ifdef _WIN32

    // Call update to complete
    asset_processor.update();

    // Should now be complete and success reported
    ASSERT_TRUE(asset_processor.isComplete());
    ASSERT_TRUE(asset_processor.isSuccess());

    // Check an acknowledge message has been sent
    const auto expected_str = "{\"id\":\"" + script_id + "\",\"data\":\"s9hdl8dW6iN7uQzFiRBP9A==\"}";
    const auto output_json = mp_mqtt_client->getLastPublishJson();
    ASSERT_STREQ(expected_str.c_str(), output_json.c_str());

    rapidjson::Document output_obj;
    output_obj.Parse(output_json.c_str());
    ASSERT_TRUE(output_obj.HasMember("data"));
    auto output = TesterHelper::decrypt(output_obj["data"].GetString(), TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv());
    ASSERT_STREQ("Hello World\n", output.c_str());

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getSatReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getSatSuccessCount());
    ASSERT_EQ(0, mp_test_manager->getSatFailureCount());
}

TEST_F(SatAssetProcessorTest, LongRunningScript_ExpectSuccess)
{
    const std::string asset_id = "57a4f09d-8db2-4d1e-833c-9c12749bc199";
    const std::string script_id = "scriptId12345";
    const std::string script_data = TesterHelper::encrypt("sleep 4; echo \"Finished\"", TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv());
    const std::string asset_data_str = makeSatAssetData(TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv());

    SatAssetProcessor asset_processor(asset_id, mp_asset_messenger.get(), script_id, script_data, "specifictopic");
    unsigned int sleep_val = 0;
    asset_processor.handleAsset(
        m_asset_data_json,
        utils::toBase64(TesterHelper::getSymmetricKey()),
        utils::toBase64(TesterHelper::getSymmetricIv()),
        "",
        sleep_val);
    // Script is running, will require at least 4 seconds to complete
    ASSERT_FALSE(asset_processor.isComplete());

    // Check update does not report complete as script runs for 4 seconds
    for (int i = 0; i < 3; i++)
    {
#ifdef _WIN32
		Sleep(1);
#else
		sleep(1);
#endif // #ifdef _WIN32
        
		asset_processor.update();
        ASSERT_FALSE(asset_processor.isComplete());
    }

    // Give extra time to complete
#ifdef _WIN32
    Sleep(2);
#else
    sleep(2);
#endif // #ifdef _WIN32

    asset_processor.update();

    // Should now be complete and success reported
    ASSERT_TRUE(asset_processor.isComplete());
    ASSERT_TRUE(asset_processor.isSuccess());

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getSatReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getSatSuccessCount());
    ASSERT_EQ(0, mp_test_manager->getSatFailureCount());
}

TEST_F(SatAssetProcessorTest, MultipleScriptsRunningAtSameTime_ExpectSuccess)
{
    const std::string asset_id = "57a4f09d-8db2-4d1e-833c-9c12749bc199";
    const std::string script_id = "scriptId12345";
    const std::string slowScriptData = TesterHelper::encrypt("sleep 2; echo \"Finished\"", TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv());
    const std::string fastScriptData = TesterHelper::encrypt("echo \"Hello World\"", TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv());

    unsigned int sleep_val = 0;
    SatAssetProcessor slowAssetProcessor(asset_id, mp_asset_messenger.get(), script_id, slowScriptData, "specifictopic");
    slowAssetProcessor.handleAsset(
        m_asset_data_json,
        utils::toBase64(TesterHelper::getSymmetricKey()),
        utils::toBase64(TesterHelper::getSymmetricIv()),
        "",
        sleep_val);
    ASSERT_FALSE(slowAssetProcessor.isComplete());

    SatAssetProcessor fastAssetProcessor(asset_id, mp_asset_messenger.get(), script_id, fastScriptData, "specifictopic");
    fastAssetProcessor.handleAsset(
        m_asset_data_json,
        utils::toBase64(TesterHelper::getSymmetricKey()),
        utils::toBase64(TesterHelper::getSymmetricIv()),
        "",
        sleep_val);
    ASSERT_FALSE(fastAssetProcessor.isComplete());

#ifdef _WIN32
    Sleep(1);
#else
    sleep(1);
#endif // #ifdef _WIN32
    // Simulate calling update on both processors
    slowAssetProcessor.update();
    fastAssetProcessor.update();

    // Expect slow asset processor to not have yet completed
    ASSERT_FALSE(slowAssetProcessor.isComplete());
    // And the fast asset processor to have completed
    ASSERT_TRUE(fastAssetProcessor.isComplete());

#ifdef _WIN32
    Sleep(2);
#else
    sleep(2);
#endif // #ifdef _WIN32

    // Allow time for the slow asset processor and check it is complete
    slowAssetProcessor.update();
    ASSERT_TRUE(slowAssetProcessor.isComplete());

    // Verify notifications were raised
    ASSERT_EQ(2, mp_test_manager->getSatReceivedCount());
    ASSERT_EQ(2, mp_test_manager->getSatSuccessCount());
    ASSERT_EQ(0, mp_test_manager->getSatFailureCount());
}

TEST_F(SatAssetProcessorTest, ProcessInvalidScript_ExpectFailure)
{
    const std::string asset_id = "57a4f09d-8db2-4d1e-833c-9c12749bc199";
    const std::string script_id = "scriptId12345";
    const std::string script_data = TesterHelper::encrypt("echo $(\"Hello World\"", TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv());

    SatAssetProcessor asset_processor(asset_id, mp_asset_messenger.get(), script_id, script_data, "specifictopic");
    unsigned int sleep_val = 0;
    asset_processor.handleAsset(
        m_asset_data_json,
        utils::toBase64(TesterHelper::getSymmetricKey()),
        utils::toBase64(TesterHelper::getSymmetricIv()),
        "",
        sleep_val);
    ASSERT_FALSE(asset_processor.isComplete());

    // Script fails and should return complete true with error
#ifdef _WIN32
    Sleep(1);
#else
    sleep(1);
#endif // #ifdef _WIN32
    asset_processor.update();
    ASSERT_TRUE(asset_processor.isComplete());
    ASSERT_FALSE(asset_processor.isSuccess());

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getSatReceivedCount());
    ASSERT_EQ(0, mp_test_manager->getSatSuccessCount());
    ASSERT_EQ(1, mp_test_manager->getSatFailureCount());
}

TEST_F(SatAssetProcessorTest, BlankScript_ExpectSuccessWithNoResultData)
{
    const std::string asset_id = "57a4f09d-8db2-4d1e-833c-9c12749bc199";
    const std::string script_id = "scriptId12345";
    const std::string script_data = TesterHelper::encrypt("", TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv());

    SatAssetProcessor asset_processor(asset_id, mp_asset_messenger.get(), script_id, script_data, "specifictopic");
    unsigned int sleep_val = 0;
    asset_processor.handleAsset(
        m_asset_data_json,
        utils::toBase64(TesterHelper::getSymmetricKey()),
        utils::toBase64(TesterHelper::getSymmetricIv()),
        "",
        sleep_val);
    ASSERT_FALSE(asset_processor.isComplete());

    // Script fails and should return complete true with error
#ifdef _WIN32
    Sleep(1);
#else
    sleep(1);
#endif // #ifdef _WIN32
    asset_processor.update();
    ASSERT_TRUE(asset_processor.isComplete());
    ASSERT_TRUE(asset_processor.isSuccess());

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getSatReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getSatSuccessCount());
    ASSERT_EQ(0, mp_test_manager->getSatFailureCount());
}

TEST_F(SatAssetProcessorTest, CheckOutputIsCorrectlyFormatted_ExpectSuccess)
{
    const std::string asset_id = "57a4f09d-8db2-4d1e-833c-9c12749bc199";
    const std::string script_id = "scriptId12345";
    const std::string script_data = TesterHelper::encrypt("echo \"Hello World\"", TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv());
    const std::string asset_data_str = makeSatAssetData(TesterHelper::getSymmetricKey(), TesterHelper::getSymmetricIv());

    SatAssetProcessor asset_processor(asset_id, mp_asset_messenger.get(), script_id, script_data, "specifictopic");
    unsigned int sleep_val = 0;
    asset_processor.handleAsset(
        m_asset_data_json,
        utils::toBase64(TesterHelper::getSymmetricKey()),
        utils::toBase64(TesterHelper::getSymmetricIv()),
        "",
        sleep_val);
    // Script is running, requires an update to complete
    ASSERT_FALSE(asset_processor.isComplete());
	
#ifdef _WIN32
    Sleep(1);
#else
    sleep(1);
#endif // #ifdef _WIN32
    // Call update to complete
    asset_processor.update();

    // Should now be complete and success reported
    ASSERT_TRUE(asset_processor.isComplete());
    ASSERT_TRUE(asset_processor.isSuccess());

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getSatReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getSatSuccessCount());
    ASSERT_EQ(0, mp_test_manager->getSatFailureCount());
}

#endif // #ifndef DISABLE_MQTT

#endif // #ifndef SAT_ASSET_PROCESSOR_HPP