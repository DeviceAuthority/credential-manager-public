/**
 * \file
 *
 * \brief HTTP worker loop unit tests
 *
 * \author Copyright (c) 2022 by Device Authority Ltd. ALL RIGHTS RESERVED.
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to Device Authority Ltd. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from Device Authority Ltd.
 *
 *
 * \date June 19 2023
 *
 */

#ifndef GROUP_ASSET_PROCESSOR_UNITTEST_HPP
#define GROUP_ASSET_PROCESSOR_UNITTEST_HPP

#include <fstream>
#include <iostream>
#include "gtest/gtest.h"
#include "deviceauthority.hpp"
#include "event_manager.hpp"
#include "group_asset_processor.hpp"
#include "http_asset_messenger.hpp"
#include "test_event_manager.hpp"
#include "test_http_client.hpp"
#include "test_deviceauthority.hpp"
#include "tester_helper.hpp"
#include "utils.hpp"

class GroupAssetProcessorTest : public testing::Test
{
    public:
    const std::string m_test_url{"https://abc.ks.net"};
    std::unique_ptr<TestHttpClient> mp_http_client = nullptr;
    std::unique_ptr<AssetMessenger> mp_asset_messenger = nullptr;
    TestEventManager *mp_test_manager = nullptr;

    void SetUp() override
    {
        mp_http_client.reset(new TestHttpClient());
        mp_asset_messenger.reset(new HttpAssetMessenger(m_test_url, mp_http_client.get()));

        // Use test deviceauthority instance to mock the interface between us and DDKG
        DeviceAuthority::setInstance(new TestDeviceAuthority());

        mp_test_manager = new TestEventManager();
        EventManager::setInstance(mp_test_manager);

    }

    void TearDown() override
    {
        DeviceAuthority::getInstance()->destroyInstance();

        EventManager::setInstance(nullptr);
    }

    const std::string makeGroupAssetData(const std::string &metadata) const
    {
        std::stringstream ss;
        ss << "{\n"
        << "  \"metadata\": \"" << utils::toBase64(metadata) << "\"\n"
        << "}";
        return ss.str();
    }

    const GroupAssetProcessor executeGroupMetadataAssetProcessor(const std::string &metadata_filepath, const std::string &metadata_text) const
    {
        const std::string asset_id = "57a4f09d-8db2-4d1e-833c-9c12749bc199";

        const std::string asset_data_str = makeGroupAssetData(metadata_text);
        GroupAssetProcessor asset_processor(asset_id, mp_asset_messenger.get(), metadata_filepath);

        rapidjson::Document asset_data_json;
        asset_data_json.Parse(asset_data_str.c_str());

        if (asset_data_json.HasParseError())
        {
            throw std::runtime_error("Bad recipe JSON:" + asset_data_str);
        }

        unsigned int sleep_val = 0;
        asset_processor.handleAsset(
            asset_data_json,
            utils::toBase64(TesterHelper::getSymmetricKey()),
            utils::toBase64(TesterHelper::getSymmetricIv()),
            "",
            sleep_val);

        return asset_processor;
    }
};

TEST_F(GroupAssetProcessorTest, TestWriteMetadataToFile)
{
    const std::string metadata_filepath{"/tmp/metadata_file.txt"};
    const std::string metadata_text{"this is his spider"};

    GroupAssetProcessor asset_processor = executeGroupMetadataAssetProcessor(metadata_filepath, metadata_text);

    ASSERT_TRUE(asset_processor.isComplete());
    ASSERT_TRUE(asset_processor.isSuccess());

    std::ifstream metadata_file(metadata_filepath.c_str());
    std::string line{};
    getline(metadata_file, line);
    metadata_file.close();
    ASSERT_STREQ(metadata_text.c_str(), line.c_str());

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getGroupMetadataReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getGroupMetadataSuccessCount());
    ASSERT_EQ(0, mp_test_manager->getGroupMetadataFailureCount());
}

TEST_F(GroupAssetProcessorTest, TestEmptyMetadataFilenameFailure)
{
    const std::string metadata_filepath{""};
    const std::string metadata_text{"this is his spider"};

    GroupAssetProcessor asset_processor = executeGroupMetadataAssetProcessor(metadata_filepath, metadata_text);

    ASSERT_TRUE(asset_processor.isComplete());
    ASSERT_FALSE(asset_processor.isSuccess());

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getGroupMetadataReceivedCount());
    ASSERT_EQ(0, mp_test_manager->getGroupMetadataSuccessCount());
    ASSERT_EQ(1, mp_test_manager->getGroupMetadataFailureCount());
}

TEST_F(GroupAssetProcessorTest, TestInvalidMetadataFilenameFailure)
{
    const std::string metadata_filepath{"/does/not/exist"};
    const std::string metadata_text{"this is his spider"};

    GroupAssetProcessor asset_processor = executeGroupMetadataAssetProcessor(metadata_filepath, metadata_text);

    ASSERT_TRUE(asset_processor.isComplete());
    ASSERT_FALSE(asset_processor.isSuccess());

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getGroupMetadataReceivedCount());
    ASSERT_EQ(0, mp_test_manager->getGroupMetadataSuccessCount());
    ASSERT_EQ(1, mp_test_manager->getGroupMetadataFailureCount());
}

#endif // #ifndef GROUP_ASSET_PROCESSOR_UNITTEST_HPP
