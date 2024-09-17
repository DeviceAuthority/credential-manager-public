/**
 * \file certificate_data_asset_processor_unittest.cpp
 *
 * \brief Unit test certificate data asset processor
 *
 * \author Copyright (c) 2023 by Device Authority Ltd. ALL RIGHTS RESERVED.
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to Device Authority Ltd. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from Device Authority Ltd.
 *
 *
 * \date Jul 31, 2023
 *
 */

#ifndef CERTIFICATE_DATA_ASSET_PROCESSOR_UNITTEST_HPP
#define CERTIFICATE_DATA_ASSET_PROCESSOR_UNITTEST_HPP

#include <vector>
#include "gtest/gtest.h"
#include "rapidjson/document.h"
#include "rapidjson/rapidjson.h"
#include "certificate_data_asset_processor.hpp"
#include "deviceauthority.hpp"
#include "event_manager.hpp"
#include "http_asset_messenger.hpp"
#include "test_deviceauthority.hpp"
#include "test_event_manager.hpp"
#include "test_http_client.hpp"
#include "test_tpm_wrapper.hpp"
#include "tester_helper.hpp"
#include "utils.hpp"

class CertificateDataAssetProcessorTest : public testing::Test
{
    public:
    const std::string m_asset_id{"asset_1234"};
    const std::string m_key_id{"keyid_1234"};
#ifdef _WIN32
    const std::string m_file_path{"C:\\Temp\\certs"};
#else // #ifdef _WIN32
    const std::string m_file_path{"/tmp/certs/"};
#endif // #ifdef _WIN32
    const std::string m_inter_file_path{m_file_path + "private_inter.pem"};
    const std::string m_private_key_file_path{m_file_path + "deviceKey.pem"};
    const std::string m_common_name{"Internet Widgits Pty Ltd"};
    const std::string m_certificate_id{"abcde-efghi-12345"};
    const std::string m_key{"01234567890123456789012345678901"};
    const std::string m_iv{"0123456789ABCDEF"};
    TestHttpClient *mp_http_client{nullptr};
    std::unique_ptr<AssetMessenger> mp_asset_messenger{nullptr};
    TestEventManager *mp_test_manager{nullptr};

    void SetUp() override
    {
        // Use test deviceauthority instance to mock the interface between us and DDKG
        DeviceAuthority::setInstance(new TestDeviceAuthority());

        mp_http_client = new TestHttpClient();
        mp_asset_messenger.reset(new HttpAssetMessenger("test url", mp_http_client));

        mp_test_manager = new TestEventManager();
        EventManager::setInstance(mp_test_manager);

        // Ensure file path exists
#ifdef _WIN32
		_mkdir(m_file_path.c_str());
#else
        mkdir(m_file_path.c_str(), 0777);
#endif // #ifdef _WIN32
    }

    void TearDown() override
    {
        if (mp_http_client)
        {
            delete mp_http_client;
            mp_http_client = nullptr;
        }

        EventManager::setInstance(nullptr);

#ifdef _WIN32
		_rmdir(m_file_path.c_str());
#else
        rmdir(m_file_path.c_str());
#endif // #ifdef _WIN32
    }

    const std::string makeCertificateDataAssetData(
        const std::string &file_path,
        bool auto_rotate,
        unsigned int polling_rate,
        const std::string &common_name,
        const std::string &certificate_id,
        const std::string &asset_id,
        bool is_ca,
        bool store_encrypted,
        bool sign_apphash)
    {
        rapidjson::Document root_document;
        root_document.SetObject();
        rapidjson::Document::AllocatorType& allocator = root_document.GetAllocator();

        root_document.AddMember("filePath", rapidjson::StringRef(file_path.c_str()), allocator);
        root_document.AddMember("autoRotate", auto_rotate, allocator);
        root_document.AddMember("pollingRate", polling_rate, allocator);
        root_document.AddMember("storeEncrypted", store_encrypted, allocator);
        root_document.AddMember("assetId", rapidjson::StringRef(asset_id.c_str()), allocator);
        root_document.AddMember("commonName", rapidjson::StringRef(common_name.c_str()), allocator);
        root_document.AddMember("certificateId", rapidjson::StringRef(certificate_id.c_str()), allocator);
        root_document.AddMember("ca", is_ca, allocator);
        root_document.AddMember("signAppHash", sign_apphash, allocator);

        rapidjson::StringBuffer strbuf;
        rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
        root_document.Accept(writer);

        return std::string(strbuf.GetString());
    }

    void testCertificateDataDeliveryStoredEncrypted(bool sign_apphash)
    {
        TpmWrapper::setInstance(new TestTpmWrapper(false));

        const std::string asset_data_str = makeCertificateDataAssetData(
            m_file_path, false, 0, m_common_name, m_certificate_id, m_asset_id, false /* is_ca */, true /* store_encrypted */, sign_apphash);
        CertificateDataAssetProcessor asset_processor(m_asset_id, mp_asset_messenger.get());

        rapidjson::Document asset_data_json;
        asset_data_json.Parse(asset_data_str.c_str());

        mp_http_client->setResponseJson("{\"statusCode\": 0}");

        unsigned int sleep_val = 0;
        asset_processor.handleAsset(
            asset_data_json,
            m_key,
            m_iv,
            m_key_id,
            sleep_val);

        // Should now be complete and success reported
        ASSERT_TRUE(asset_processor.isComplete());
        ASSERT_TRUE(asset_processor.isSuccess());

#ifndef _WIN32
        // Private key file should not exist as we store the interim key in a different file
        // while waiting for CSR response
        std::ifstream private_key_file(m_private_key_file_path);
        ASSERT_FALSE(private_key_file.good()); // file exists?

        std::ifstream inter_file(m_inter_file_path);
        ASSERT_TRUE(inter_file.good()); // file exists?
        std::string line;
        inter_file >> line;
        inter_file.close();
        ASSERT_GT(line.length(), 0);

        rapidjson::Document root_document;
        root_document.Parse<0>(line.c_str());
        ASSERT_FALSE(root_document.HasParseError());
        ASSERT_TRUE(root_document.HasMember("key-id"));
        ASSERT_TRUE(root_document.HasMember("asset-id"));
        ASSERT_TRUE(root_document.HasMember("ciphertext"));
        ASSERT_TRUE(root_document.HasMember("sign-apphash"));
        ASSERT_EQ(root_document["sign-apphash"].GetBool(), sign_apphash);

        ASSERT_EQ(remove(m_inter_file_path.c_str()), 0);
#endif // #ifndef _WIN32

        // Verify notifications were raised
        ASSERT_EQ(1, mp_test_manager->getCertificateDataReceivedCount());
        ASSERT_EQ(1, mp_test_manager->getPrivateKeyCreatedCount());
        ASSERT_EQ(1, mp_test_manager->getPrivateKeyStoredCount());
        ASSERT_EQ(0, mp_test_manager->getPrivateKeyFailureCount());
        ASSERT_EQ(1, mp_test_manager->getCsrCreatedCount());
        ASSERT_EQ(1, mp_test_manager->getCsrDeliveredCount());
        ASSERT_EQ(0, mp_test_manager->getCsrFailureCount());
    }
};

TEST_F(CertificateDataAssetProcessorTest, ProcessCertificateDataDelivery_NotEncrypted)
{
    const std::string asset_data_str = makeCertificateDataAssetData(
        m_file_path, false, 0, m_common_name, m_certificate_id, m_asset_id, false /* is_ca */, false /* store_encrypted */, false /* sign_apphash */);
    CertificateDataAssetProcessor asset_processor(m_asset_id, mp_asset_messenger.get());

    rapidjson::Document asset_data_json;
    asset_data_json.Parse(asset_data_str.c_str());

    mp_http_client->setResponseJson("{\"statusCode\": 0}");

    unsigned int sleep_val = 0;
    asset_processor.handleAsset(
        asset_data_json,
        m_key,
        m_iv,
        m_key_id,
        sleep_val);

    // Should now be complete and success reported
    ASSERT_TRUE(asset_processor.isComplete());
    ASSERT_TRUE(asset_processor.isSuccess());

#ifndef _WIN32
    {
        std::ifstream private_key_file(m_private_key_file_path);
        ASSERT_TRUE(private_key_file.good()); // file exists?
        std::string line;
        private_key_file >> line;
        private_key_file.close();
        ASSERT_GT(line.length(), 0);
    }

    ASSERT_EQ(remove(m_private_key_file_path.c_str()), 0);
#endif // #ifndef _WIN32

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getCertificateDataReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getPrivateKeyCreatedCount());
    ASSERT_EQ(1, mp_test_manager->getPrivateKeyStoredCount());
    ASSERT_EQ(0, mp_test_manager->getPrivateKeyFailureCount());
    ASSERT_EQ(0, mp_test_manager->getCertificateFailureCount());
}

TEST_F(CertificateDataAssetProcessorTest, ProcessCertificateDataDelivery_StoreEncrypted_NoAppHashSig_NoTPM)
{
    testCertificateDataDeliveryStoredEncrypted(false);
}

TEST_F(CertificateDataAssetProcessorTest, ProcessCertificateDataDelivery_StoreEncrypted_WithAppHashSig_NoTPM)
{
    testCertificateDataDeliveryStoredEncrypted(true);
}

TEST_F(CertificateDataAssetProcessorTest, ProcessCertificateDataDelivery_StoreEncrypted_WithTPM)
{
    TpmWrapper::setInstance(new TestTpmWrapper(true));

    const std::string asset_data_str = makeCertificateDataAssetData(
        m_file_path, false, 0, m_common_name, m_certificate_id, m_asset_id, false /* is_ca */, true /* store_encrypted */, false /* sign_apphash */);
    CertificateDataAssetProcessor asset_processor(m_asset_id, mp_asset_messenger.get());

    rapidjson::Document asset_data_json;
    asset_data_json.Parse(asset_data_str.c_str());

    mp_http_client->setResponseJson("{\"statusCode\": 0}");

    unsigned int sleep_val = 0;
    asset_processor.handleAsset(
        asset_data_json,
        m_key,
        m_iv,
        m_key_id,
        sleep_val);

    // Should now be complete and success reported
    ASSERT_TRUE(asset_processor.isComplete());
    ASSERT_TRUE(asset_processor.isSuccess());

#ifndef _WIN32
    // Private key file should not exist as we store the interim key in a different file
    // while waiting for CSR response
    std::ifstream private_key_file(m_private_key_file_path);
    ASSERT_FALSE(private_key_file.good()); // file exists?

    std::ifstream inter_file(m_inter_file_path);
    ASSERT_TRUE(inter_file.good()); // file exists?
    std::string line;
    inter_file >> line;
    inter_file.close();
    ASSERT_GT(line.length(), 0);

    // Ensure the key encrypting the inter file content has been created at the expected path
    TestTpmWrapper* p_tpm_wrapper = (TestTpmWrapper*)TpmWrapper::getInstance();
    ASSERT_TRUE(p_tpm_wrapper->hasKey(m_inter_file_path));

    rapidjson::Document root_document;
    root_document.Parse<0>(line.c_str());
    ASSERT_FALSE(root_document.HasParseError());
    ASSERT_TRUE(root_document.HasMember("ciphertext"));
    ASSERT_TRUE(root_document.HasMember("iv"));

    ASSERT_EQ(remove(m_inter_file_path.c_str()), 0);
#endif // #ifndef _WIN32

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getCertificateDataReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getPrivateKeyCreatedCount());
    ASSERT_EQ(1, mp_test_manager->getPrivateKeyStoredCount());
    ASSERT_EQ(0, mp_test_manager->getPrivateKeyFailureCount());
    ASSERT_EQ(0, mp_test_manager->getCertificateFailureCount());
}

#endif // #ifndef CERTIFICATE_DATA_ASSET_PROCESSOR_HPP
