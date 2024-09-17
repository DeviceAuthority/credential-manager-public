/**
 * \file certificate_asset_processor_unittest.cpp
 *
 * \brief Unit test certificate asset processor
 *
 * \author Copyright (c) 2023 by Device Authority Ltd. ALL RIGHTS RESERVED.
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to Device Authority Ltd. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from Device Authority Ltd.
 *
 *
 * \date Jul 28, 2023
 *
 */

#ifndef CERTIFICATE_ASSET_PROCESSOR_UNITTEST_HPP
#define CERTIFICATE_ASSET_PROCESSOR_UNITTEST_HPP

#include <vector>
#include "gtest/gtest.h"
#include "rapidjson/document.h"
#include "rapidjson/rapidjson.h"
#include "certificate_asset_processor.hpp"
#include "deviceauthority.hpp"
#include "event_manager.hpp"
#include "http_asset_messenger.hpp"
#include "ncrypt_cert_store.hpp"
#include "test_deviceauthority.hpp"
#include "test_event_manager.hpp"
#include "test_http_client.hpp"
#include "test_tpm_wrapper.hpp"
#include "tpm_wrapper.hpp"
#include "tester_helper.hpp"
#include "utils.hpp"
#include "win_cert_store_factory.hpp"

class CertificateAssetProcessorTest : public testing::Test
{
    public:
    const std::string m_asset_id{"asset_1234"};
    const std::string m_key_id{"keyid_1234"};
    const std::string m_certificate{"-----BEGIN CERTIFICATE-----\nMIIDETCCAfkCFBWeseQkSi3duBP6ieYfi5hx88kaMA0GCSqGSIb3DQEBCwUAMEUx\nCzAJBgNVBAYTAkdCMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\ncm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjQwMzA0MTcyNDI1WhcNMjUwMzA0MTcy\nNDI1WjBFMQswCQYDVQQGEwJHQjETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE\nCgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOC\nAQ8AMIIBCgKCAQEAk90/qjsel7r2xxhdShWxb7WkAajrzK+2PTZZ5LKmx7WHHSHy\n+geU5qYPgk7Po1UUouOKnTAwxglLe3d0pAgNHoYzAHHCK9LXNntpgz4XrnL2LJhT\n7YCuwMN3TBzqXHmZy2BPa7tyDOoqljyewD5+ggT3slftnGvXKBhUZMQ4pxQBjAeY\n7d8LRBwZoK2DfuGFgicgpna+pjr6k+P7oWDLcUkjOGCHBx2JX52dpTz3jGWbYnEc\n+QY4NBgOVZ49Y6dbk6MONGsdlo5HYm1XnotpZKrdHXzqEGqKJV+L1xgJzd1vU6XL\n5xrNCWY0SdVkK3f3sPfRkUcXdLnNLztBun2AMwIDAQABMA0GCSqGSIb3DQEBCwUA\nA4IBAQAi8cSB2ko9gVikjc9s70Lr2gNzsLEEM7zWvNz+zFr0yczRkoxG/3xxMLan\nTvdKjHzGBUXXpwSmqBziVqkYyx6C0e3Z77ql0XGnWVIFLepsqVvYxyHezo2Lp4+M\nKwG3f1sYOrg3LAQPsrcwi1fFJTj82uNv6QrGnnjitzPs4RKiTTnF+tAkNP/d6Y8G\nCX0mZa68lsM9VQ939yTZ7qT+W7kfvWPc6eZ8gz+PtnEEViFBW7Sn6aub7y4VmRXT\n8QGsR7mduEEh3EIos61bmI8JkS7/asRcFd5o92eXRbs/R5+kTKqRSoq5lbhEXE0J\nVDSEnab86efNI852k/r3gWgzaw6n\n-----END CERTIFICATE-----\n"};
    const std::string m_private_key{"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAk90/qjsel7r2xxhdShWxb7WkAajrzK+2PTZZ5LKmx7WHHSHy\n+geU5qYPgk7Po1UUouOKnTAwxglLe3d0pAgNHoYzAHHCK9LXNntpgz4XrnL2LJhT\n7YCuwMN3TBzqXHmZy2BPa7tyDOoqljyewD5+ggT3slftnGvXKBhUZMQ4pxQBjAeY\n7d8LRBwZoK2DfuGFgicgpna+pjr6k+P7oWDLcUkjOGCHBx2JX52dpTz3jGWbYnEc\n+QY4NBgOVZ49Y6dbk6MONGsdlo5HYm1XnotpZKrdHXzqEGqKJV+L1xgJzd1vU6XL\n5xrNCWY0SdVkK3f3sPfRkUcXdLnNLztBun2AMwIDAQABAoIBAQCAM5ZdjECsIYiR\nesh30XM0ffKjFcjMgZSqYhNyvIrqILPzSFoY+rXZfSV5P8e7v6rSyCKIwx2mtqxh\ncmMJTYnCa2yQ+BD4WigKrtn+1rlFoZtbcv9hru7VZyRqM6/nWe9EbE6wA6eRFv6x\noAGsgQLCzHfOg3oa4017EA0sCQ1tng1dcyTF2jZeR66GiiEWn9kOkiubVKhH1W2+\noS9alP9d39Nc/AupUMhu4Cn2pRoHIlZbxllfOf9TH6urcxeIZP4BFdmCzx5hDlQK\ngxNvH0VF36DeX97kPe+yvHmaNHhcnUr18BdWSRy6dpj68Jm6hDpDm/cMQsOsQzfS\nnMcNy8QBAoGBAOuZhHqtr5mDSmLogUnNXlbBlzsbzRcpgxCtkYAJFUN7Fqo8Ts/O\nY9p0/awCQJ3AVN2kE8ye/uDBfQ+1BlCWY6UKmbqzdc6jo3iZVP1we3r42HQ6pP3L\nDvxoPeA4soq30K6Sttis5BMNUY3wsCe2/YuZZznrc39AhDJDMRsPmrsBAoGBAKCq\n67QAl9cQ7FPRccw/USOj5yLsj8cO3x7kB4F2O8D3wncf87m9CO69dgOJfW7637CW\nb3S/VCCc+AHm8dr2kROBmnUHeX0L2vigf1NZWJBfWOFnHZrsOuiW71FSDKPxjveK\noX1CTaLIyVCRx2fj2W94xSOipYqspmY/MhsDpT8zAoGAAyncjYkngngw14MnuUX4\nrlGLJlAJQPZdvCuYeI+mqXFNrJuCs2eiD5ziixy8oWGjwhYh7e10nq/6beuQWiSq\n0dyCk+809cFcwJHOgliwT8Znoafn70B6wwjjS893FkXBl5aAvggUR+012yIQO3hJ\nj0ZQDIcM1fiXzdT5I9Ph0AECgYAswXAHJGMntb8fWiipDLo9g1rPj7Y9bRcaM8sj\ndRwQFPRG2s+53b6vQnetZI9cauYE+uLxUprMuu0bGookxKqFFIVCNGLTQoos2Aif\n3zOcg/LuVxsYHNYMFH9117VNtextaGCz09RslCIAH5u8hOv88Vd5JcWXa6Cuusvq\nWomdoQKBgCPDxQbFu6rqdCfPJdpfHjhMbSajV/6uLB/5KnUub4mphdw/WB/HDEqc\nHElz0nIuA4eDptz0zb5v99tDqwKp3PyxuG8WpdMcYdUbVuZhQ8GumU/IVhC+/Tau\ndqhoIIXIoxk4bmY8UTjTpJeEwiG+cFX7IIADKPKc8HVluesAJYzD\n-----END RSA PRIVATE KEY-----\n"};
    const std::string m_key{"01234567890123456789012345678901"};
    const std::string m_iv{"0123456789ABCDEF"};
    const std::string m_tpm_key{"12345678901234567890123456789010"};
    const std::string m_tpm_iv{"123456789ABCDEF0"};
#ifdef _WIN32
    const std::string m_file_path{"C:\\Temp\\certs\\"};
#else
	const std::string m_file_path{"/tmp/certs/"};
#endif // #ifdef _WIN32
    const std::string m_inter_file_path{m_file_path + "private_inter.pem"};
    const std::string m_cert_file_path{m_file_path + "deviceCert.cert"};
    const std::string m_private_key_file_path{m_file_path + "deviceKey.pem"};
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

        WinCertStoreFactory::useUserStore(true);

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

#ifdef _WIN32
		_rmdir(m_file_path.c_str());
#else
        rmdir(m_file_path.c_str());
#endif // #ifdef _WIN32

        TpmWrapper::setInstance(nullptr);

        EventManager::setInstance(nullptr);
    }

    const std::string makeCertificateAssetData(
        const std::string &file_path,
        bool auto_rotate,
        unsigned int polling_rate,
        bool store_encrypted,
        const std::string &asset_id,
        const std::string &certificate,
        const std::string &key_id = "",
        const std::string &private_key = "",
        const std::string &key = "",
        const std::string &iv = "",
        bool sign_apphash = false)
    {
        rapidjson::Document root_document;
        root_document.SetObject();
        rapidjson::Document::AllocatorType& allocator = root_document.GetAllocator();

        root_document.AddMember("filePath", rapidjson::StringRef(file_path.c_str()), allocator);
        root_document.AddMember("autoRotate", auto_rotate, allocator);
        root_document.AddMember("pollingRate", polling_rate, allocator);
        root_document.AddMember("storeEncrypted", store_encrypted, allocator);
        root_document.AddMember("assetId", rapidjson::StringRef(asset_id.c_str()), allocator);
        const std::string encrypted_cert(TesterHelper::encrypt(certificate.c_str(), key, iv));
        root_document.AddMember("certificate", rapidjson::StringRef(encrypted_cert.c_str()), allocator);

        if (!key_id.empty())
        {
            root_document.AddMember("keyId", rapidjson::StringRef(key_id.c_str()), allocator);
        }

        std::string encrypted_private_key;
        if (!private_key.empty())
        {
            encrypted_private_key = TesterHelper::encrypt(private_key, key, iv);
        }
        root_document.AddMember("privateKey", rapidjson::StringRef(encrypted_private_key.c_str()), allocator);

        std::string encrypted_key;
        if (!key.empty())
        {
            encrypted_key = TesterHelper::encrypt(utils::toBase64(key).c_str(), key, iv);
        }
        root_document.AddMember("key", rapidjson::StringRef(encrypted_key.c_str()), allocator);

        std::string encrypted_iv;
        if (!iv.empty())
        {
            encrypted_iv = TesterHelper::encrypt(utils::toBase64(iv).c_str(), key, iv);
        }
        root_document.AddMember("iv", rapidjson::StringRef(encrypted_iv.c_str()), allocator);

        root_document.AddMember("signAppHash", sign_apphash, allocator);

        rapidjson::StringBuffer strbuf;
        rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
        root_document.Accept(writer);

        return std::string(strbuf.GetString());
    }

    void testProcessCertificateDeliveryStoredEncryptedWithPrivateKey(bool sign_apphash)
    {
        TpmWrapper::setInstance(new TestTpmWrapper(false));

        const std::string asset_data_str = makeCertificateAssetData(
            m_file_path, false, 0, true, m_asset_id, m_certificate, m_key_id, m_private_key, m_key, m_iv, sign_apphash);

        std::string private_key_json;
        utils::createJsonEncryptionBlock(
            m_key_id,
            m_asset_id,
            TesterHelper::encrypt(m_private_key, m_key, m_iv),
            private_key_json,
            false,
            sign_apphash);

        std::string certificate_json;
        utils::createJsonEncryptionBlock(
            m_key_id,
            m_asset_id,
            TesterHelper::encrypt(m_certificate, m_key, m_iv),
            certificate_json,
            false,
            sign_apphash);

        CertificateAssetProcessor asset_processor(m_asset_id, mp_asset_messenger.get());

        rapidjson::Document asset_data_json;
        asset_data_json.Parse(asset_data_str.c_str());

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
        ASSERT_TRUE(TesterHelper::checkFileContentsMatch(m_cert_file_path, certificate_json));
        ASSERT_TRUE(TesterHelper::checkFileContentsMatch(m_private_key_file_path, private_key_json));

        ASSERT_EQ(remove(m_private_key_file_path.c_str()), 0);
        ASSERT_EQ(remove(m_cert_file_path.c_str()), 0);
#endif // #ifndef _WIN32

        // Verify notifications were raised
        ASSERT_EQ(1, mp_test_manager->getCertificateReceivedCount());
        ASSERT_EQ(1, mp_test_manager->getCertificateStoredCount());
        ASSERT_EQ(0, mp_test_manager->getCertificateFailureCount());
        ASSERT_EQ(1, mp_test_manager->getPrivateKeyReceivedCount());
        ASSERT_EQ(1, mp_test_manager->getPrivateKeyStoredCount());
        ASSERT_EQ(0, mp_test_manager->getPrivateKeyFailureCount());
    }
};

TEST_F(CertificateAssetProcessorTest, ProcessCertificateDelivery_NotEncrypted_NoPrivateKey)
{
    TpmWrapper::setInstance(new TestTpmWrapper(false));

    const std::string asset_data_str = makeCertificateAssetData(
        m_file_path, false, 0, false, m_asset_id, m_certificate, m_key_id, "", m_key, m_iv);
    CertificateAssetProcessor asset_processor(m_asset_id, mp_asset_messenger.get());

    rapidjson::Document asset_data_json;
    asset_data_json.Parse(asset_data_str.c_str());

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

    ASSERT_TRUE(TesterHelper::checkFileContentsMatch(m_cert_file_path, m_certificate));

    ASSERT_EQ(remove(m_cert_file_path.c_str()), 0);

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getCertificateReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getCertificateStoredCount());
    ASSERT_EQ(0, mp_test_manager->getCertificateFailureCount());
    ASSERT_EQ(0, mp_test_manager->getPrivateKeyReceivedCount());
    ASSERT_EQ(0, mp_test_manager->getPrivateKeyStoredCount());
    ASSERT_EQ(0, mp_test_manager->getPrivateKeyFailureCount());
}

TEST_F(CertificateAssetProcessorTest, ProcessCertificateDelivery_NotEncrypted_WithPrivateKeyInJsonRequest)
{
    TpmWrapper::setInstance(new TestTpmWrapper(false));

    const std::string asset_data_str = makeCertificateAssetData(
        m_file_path, false, 0, false, m_asset_id, m_certificate, m_key_id, m_private_key, m_key, m_iv);
    CertificateAssetProcessor asset_processor(m_asset_id, mp_asset_messenger.get());

    rapidjson::Document asset_data_json;
    asset_data_json.Parse(asset_data_str.c_str());

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

    ASSERT_TRUE(TesterHelper::checkFileContentsMatch(m_cert_file_path, m_certificate));
    ASSERT_TRUE(TesterHelper::checkFileContentsMatch(m_private_key_file_path, m_private_key));

    ASSERT_EQ(remove(m_private_key_file_path.c_str()), 0);
    ASSERT_EQ(remove(m_cert_file_path.c_str()), 0);

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getCertificateReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getCertificateStoredCount());
    ASSERT_EQ(0, mp_test_manager->getCertificateFailureCount());
    ASSERT_EQ(1, mp_test_manager->getPrivateKeyReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getPrivateKeyStoredCount());
    ASSERT_EQ(0, mp_test_manager->getPrivateKeyFailureCount());
}

#ifndef _WIN32
TEST_F(CertificateAssetProcessorTest, ProcessCertificateDelivery_NotEncrypted_WithPrivateKeyInJsonRequest_WithTPM)
{
    TpmWrapper::setInstance(new TestTpmWrapper(true));

    const std::string asset_data_str = makeCertificateAssetData(
        m_file_path, false, 0, false, m_asset_id, m_certificate, m_key_id, m_private_key, m_key, m_iv);

    CertificateAssetProcessor asset_processor(m_asset_id, mp_asset_messenger.get());

    rapidjson::Document asset_data_json;
    asset_data_json.Parse(asset_data_str.c_str());

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

    ASSERT_TRUE(TesterHelper::checkFileContentsMatch(m_cert_file_path, m_certificate));
    ASSERT_TRUE(TesterHelper::checkFileContentsMatch(m_private_key_file_path, m_private_key));

    ASSERT_EQ(remove(m_private_key_file_path.c_str()), 0);
    ASSERT_EQ(remove(m_cert_file_path.c_str()), 0);

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getCertificateReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getCertificateStoredCount());
    ASSERT_EQ(0, mp_test_manager->getCertificateFailureCount());
    ASSERT_EQ(1, mp_test_manager->getPrivateKeyReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getPrivateKeyStoredCount());
    ASSERT_EQ(0, mp_test_manager->getPrivateKeyFailureCount());
}
#endif // #ifndef _WIN32

TEST_F(CertificateAssetProcessorTest, ProcessCertificateDelivery_StoreEncrypted_WithPrivateKeyInJsonRequest_SignAppHash)
{
    // Test with sign_apphash set to true
    testProcessCertificateDeliveryStoredEncryptedWithPrivateKey(true);
}

TEST_F(CertificateAssetProcessorTest, ProcessCertificateDelivery_StoreEncrypted_WithPrivateKeyInJsonRequest_NoSignAppHash)
{
    // Test without sign_apphash set to true
    testProcessCertificateDeliveryStoredEncryptedWithPrivateKey(false);
}

#ifndef _WIN32
TEST_F(CertificateAssetProcessorTest, ProcessCertificateDelivery_StoreEncrypted_WithPrivateKeyInJsonRequest_WithTPM)
{
    TpmWrapper::setInstance(new TestTpmWrapper(true));

    // Force random number generator to return our key and iv
    TestTpmWrapper* p_tpm_wrapper = (TestTpmWrapper*)TpmWrapper::getInstance();
    p_tpm_wrapper->addRandomDataResult({m_tpm_key.begin(), m_tpm_key.end()});
    p_tpm_wrapper->addRandomDataResult({m_tpm_iv.begin(), m_tpm_iv.end()});

    const std::string asset_data_str = makeCertificateAssetData( // simulate encrypted private key from keyscaler key / iv
        m_file_path, false, 0, true, m_asset_id, m_certificate, m_key_id, m_private_key, m_key, m_iv);

    CertificateAssetProcessor asset_processor(m_asset_id, mp_asset_messenger.get());

    rapidjson::Document asset_data_json;
    asset_data_json.Parse(asset_data_str.c_str());

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

    std::string private_key_json = utils::createJsonEncryptionBlockForTpm(
        TesterHelper::encrypt(m_private_key, m_tpm_key, m_tpm_iv),
        {m_tpm_iv.begin(), m_tpm_iv.end()});

    std::string certificate_json = utils::createJsonEncryptionBlockForTpm(
        TesterHelper::encrypt(m_certificate, m_tpm_key, m_tpm_iv),
        {m_tpm_iv.begin(), m_tpm_iv.end()});

    ASSERT_TRUE(TesterHelper::checkFileContentsMatch(m_cert_file_path, certificate_json));
    ASSERT_TRUE(TesterHelper::checkFileContentsMatch(m_private_key_file_path, private_key_json));

    ASSERT_EQ(remove(m_private_key_file_path.c_str()), 0);
    ASSERT_EQ(remove(m_cert_file_path.c_str()), 0);

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getCertificateReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getCertificateStoredCount());
    ASSERT_EQ(0, mp_test_manager->getCertificateFailureCount());
    ASSERT_EQ(1, mp_test_manager->getPrivateKeyReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getPrivateKeyStoredCount());
    ASSERT_EQ(0, mp_test_manager->getPrivateKeyFailureCount());
}
#endif // #ifndef _WIN32

TEST_F(CertificateAssetProcessorTest, ProcessCertificateDelivery_StoreEncrypted_PrivateKeyInInterFile)
{
    TpmWrapper::setInstance(new TestTpmWrapper(false));

    const std::string asset_data_str = makeCertificateAssetData(
        m_file_path, false, 0, true, m_asset_id, m_certificate, m_key_id, "", m_key, m_iv, true);

#ifndef _WIN32
    std::string private_key_json;
    utils::createJsonEncryptionBlock(
        m_key_id,
        m_asset_id,
        TesterHelper::encrypt(m_private_key, m_key, m_iv),
        private_key_json);

    std::string certificate_json;
    utils::createJsonEncryptionBlock(
        m_key_id,
        m_asset_id,
        TesterHelper::encrypt(m_certificate, m_key, m_iv),
        certificate_json);

    // Create private interim file that will be decrypted and migrated to private key file
    std::ofstream f(m_inter_file_path);
    f << private_key_json;
    f.close();
#else
    NcryptCertStore cert_store{true, false};
    cert_store.initialize();
    std::string subject_name;
    ASSERT_TRUE(cert_store.getSubjectNameFromCertificate(m_certificate, subject_name));
    cert_store.importPrivateKey(m_private_key, subject_name);
    cert_store.shutdown();
#endif // ifndef _WIN32

    CertificateAssetProcessor asset_processor(m_asset_id, mp_asset_messenger.get());

    rapidjson::Document asset_data_json;
    asset_data_json.Parse(asset_data_str.c_str());

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
    ASSERT_TRUE(TesterHelper::checkFileContentsMatch(m_cert_file_path, certificate_json));
    ASSERT_TRUE(TesterHelper::checkFileContentsMatch(m_private_key_file_path, private_key_json));

    ASSERT_EQ(remove(m_private_key_file_path.c_str()), 0);
    ASSERT_EQ(remove(m_cert_file_path.c_str()), 0);
#endif // #ifndef _WIN32

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getCertificateReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getCertificateStoredCount());
    ASSERT_EQ(0, mp_test_manager->getCertificateFailureCount());
    ASSERT_EQ(0, mp_test_manager->getPrivateKeyReceivedCount());
#ifndef _WIN32
    // Expect private key stored event in Linux as the key is moved from interim file to private key path
    ASSERT_EQ(1, mp_test_manager->getPrivateKeyStoredCount());
#else // #ifndef _WIN32
    // Expect no private key stored events in Windows as the private key is not moved or changed, it exists
    // in Windows Cert Store under the same name.
    ASSERT_EQ(0, mp_test_manager->getPrivateKeyStoredCount());
#endif // #ifndef _WIN32
    ASSERT_EQ(0, mp_test_manager->getPrivateKeyFailureCount());
}

#ifndef _WIN32
TEST_F(CertificateAssetProcessorTest, ProcessCertificateDelivery_StoreEncrypted_PrivateKeyInInterFile_WithTPM)
{
    TpmWrapper::setInstance(new TestTpmWrapper(true));

    // Force random number generator to return our key and iv
    TestTpmWrapper* p_tpm_wrapper = (TestTpmWrapper*)TpmWrapper::getInstance();
    p_tpm_wrapper->addRandomDataResult({m_tpm_key.begin(), m_tpm_key.end()});
    p_tpm_wrapper->addRandomDataResult({m_tpm_iv.begin(), m_tpm_iv.end()});

    p_tpm_wrapper->createSeal(m_inter_file_path, {m_tpm_key.begin(), m_tpm_key.end()}, true);

    const std::string asset_data_str = makeCertificateAssetData(
        m_file_path, false, 0, true, m_asset_id, m_certificate, m_key_id, "", m_key, m_iv);

    std::string inter_key_json = utils::createJsonEncryptionBlockForTpm(
        TesterHelper::encrypt(m_private_key, m_tpm_key, m_tpm_iv),
        {m_tpm_iv.begin(), m_tpm_iv.end()});
    std::string certificate_json = utils::createJsonEncryptionBlockForTpm(
        TesterHelper::encrypt(m_certificate, m_tpm_key, m_tpm_iv),
        {m_tpm_iv.begin(), m_tpm_iv.end()});

    // Create private interim file that will be decrypted and migrated to private key file
    std::ofstream f{m_inter_file_path};
    f << inter_key_json;
    f.close();

    CertificateAssetProcessor asset_processor(m_asset_id, mp_asset_messenger.get());

    rapidjson::Document asset_data_json;
    asset_data_json.Parse(asset_data_str.c_str());

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

    ASSERT_TRUE(p_tpm_wrapper->hasKey(m_private_key_file_path));
    ASSERT_TRUE(p_tpm_wrapper->hasKey(m_cert_file_path));

    ASSERT_TRUE(TesterHelper::checkFileContentsMatch(m_private_key_file_path, inter_key_json));
    ASSERT_TRUE(TesterHelper::checkFileContentsMatch(m_cert_file_path, certificate_json));

    ASSERT_EQ(remove(m_private_key_file_path.c_str()), 0);
    ASSERT_EQ(remove(m_cert_file_path.c_str()), 0);

    // Verify notifications were raised
    ASSERT_EQ(1, mp_test_manager->getCertificateReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getCertificateStoredCount());
    ASSERT_EQ(0, mp_test_manager->getCertificateFailureCount());
    ASSERT_EQ(0, mp_test_manager->getPrivateKeyReceivedCount());
    ASSERT_EQ(1, mp_test_manager->getPrivateKeyStoredCount());
    ASSERT_EQ(0, mp_test_manager->getPrivateKeyFailureCount());
}
#endif // #ifndef _WIN32

#endif // #ifndef CERTIFICATE_ASSET_PROCESSOR_UNITTEST_HPP
