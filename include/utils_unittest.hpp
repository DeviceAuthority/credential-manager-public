/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Unit tests for the common utils functions
 */

#include "gtest/gtest.h"
#include "utils.hpp"

#ifndef UTILS_UNITTEST_HPP
#define UTILS_UNITTEST_HPP

TEST(Utils, CreateJsonEncryptionBlock_TestSuccess)
{
    const auto expected_json = "{\"key-id\":\"TheKeyId\",\"asset-id\":\"TheAssetId\",\"ciphertext\":\"TheEncryptedString\",\"sign-apphash\":false}";

    std::string encrypted_output_json;
    utils::createJsonEncryptionBlock("TheKeyId", "TheAssetId", "TheEncryptedString", encrypted_output_json, false);
    ASSERT_STREQ(expected_json, encrypted_output_json.c_str());
}

TEST(Utils, CreateJsonEncryptionBlockBase64Encoded_TestSuccess)
{
    // Base 64 encoded from {"key-id":"TheKeyId","asset-id":"TheAssetId","ciphertext":"TheEncryptedString","sign-apphash":false}
    const auto expected_json = "eyJrZXktaWQiOiJUaGVLZXlJZCIsImFzc2V0LWlkIjoiVGhlQXNzZXRJZCIsImNpcGhlcnRleHQiOiJUaGVFbmNyeXB0ZWRTdHJpbmciLCJzaWduLWFwcGhhc2giOmZhbHNlfQ==";

    std::string encrypted_output_json;
    utils::createJsonEncryptionBlock("TheKeyId", "TheAssetId", "TheEncryptedString", encrypted_output_json, true);
    ASSERT_STREQ(expected_json, encrypted_output_json.c_str());
}

TEST(Utils, ReadJsonEncryptionBlock_NoSig_TestSuccess)
{
    std::string encrypted_output_json;
    utils::createJsonEncryptionBlock("TheKeyId", "TheAssetId", "TheEncryptedString", encrypted_output_json, false);

    std::string key_id;
    std::string asset_id;
    std::string ciphertext;
    bool sign_apphash;
    ASSERT_TRUE(utils::getTextFromJsonEncryptionBlock(key_id, asset_id, ciphertext, sign_apphash, encrypted_output_json, false));
    ASSERT_STREQ(key_id.c_str(), "TheKeyId");
    ASSERT_STREQ(asset_id.c_str(), "TheAssetId");
    ASSERT_STREQ(ciphertext.c_str(), "TheEncryptedString");
    ASSERT_FALSE(sign_apphash);
}

TEST(Utils, ReadJsonEncryptionBlock_WithSig_TestSuccess)
{
    std::string encrypted_output_json;
    utils::createJsonEncryptionBlock("TheKeyId", "TheAssetId", "TheEncryptedString", encrypted_output_json, false, true);

    std::string key_id;
    std::string asset_id;
    std::string ciphertext;
    bool sign_apphash;
    ASSERT_TRUE(utils::getTextFromJsonEncryptionBlock(key_id, asset_id, ciphertext, sign_apphash, encrypted_output_json, false));
    ASSERT_STREQ(key_id.c_str(), "TheKeyId");
    ASSERT_STREQ(asset_id.c_str(), "TheAssetId");
    ASSERT_STREQ(ciphertext.c_str(), "TheEncryptedString");
    ASSERT_TRUE(sign_apphash);
}

#ifndef _WIN32
TEST(Utils, CreateJsonEncryptionBlockForTpm_TestSuccess)
{
    const std::string iv{"12345"};

    const auto expected_json = "{\"ciphertext\":\"TheEncryptedString\",\"iv\":\"MTIzNDU=\"}"; // IV base 64 encoded

    std::string encrypted_output_json = utils::createJsonEncryptionBlockForTpm("TheEncryptedString", {iv.begin(), iv.end()});
    ASSERT_STREQ(expected_json, encrypted_output_json.c_str());
}

TEST(Utils, ReadJsonEncryptionBlockForTpm_TestSuccess)
{
    const std::vector<char> iv = {'1', '2', '3', '4', '5'};
    std::string encrypted_output_json = utils::createJsonEncryptionBlockForTpm("TheEncryptedString", iv);

    std::vector<char> out_iv{};
    std::string ciphertext{};
    ASSERT_TRUE(utils::getTextFromJsonEncryptionBlockWithTpm(encrypted_output_json, ciphertext, out_iv));
    ASSERT_STREQ(ciphertext.c_str(), "TheEncryptedString");
    ASSERT_EQ(iv, out_iv);
}
#endif // #ifndef _WIN32

TEST(Utils, GenerateHMAC_TestSuccess)
{
    const auto signature = utils::generateHMAC("abcde", "123123123123", true);
    ASSERT_TRUE(!signature.empty());
    ASSERT_STREQ("/LmZuN0BJPEyWTEjaKeagj4tr4QHhGX0u6dRuWEHmM0=", signature.c_str());
}

TEST(Utils, GenerateHMACOnLongMessage_TestSuccess)
{
    const auto signature = utils::generateHMAC("abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcdeabcde", "321321321", true);
    ASSERT_TRUE(!signature.empty());
    ASSERT_STREQ("JlVRaNieMnUMPKUhhHOAqrkcQy7+HR68no/UKDbAtbI=", signature.c_str());
}

TEST(Utils, GenerateHMACWithEmptyKey_TestFailure)
{
    const auto signature = utils::generateHMAC("abcde", "", true);
    ASSERT_TRUE(signature.empty());
}

TEST(Utils, TestEncryptDecryptFile_TestSuccess)
{
    const std::string m_asset_id{"asset_1234"};
    const std::string m_key_id{"keyid_1234"};
    const std::string m_file_path{"/tmp/test.out"};
    const std::string m_key{"01234567890123456789012345678901"};
    const std::string m_iv{"0123456789ABCDEF"};

    ASSERT_TRUE(utils::encryptAndStorePK("abcdefg", m_key, m_iv, m_key_id, m_asset_id, m_file_path, false, false));
    bool sign_apphash;
    std::string pk;
    ASSERT_TRUE(utils::decryptJsonBlockFile(pk, sign_apphash, std::string(m_key.begin(), m_key.end()), std::string(m_iv.begin(), m_iv.end()), m_file_path, false));

    ASSERT_STREQ(pk.c_str(), "abcdefg");
}

TEST(Utils, TestGetFileNameFromWindowsFilePath_TestSuccess)
{
    const std::string m_file_path{ "C:\\ABC\\DEF\\GHIJK.txt" };
    const auto file_name = utils::getFileNameFromPath(m_file_path);
    ASSERT_STREQ("GHIJK.txt", file_name.c_str());
}

TEST(Utils, TestGetFileNameFromLinuxFilePath_TestSuccess)
{
    const std::string m_file_path{ "/var/bob/GHIJK.txt" };
    const auto file_name = utils::getFileNameFromPath(m_file_path);
    ASSERT_STREQ("GHIJK.txt", file_name.c_str());
}

TEST(Utils, TestGetFileNameFromFilePath_EmptyFilePath_TestSuccess)
{
    const std::string m_file_path{ "" };
    const auto file_name = utils::getFileNameFromPath(m_file_path);
    ASSERT_STREQ("", file_name.c_str());
}

TEST(Utils, TestGetFileNameFromFilePath_FilePathNoFileName_TestSuccess)
{
    const std::string m_file_path{ "/opt/dave/" };
    const auto file_name = utils::getFileNameFromPath(m_file_path);
    ASSERT_STREQ("", file_name.c_str());
}

#include "opensslhelper.h"
TEST(SSLWrapper, TestStorePrivateKeyUsingOpensslStorageProvider)
{
    ASSERT_TRUE(openssl_load_provider("/home/deanharris/work/agent/credential-management/dastore_provider.so"));
    
    auto wrapper = SSLWrapper();
    ASSERT_TRUE(wrapper.writePrivateKeyToStorageProvider(TesterHelper::m_privateKey, "abcde", true));
    ASSERT_TRUE(wrapper.writeCertificateToStorageProvider(TesterHelper::m_certificate, "edcba", true));
    ASSERT_TRUE(wrapper.writePrivateKeyToStorageProvider(TesterHelper::m_privateKey, "bcdea", false));
    ASSERT_TRUE(wrapper.writeCertificateToStorageProvider(TesterHelper::m_certificate, "dcbae", false));
    
}

#endif // UTILS_UNITTEST_HPP
