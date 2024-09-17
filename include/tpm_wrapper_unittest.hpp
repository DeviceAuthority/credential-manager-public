/**
 * \file tpm_wrapper_unittest.cpp
 *
 * \brief Unit tests for the TPM wrapper
 *
 * \author Copyright (c) 2023 by Device Authority Ltd. ALL RIGHTS RESERVED.
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to Device Authority Ltd. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from Device Authority Ltd.
 *
 *
 * \date July 21, 2023
 *
 */

#ifndef TPM_WRAPPER_UNITTEST_HPP
#define TPM_WRAPPER_UNITTEST_HPP

#include <iostream>
#include <string>
#include "gtest/gtest.h"
#include "tpm_wrapper.hpp"
#include "test_tpm_wrapper.hpp"

class TpmWrapperTest : public testing::Test
{
    public:
    void SetUp() override
    {
        TpmWrapper::setInstance(new TestTpmWrapper());
    }

    void TearDown() override
    {
        TpmWrapper::setInstance(nullptr); // Clear the test instance
    }
};

TEST_F(TpmWrapperTest, GetRandom)
{
    auto *p_tpm_wrapper = TpmWrapper::getInstance();
    if (!p_tpm_wrapper->initialised())
    {
        // If TPM failed to initialise the only acceptable reason is there is no
        // TPM on the host device (bypass test with success)
        ASSERT_FALSE(p_tpm_wrapper->isTpmAvailable());
        return;
    }

    const size_t num_bytes{20};
    std::vector<char> random_bytes_1{};
    ASSERT_TRUE(p_tpm_wrapper->getRandom(num_bytes, random_bytes_1));
    ASSERT_EQ(num_bytes, random_bytes_1.size());

    std::vector<char> random_bytes_2{};
    ASSERT_TRUE(p_tpm_wrapper->getRandom(num_bytes, random_bytes_2));
    ASSERT_EQ(num_bytes, random_bytes_2.size());

    ASSERT_NE(random_bytes_1, random_bytes_2);
}

TEST_F(TpmWrapperTest, SealAndUnsealData)
{
    auto p_tpm_wrapper = TpmWrapper::getInstance();
    if (!p_tpm_wrapper->initialised())
    {
        // If TPM failed to initialise the only acceptable reason is there is no
        // TPM on the host device (bypass test with success)
        ASSERT_FALSE(p_tpm_wrapper->isTpmAvailable());
        return;
    }

    // Seal and unseal data - check it unseals successfully
    const std::string data_to_seal{"The data to encrypt"};
    const std::string key_name{"mySeal"};
    ASSERT_TRUE(p_tpm_wrapper->createSeal(key_name, {data_to_seal.begin(), data_to_seal.end()}));
    std::vector<char> unsealed_data{};
    ASSERT_TRUE(p_tpm_wrapper->unseal(key_name, unsealed_data));
    std::string unsealed_data_str{unsealed_data.begin(), unsealed_data.end()};
    ASSERT_STREQ(data_to_seal.c_str(), unsealed_data_str.c_str());

    // Tidy up
    ASSERT_TRUE(p_tpm_wrapper->deleteKey(key_name));
}

TEST_F(TpmWrapperTest, OverwriteSealKey_Success)
{
    auto p_tpm_wrapper = TpmWrapper::getInstance();
    if (!p_tpm_wrapper->initialised())
    {
        // If TPM failed to initialise the only acceptable reason is there is no
        // TPM on the host device (bypass test with success)
        ASSERT_FALSE(p_tpm_wrapper->isTpmAvailable());
        return;
    }

    // Create seal then unseal to verify success
    const std::string data_to_seal_1{"The data to encrypt 1"};
    const std::string data_to_seal_2{"The data to encrypt 2"};
    const std::string key_name{"mySeal"};
    std::vector<char> unsealed_data{};
    ASSERT_TRUE(p_tpm_wrapper->createSeal(key_name, {data_to_seal_1.begin(), data_to_seal_1.end()}));
    ASSERT_TRUE(p_tpm_wrapper->unseal(key_name, unsealed_data));
    std::string unsealed_data_str{unsealed_data.begin(), unsealed_data.end()};
    ASSERT_STREQ(data_to_seal_1.c_str(), unsealed_data_str.c_str());

    // Create another seal - key exists and overwrite set to false - confirm create seal fails
    ASSERT_FALSE(p_tpm_wrapper->createSeal(key_name, {data_to_seal_2.begin(), data_to_seal_2.end()}, false));

    // Create another seal - key exists and overwrite set to true - confirm create seal succeeds
    ASSERT_TRUE(p_tpm_wrapper->createSeal(key_name, {data_to_seal_2.begin(), data_to_seal_2.end()}, true));
    ASSERT_TRUE(p_tpm_wrapper->unseal(key_name, unsealed_data));
    unsealed_data_str = {unsealed_data.begin(), unsealed_data.end()};
    ASSERT_STREQ(data_to_seal_2.c_str(), unsealed_data_str.c_str());

    // Tidy up
    ASSERT_TRUE(p_tpm_wrapper->deleteKey(key_name));
}


// bool provision(FAPI_CONTEXT *p_fapi_context)
// {
//     const TSS2_RC r = Fapi_Provision(p_fapi_context, nullptr, nullptr, nullptr);
//     return r == TSS2_RC_SUCCESS || r == TSS2_FAPI_RC_ALREADY_PROVISIONED;
// }

// bool createSeal(FAPI_CONTEXT *p_fapi_context, const std::string &path, const std::string &data)
// {
//     TSS2_RC r = Fapi_CreateSeal(p_fapi_context, path.c_str(), "noda,system", data.size(), nullptr, nullptr, reinterpret_cast<const uint8_t*>(data.c_str()));
//     if (r == TSS2_FAPI_RC_PATH_ALREADY_EXISTS)
//     {
//         std::cerr << "Key path already exists" << std::endl;
//         r = Fapi_Delete(p_fapi_context, path.c_str());
//         if (r != TSS2_RC_SUCCESS)
//         {
//             std::cerr << "Failed to delete key :(" << std::endl;
//             return false;
//         }

//         return createSeal(p_fapi_context, path, data);
//     }

//     return r == TSS2_RC_SUCCESS;
// }

// bool unseal(FAPI_CONTEXT *p_fapi_context, const std::string &path, std::string &data)
// {
//     uint8_t* raw_data{nullptr};
//     size_t size;
//     TSS2_RC r = Fapi_Unseal(p_fapi_context, path.c_str(), &raw_data, &size);
//     if (r == TSS2_RC_SUCCESS)
//     {
//         data = std::string(reinterpret_cast<char*>(raw_data), size);

//         return true;
//     }

//     return false;
// }

// TEST_F(TpmWrapperTest, ProvisionTPM)
// {
//     bool success{false};

//     FAPI_CONTEXT *fapi_context{nullptr};
//     TSS2_RC r = Fapi_Initialize(&fapi_context, nullptr);
//     if (r == TSS2_RC_SUCCESS)
//     {
//         std::cout << "Initialised" << std::endl;;

//         char *info = NULL;
//         r = Fapi_GetInfo(fapi_context, &info);
//         std::cout << info << std::endl;
//         delete[] info;

//         r = Fapi_Provision(fapi_context, nullptr, nullptr, nullptr);
//         if (r == TSS2_RC_SUCCESS)
//         {
//             std::cout << "Provisioned" << std::endl;
//             success = true;
//         }
//     }

//     Fapi_Finalize(&fapi_context);
//     ASSERT_TRUE(success);
// }

// TEST_F(TpmWrapperTest, CreateKeyPairUsingTheTPM)
// {
//     TSS2_RC r = 0;
//     size_t signatureSize = 0;
//     uint8_t *signature;
//     char *publicKey;
//     size_t digestSize = 32;
//     uint8_t digest[32] = {'\0'};
//     FAPI_CONTEXT *fapi_context{nullptr};
//     r = Fapi_Initialize(&fapi_context, nullptr);
//     if (r != TSS2_RC_SUCCESS)
//         goto error;

//     r = Fapi_CreateKey(fapi_context, "HS/SRK/mySigningKey", "noDa, sign", "", "");
//     if (r != TSS2_RC_SUCCESS)
//         goto error;

//     r = Fapi_Sign(fapi_context, "HS/SRK/mySigningKey", NULL, digest, digestSize, &signature,
//     &signatureSize, &publicKey, NULL);
//     if (r != TSS2_RC_SUCCESS)
//         goto error;
//     Fapi_Finalize(&fapi_context);
//     for (size_t i = 0; i < signatureSize; i++)
//         printf("%02x", signature[i]);
//     printf("\n");
//     return;

// error:
//     Fapi_Finalize(&fapi_context);
//     return;
// }

#endif // #ifndef TPM_WRAPPER_UNITTEST_HPP
