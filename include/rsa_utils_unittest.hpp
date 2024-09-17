/**
 * \file 
 *
 * \brief Unit test RSA utils functions
 *
 * \author Copyright (c) 2024 by Device Authority Ltd. ALL RIGHTS RESERVED.
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to Device Authority Ltd. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from Device Authority Ltd.
 *
 *
 */

#ifndef RSA_UTILS_UNITTEST_HPP
#define RSA_UTILS_UNITTEST_HPP

#include <stdlib.h>
#include <string>
#include "log.hpp"
#include "gtest/gtest.h"
#include "configuration.hpp"
#include "rsa_utils.hpp"

class RSAUtilsTest : public testing::Test
{
    public:

    static const char *RSA_PUBLIC_KEY;

    void SetUp() override
    {

    }

    void TearDown() override
    {
        
    }

    bool writeToFileSystem(const std::string &public_key_path, const std::string &public_key)
    {
        std::ofstream ofs(public_key_path.c_str());
        if (!ofs.good())
        {
            const std::string message = "Problem writing to file path \\\"" + public_key_path + "\\\"";
            Log::getInstance()->printf(Log::Error, " %s %s", __func__, message.c_str());

            return false;
        }
        ofs << public_key;
        ofs.close();

        return true;
    }
};

TEST_F(RSAUtilsTest, ReadPublicKey_ValidRsaFile_ExpectSuccess)
{
    const std::string &public_key_path = "/tmp/rsatest.pub";
    writeToFileSystem(public_key_path, RSA_PUBLIC_KEY);

    config.override(CFG_CERTIFICATEPATH, public_key_path);
    try {
        RsaUtils::getRSAPublicKey();
    }
    catch (const std::exception &ex)
    {
        Log::getInstance()->printf(Log::Error, "%s", ex.what());
    }
    ASSERT_NO_THROW(RsaUtils::getRSAPublicKey());
}

TEST_F(RSAUtilsTest, ReadPublicKey_EmptyCertPath_ExpectFailure)
{
    const std::string &public_key_path = "";
    config.override(CFG_CERTIFICATEPATH, public_key_path);
    ASSERT_ANY_THROW(RsaUtils::getRSAPublicKey());
}

TEST_F(RSAUtilsTest, ReadPublicKey_InvalidCert_ExpectFailure)
{
    const std::string &public_key_path = "/tmp/rsatest.pub";

    writeToFileSystem(public_key_path, "abcde");

    config.override(CFG_CERTIFICATEPATH, public_key_path);
    ASSERT_ANY_THROW(RsaUtils::getRSAPublicKey());
}

const char *RSAUtilsTest::RSA_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsjtGIk8SxD+OEiBpP2/T\n"
    "JUAF0upwuKGMk6wH8Rwov88VvzJrVm2NCticTk5FUg+UG5r8JArrV4tJPRHQyvqK\n"
    "wF4NiksuvOjv3HyIf4oaOhZjT8hDne1Bfv+cFqZJ61Gk0MjANh/T5q9vxER/7TdU\n"
    "NHKpoRV+NVlKN5bEU/NQ5FQjVXicfswxh6Y6fl2PIFqT2CfjD+FkBPU1iT9qyJYH\n"
    "A38IRvwNtcitFgCeZwdGPoxiPPh1WHY8VxpUVBv/2JsUtrB/rAIbGqZoxAIWvijJ\n"
    "Pe9o1TY3VlOzk9ASZ1AeatvOir+iDVJ5OpKmLnzc46QgGPUsjIyo6Sje9dxpGtoG\n"
    "QQIDAQAB\n"
    "-----END PUBLIC KEY-----\n";

#endif // #ifndef RSA_UTILS_UNITTEST_HPP