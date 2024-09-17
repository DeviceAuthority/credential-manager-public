/**
 * \file script_utils_unittest.hpp
 *
 * \brief Unit test script utils
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

#ifndef SCRIPT_UTILS_UNITTEST_HPP
#define SCRIPT_UTILS_UNITTEST_HPP

#include "gtest/gtest.h"
#include "script_utils.hpp"

TEST(ScriptUtils, ExecuteScriptAndVerifyOutput_ExpectSuccess)
{
#ifdef _WIN32
    const std::string script{ "echo hello world" };
#else // #ifdef _WIN32
    const std::string script{ "echo 'hello world' > /tmp/test.out; cat /tmp/test.out; rm /tmp/test.out" };
#endif // #ifdef _WIN32

    std::string logOutput;
    ASSERT_TRUE(script_utils::execScript(script, logOutput));
    ASSERT_STREQ(logOutput.c_str(), "hello world\n");
}

TEST(ScriptUtils, ExecuteInvalidScript_ExpectFailure)
{
    std::string logOutput;
    ASSERT_FALSE(script_utils::execScript("invalid script that will fail to execute", logOutput));
    const std::string expectedErrorString = "Script exited with err:";
    ASSERT_GT(logOutput.length(), expectedErrorString.length());
    ASSERT_STREQ(logOutput.substr(0, expectedErrorString.length()).c_str(), expectedErrorString.c_str());
}

#endif // #ifndef SCRIPT_UTILS_UNITTEST_HPP
