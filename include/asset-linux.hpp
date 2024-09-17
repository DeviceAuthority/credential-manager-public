/*
 * Copyright (c) 2020 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Linux specific functions for asset processor module
 */
#ifndef ASSET_LINUX_HPP
#define ASSET_LINUX_HPP

#include <pwd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string>
#if __cplusplus > 199711L
#else
#include <algorithm>
#endif // #if __cplusplus > 199711L

static int setEnv(const std::string &name, const std::string &value)
{
    return setenv(name.c_str(), value.c_str(), 1);
}

static std::string fixLineEndings(std::string str)
{
#if __cplusplus > 199711L
    std::string os;

    os.reserve(str.size());
    for (const char c : str)
    {
        if (c != '\r')
        {
            os.push_back(c);
        }
    }

    return os;
#else
    str.erase(std::remove(str.begin(), str.end(), '\r'), str.end());

    return str;
#endif // #if __cplusplus > 199711L
}

#endif // ASSET_LINUX_HPP
