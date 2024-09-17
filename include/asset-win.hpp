/*
 * Copyright (c) 2020 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Windows specific functions for asset processor module
 */
#ifndef ASSET_WIN_HPP
#define ASSET_WIN_HPP

#include <string>
#include <stdlib.h>

static int setEnv(const std::string &name, const std::string &value)
{
    return _putenv_s(name.c_str(), value.c_str());
}

static FILE *popen(const char *cmd, const char *type)
{
    return _popen(cmd, type);
}

static int pclose(FILE *f)
{
    return _pclose(f);
}

static std::string fixLineEndings(std::string str)
{
    return str;
}

#endif // ASSET_WIN_HPP
