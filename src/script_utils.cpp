/*
 * Copyright (c) 2023 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 *  Script running utility functions.
 */

#if defined(WIN32)
#include "asset-win.hpp"
#else
#include "asset-linux.hpp"
#endif // #if defined(WIN32)

#include "log.hpp"
#include "script_utils.hpp"

namespace script_utils
{

bool execScript(const std::string &script, std::string& log_output)
{
    FILE *pipe = popen(script.c_str(), "r");
    if (!pipe)
    {
        log_output = "";
        return false;
    }

    std::string buf;
    for (int c = getc(pipe); c != EOF; c = getc(pipe))
    {
        buf.push_back(c);
    }

    int err = pclose(pipe);
    if (err != 0)
    {
        std::stringstream ss;
        ss << "Script exited with err:" << err << " results:\n"
            << buf << std::endl;
        log_output = ss.str();
        Log::getInstance()->printf(Log::Error, "%s", log_output.c_str());
        return false;
    }

    log_output = buf;
	return true;
}

} // namespace script_utils
