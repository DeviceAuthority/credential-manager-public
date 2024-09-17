/*
 * Copyright (c) 2015 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 *  Script running utility functions.
 */

#ifndef SCRIPT_UTILS_HPP
#define SCRIPT_UTILS_HPP

#include <string>
#include <sstream>
#include <stdexcept>

namespace script_utils
{
    /**
     * @brief Executes a script
     *
     * @param script The script to execute
     * @param[in] logOutput The script output if success
     * @return True on success, false if failure to run the script
     */
    bool execScript(const std::string &script, std::string& logOutput);

} // namespace script_utils

#endif // #ifndef SCRIPT_UTILS_HPP
