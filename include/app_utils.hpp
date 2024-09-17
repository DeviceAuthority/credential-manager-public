/*
 * Copyright (c) 2024 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Application utility functions.
 */

#ifndef APP_UTILS_HPP
#define APP_UTILS_HPP

#include "log.hpp"

namespace app_utils
{
    /// @brief Outputs the copyright message for the Credential Manager
    /// @param p_logger The logger instance
    void output_copyright_message(Log* p_logger);

} // namespace app_utils

#endif // #ifndef APP_UTILS_HPP
