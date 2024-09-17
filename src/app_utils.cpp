/*
 * Copyright (c) 2024 Device Authority. - All rights reserved. - www.deviceauthority.com
 *
 * Application utility functions.
 */

#include "app_utils.hpp"
#include "version.h"
#include "win_cert_store_factory.hpp"

namespace app_utils
{
    /// @brief The copyright message with place holders for version and build
    static const char* COPYRIGHT_MESSAGE = "Credential Manager version %s build %s%s - The device is the key. Copyright 2024 Device Authority.";
    static const char* BUILD_MESSAGE = "Built on %s at %s.";
    static const char* CONTACT_MESSAGE = "Please contact customer_support@deviceauthority.com for support.";
    static const char* BUILD_INFO_MESSAGE = "MQTT support: %s, TPM support: %s";

    void output_copyright_message(Log* p_logger)
    {
        std::string debug_text = "";
#if defined(DEBUG)
        debug_text += " (DEBUG)";
#endif // #if defined(DEBUG)

        // Output copyright message
        if (p_logger)
        {
            p_logger->printf(Log::Notice, COPYRIGHT_MESSAGE, VERSION_TEXT, BUILD_TEXT, debug_text.c_str());
            p_logger->printf(Log::Notice, BUILD_MESSAGE, __DATE__, __TIME__);
            p_logger->printf(Log::Notice, "%s", CONTACT_MESSAGE);
        }
        else
        {
            printf(COPYRIGHT_MESSAGE, VERSION_TEXT, BUILD_TEXT, debug_text.c_str());
            printf("\n");
            printf(BUILD_MESSAGE, __DATE__, __TIME__);
            printf("\n");
            printf("%s", CONTACT_MESSAGE);
            printf("\n");
        }

        bool has_tpm_support_flag = true, has_mqtt_support_flag = true;
#ifdef _WIN32
        has_tpm_support_flag = WinCertStoreFactory::getInstance()->isTpmSupported();
#else // #ifdef _WIN32
#ifdef DISABLE_TPM
        has_tpm_support_flag = false;
#endif
#endif
#ifdef DISABLE_MQTT
        has_mqtt_support_flag = false;
#endif
        if (p_logger)
        {
            p_logger->printf(
                Log::Debug,
                BUILD_INFO_MESSAGE,
                has_mqtt_support_flag ? "yes" : "no",
                has_tpm_support_flag ? "yes" : "no");
        }
        else
        {
            printf(BUILD_INFO_MESSAGE,
                has_mqtt_support_flag ? "yes" : "no",
                has_tpm_support_flag ? "yes" : "no");
            printf("\n");
        }
    }
}
