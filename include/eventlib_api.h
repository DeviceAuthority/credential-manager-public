/**
 * \file
 *
 * \brief Definition of the event library C-style APIs function pointer structure
 *
 * \author Copyright (c) 2023 DeviceAuthority, Inc. ALL RIGHTS RESERVED.
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to DeviceAuthority Inc. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from DeviceAuthority Inc.
 *
 */

#ifndef EVENTLIB_API_H
#define EVENTLIB_API_H

#ifdef _WINDLL
#include <windows.h>
#endif // #ifdef _WINDLL

#include "eventlib_def.h"

#if !defined(WIN32)
typedef void* HMODULE;
#endif // #ifndef _WIN32

#ifdef _WINDLL
#define OSCALL __cdecl 
#define DLL_API __declspec(dllexport)
#else
#define OSCALL
#define DLL_API
#endif

// Functions exposed by API
#ifdef __cplusplus
extern "C"
{
#endif

/// @brief Initialises the event library
DLL_API void OSCALL eventlib_initialise();

/// @brief Cleans up resources when the event library is shutdown
DLL_API void OSCALL eventlib_teardown();

/// @brief Gets the version string of the event lib
/// @return The version string
DLL_API const char * OSCALL eventlib_getversion();

/// @brief Handle event notifications raised by the CM
/// @param event_type The event type
/// @param event_type_len The length of the event type string
/// @param notification_type The notification type
/// @param notification_type_len The length of the notification type string
/// @param context The contextual information associated with the event, in JSON format
/// @param context_len The length of the text string
/// @return True if successfully processed, else false
DLL_API bool OSCALL eventlib_notify(
    const char *event_type,
    unsigned int event_type_len,
    const char *notification_type,
    unsigned int notification_type_len,
    const char *context,
    unsigned int context_len);

#ifdef __cplusplus
}
#endif

#endif // #ifndef EVENTLIB_API_H
