/**
 * \file
 *
 * \brief Definition of event library error codes and constants
 *
 * \author Copyright (c) 2023 by Device Authority Ltd. ALL RIGHTS RESERVED.
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to Device Authority Ltd. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from Device Authority Ltd.
 *
 */

#ifndef EVENTLIB_DEF_H
#define EVENTLIB_DEF_H

typedef void (*EVENTLIB_STARTUP_PROC)();
typedef void (*EVENTLIB_SHUTDOWN_PROC)();
typedef const char *(*EVENTLIB_GETVERSION_PROC)();
typedef int (*EVENTLIB_NOTIFY_PROC)(
    const char *event_type, 
    size_t event_type_len,
    const char *notification_type,
    size_t notification_type_len,
    const char *context,
    size_t context_len);

static const char *const EVENTLIB_INITIALIZE_FUNC_NAME = "eventlib_initialise";
static const char *const EVENTLIB_TEARDOWN_FUNC_NAME = "eventlib_teardown";
static const char *const EVENTLIB_GETVERSION_FUNC_NAME = "eventlib_getversion";
static const char *const EVENTLIB_NOTIFY_FUNC_NAME = "eventlib_notify";

#endif // #ifndef EVENTLIB_DEF_H
