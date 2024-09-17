/**
 * \file /mavericks/shared/include/platform.h
 *
 * \brief Implementation of platform specific definition and function declarations
 *
 * \author Copyright (c) 2005-2006 by Uniloc USA Inc. ALL RIGHTS RESERVED.
 * \author Copyright (c) 2014-2016 by DeviceAuthority Inc. ALL RIGHTS RESERVED.
 * \author Copyright (c) 2016 by Device Authority Ltd. ALL RIGHTS RESERVED.
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to Device Authority Ltd. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from Device Authority Ltd.
 *
 * \version 1.0
 *
 * \date October 5, 2011
 * \date January 1, 2014
 *
 */

#if _MSC_VER > 1000
#pragma once
#endif // #if _MSC_VER > 1000

#ifndef __PLATFORM_H__
#define __PLATFORM_H__

// Added to support Android NDK
#if defined(linux) || defined(__linux__) || defined(__ANDROID__)

//#if defined(__ANDROID__)
#ifndef _LIBC_LIMITS_H
#include <limits.h>
#endif // #ifndef _LIBC_LIMITS_H
#ifndef _STDDEF_H
#include <stddef.h>
#endif // #ifndef _STDDEF_H
#ifndef _STDINT_H
#include <stdint.h>
#endif // #ifndef _STDINT_H
#ifndef _STDBOOL_H
#include <stdbool.h>
#endif // #ifndef _STDBOOL_H
//#endif // #if defined(__ANDROID__)
#include "platform_linux.h"

typedef int64_t             Sint64;
typedef uint64_t            Uint64;
typedef long long           Sllong;
typedef unsigned long long  Ullong;

#elif defined(__APPLE__) || defined(__MACH__)

#include <TargetConditionals.h>
#include <stdint.h>
#include <unistd.h>
#include "platform_osx.h"
#if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
#include "platform_ios.h"
#endif // #if #if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR

typedef int64_t             Sint64;
typedef uint64_t            Uint64;
typedef long long           Sllong;
typedef unsigned long long  Ullong;

#elif defined(WIN32)

#include <Windows.h>

#if __STDC_WANT_SECURE_LIB__
#define STRICMP     _stricmp
#else
#define STRICMP     stricmp
#endif // #if __STDC_WANT_SECURE_LIB__

#ifndef LPCBYTE
typedef const unsigned char *LPCBYTE;
#endif // #ifndef LPCBYTE

#if defined(_MSC_VER) && (_MSC_VER >= 1400)
// VC 8.0 (aka 2005)
typedef __int64             Sint64;
typedef unsigned __int64    Uint64;
typedef __int64             Sllong;
typedef unsigned __int64    Ullong;

#elif defined(_MSC_VER) && (_MSC_VER >= 1310)
// VC 7.1 (aka .NET 2003)
typedef __int64             Sint64;
typedef unsigned __int64    Uint64;
typedef __int64             Sllong;
typedef unsigned __int64    Ullong;

#elif defined(_MSC_VER) && (_MSC_VER >= 1300)
// VC 7.0 (aka .NET 2002)
typedef __int64             Sint64;
typedef unsigned __int64    Uint64;
typedef __int64             Sllong;
typedef unsigned __int64    Ullong;

#else
// VC 6.0
//TODO: Actualy here should be more checkings, not all platofrms support "long long"
typedef long long           Sint64;
typedef unsigned long long  Uint64;
typedef long long           Sllong;
typedef unsigned long long  Ullong;

#endif // #if defined(_MSC_VER) && (_MSC_VER >= 1400)

#else
// Solaris and/or Other Platforms
//TODO: Actualy here should be more checkings, not all platofrms support "long long"
typedef long long           Sint64;
typedef unsigned long long  Uint64;

#endif // #if defined(linux) || defined(__linux__) || defined(__ANDROID__)

typedef signed long         Slong;
typedef signed int          Sint32;
typedef signed short        Sint16;
typedef char                Sint8;

typedef unsigned long       Ulong;
typedef unsigned int        Uint32;
typedef unsigned short      Uint16;
typedef unsigned char       Uint8;

#ifndef MIN
#define MIN(x,y)    (x < y)? x : y
#endif // #ifndef MIN

#ifndef MAX
#define MAX(x,y)    (x > y)? x : y
#endif // #ifndef MAX

#if defined(__ppc__) || (TARGET_RT_BIG_ENDIAN == 1)
#define SWAP16_LE_BE(x)	((((x) & 0xFF00) >> 8) | (((x) & 0x00FF) << 8))
#define SWAP32_LE_BE(x)	((SWAP16_LE_BE(((x) & 0xFFFF0000) >> 16)) | ((SWAP16_LE_BE((x) & 0x0000FFFF)) << 16))
#define SWAP64_LE_BE(x) ((SWAP32_LE_BE(((x) & 0xFFFFFFFF00000000) >> 32)) | ((SWAP32_LE_BE((x) & 0x00000000FFFFFFFF)) << 32))
#else
#define SWAP16_LE_BE(x) (x)
#define SWAP32_LE_BE(x) (x)
#define SWAP64_LE_BE(x) (x)
#endif // #if defined(__ppc__) || (TARGET_RT_BIG_ENDIAN == 1)

static LPCSTR UDI_FILENAME = ".udi";

enum UdiStatus
{
    udiStatusSuccess = 0,
    udiStatusInvalidValueError,
    udiStatusCreateDirectoryError,
    udiStatusFilePermissionError,
    udiStatusFileWriteError,
    udiStatusFileReadError
};

void Platform_SetBreakPoint();
LPCSTR Platform_GetType();
LPCSTR Platform_GetOS();
LPCSTR Platform_GetOSVersion();
LPCSTR Platform_GetArchitecture();
LPCSTR Platform_GetModel();
LPCSTR Platform_GetMachine();
LPCSTR Platform_GetDeviceName();
LPCSTR Platform_GetBrowser();
#if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
LPSTR Platform_GetInvokerSignature();
#else
LPSTR Platform_GetInvokerFilename();
#endif // #if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
int Platform_GetPlatformString(LPSTR*);
int Platform_GetUserAgentString(LPSTR*);
void Platform_ReleaseString(LPCSTR);
void Platform_SetTypePC();
void Platform_LockSyntheticKey();
void Platform_UnlockSyntheticKey();
void Platform_SetSyntheticKey(LPVOID);
LPVOID Platform_GetSyntheticKey(LPVOID);
void Platform_SyntheticKeyCleanup();
void Platform_SetAppDatabase(LPCSTR);
int Platform_SetDeviceIds(LPVOID);
LPVOID Platform_GetDeviceIds(LPVOID);
LPCSTR Platform_GenerateUUID();
void Platform_ReleaseUUID(LPSTR);
LPVOID Platform_GetSyntheticKeyFromUri(LPCSTR);
LPVOID Platform_GetSyntheticKeyUriOidVect();
int Platform_SetUdi(LPCSTR udi, const size_t len);
int Platform_GetUdi(LPSTR *udi, size_t *len);
#ifdef __cplusplus
extern "C" {
#endif // #ifdef __cplusplus

int Platform_ValidInvocation();

#ifdef __cplusplus
}
#endif // #ifdef __cplusplus

#endif // #ifndef __PLATFORM_H__
