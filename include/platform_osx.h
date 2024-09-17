/**
 * \file /mavericks/shared/include/platform_osx.h
 *
 * \brief Implementation of platform specific definition and function declarations
 *
 * \author Copyright (c) 2005-2006 by Uniloc USA Inc. ALL RIGHTS RESERVED.
 * \author Copyright (c) 2014 by DeviceAuthority Inc. ALL RIGHTS RESERVED.
 *
 * This document contains CONFIDENTIAL, PROPRIETARY, PATENTABLE
 * and/or TRADE SECRET information belonging to DeviceAuthority Inc. and may
 * not be reproduced or adapted, in whole or in part, without prior
 * written permission from DeviceAuthority Inc.
 * 
 * \version 1.0
 * 
 * \date October 5, 2011
 * \date January 1, 2014
 *
 */

#pragma once

#ifndef __PLATFORM_OSX_H__
#define __PLATFORM_OSX_H__

#define HARDWARE_MACHINE    "hw.machine"
#define HARDWARE_MODEL      "hw.model"

#ifndef NULL
#define NULL    __DARWIN_NULL
#endif /* ! NULL */

#ifndef nil
#define nil NULL
#endif /* ! nil */

#ifndef BOOL
// From objc.h
#if !defined(OBJC_HIDE_64) && TARGET_OS_IPHONE && __LP64__
typedef bool BOOL;
#else
typedef signed char BOOL;
#endif // #if !defined(OBJC_HIDE_64) && TARGET_OS_IPHONE && __LP64__
#endif // #ifndef BOOL

#ifndef TRUE
#define TRUE 1
#endif // #ifndef TRUE

#ifndef FALSE
#define FALSE 0
#endif // #ifndef FALSE

#ifndef BYTE
typedef uint8_t BYTE;
#endif // #ifndef BYTE

#ifndef LPBYTE
typedef unsigned char byte;
typedef BYTE* LPBYTE;
#ifndef LPCBYTE
typedef const BYTE* LPCBYTE;
#endif // #ifndef LPCBYTE
#endif // #ifndef LPBYTE

#ifndef LPSTR
typedef char* LPSTR;
#endif // #ifndef LPSTR

#ifndef LPCSTR
typedef const char* LPCSTR;
#endif // #ifndef LPCSTR

#ifdef  UNICODE

#else

#ifndef LPCTSTR
typedef LPCSTR LPCTSTR;
#endif // #ifndef LPCTSTR

#endif // #ifdef  UNICODE

#ifndef LPVOID
typedef void* LPVOID;
#endif // #ifndef LPVOID

#ifndef __int64
typedef int64_t __int64;
#endif // #ifndef __int64

#ifndef DWORD
typedef uint32_t DWORD;
#endif // #ifndef DWORD

#ifndef DWORDLONG
typedef uint64_t DWORDLONG;
#endif // #ifndef DWORDLONG

#ifndef LPDWORD
typedef DWORD* LPDWORD;
#endif // #ifndef LPDWORD

#endif // #ifndef __PLATFORM_OSX_H__

